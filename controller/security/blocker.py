"""Installs a DROP flow rule (priority 1000, above everything the base
controller installs) on the right switch(es) for a detected offender, and
tracks when each block expires. Three block kinds:
  - 'mac'  : value is a MAC address.      Installed on ALL switches.
  - 'ip'   : value is an IPv4 address.     Installed on ALL switches.
  - 'port' : value is "dpid:port_no".      Installed ONLY on that switch,
             matching traffic arriving on that specific ingress port -
             used for pktin_flood, where the source MAC changes every
             packet and can never be blocked directly.

Stage 4 additions:
  - duration=None means QUARANTINE (permanent until an admin unblocks).
  - every entry remembers its attack + strike number (escalation).
  - every drop rule is registered with the flow-integrity checker as
    CRITICAL, so an insider deleting it gets caught and it is re-installed.
  - export()/load()/reinstall() let a new leader take over after failover.
"""
import time

PRIORITY = 1000


class Blocker:
    def __init__(self, integrity=None):
        self.active = {}        # key -> entry dict
        self.integrity = integrity

    @staticmethod
    def _cookie():
        from security import integrity
        return integrity.COOKIE

    # ---- helpers ----
    @staticmethod
    def _key(kind, value):
        return f'{kind}:{value}'

    @staticmethod
    def _is_live(entry, now):
        return entry['expires'] is None or entry['expires'] > now

    def is_blocked(self, kind, value):
        e = self.active.get(self._key(kind, value))
        return e is not None and self._is_live(e, time.time())

    def is_port_blocked(self, dpid, in_port):
        return self.is_blocked('port', f'{dpid}:{in_port}')

    def get(self, kind, value):
        return self.active.get(self._key(kind, value))

    def _pairs(self, datapaths, kind, value):
        """[(dp, match)] on which this block must be installed."""
        pairs = []
        for dp in datapaths:
            parser = dp.ofproto_parser
            if kind == 'port':
                dpid_str, port_str = value.split(':')
                if dp.id == int(dpid_str):
                    pairs.append((dp, parser.OFPMatch(in_port=int(port_str))))
            elif kind == 'mac':
                pairs.append((dp, parser.OFPMatch(eth_src=value)))
            else:  # 'ip'
                pairs.append((dp, parser.OFPMatch(eth_type=0x0800, ipv4_src=value)))
        return pairs

    def _send_drop(self, dp, match, kind, value, expires):
        now = time.time()
        hard = 0 if expires is None else max(1, round(expires - now)) + 2
        dp.send_msg(dp.ofproto_parser.OFPFlowMod(
            datapath=dp, priority=PRIORITY, match=match,
            instructions=[], hard_timeout=hard,
            cookie=self._cookie()))          # empty instructions = DROP
        if self.integrity is not None:
            self.integrity.expect(dp.id, PRIORITY, match, critical=True,
                                  expires=None if expires is None else expires + 2,
                                  label=f'block {kind}={value}')

    # ---- API ----
    def block(self, datapaths, kind, value, duration, attack='manual', strike=0):
        """duration seconds, or None = quarantine. Returns True if newly blocked."""
        key, now = self._key(kind, value), time.time()
        existing = self.active.get(key)
        if existing and self._is_live(existing, now):
            return False                                   # already blocked
        expires = None if duration is None else now + duration
        for dp, match in self._pairs(datapaths, kind, value):
            self._send_drop(dp, match, kind, value, expires)
        self.active[key] = {'kind': kind, 'value': value, 'expires': expires,
                            'attack': attack, 'strike': strike,
                            'duration': duration, 'since': now}
        return True

    def unblock(self, datapaths, kind, value):
        key = self._key(kind, value)
        if key not in self.active:
            return False
        for dp, match in self._pairs(datapaths, kind, value):
            ofp, parser = dp.ofproto, dp.ofproto_parser
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                priority=PRIORITY, match=match))
            if self.integrity is not None:
                self.integrity.forget(dp.id, PRIORITY, match)
        del self.active[key]
        return True

    def sweep_expired(self):
        now = time.time()
        expired = [(v['kind'], v['value']) for v in self.active.values()
                   if not self._is_live(v, now)]
        for kind, value in expired:
            self.active.pop(self._key(kind, value), None)
        return expired

    def reinstall(self, dp):
        """Re-send every live drop rule to ONE switch (after failover or after
        the integrity checker found a rule deleted)."""
        now = time.time()
        for e in list(self.active.values()):
            if not self._is_live(e, now):
                continue
            for d, match in self._pairs([dp], e['kind'], e['value']):
                self._send_drop(d, match, e['kind'], e['value'], e['expires'])

    def export(self):
        return list(self.active.values())

    def load(self, entries):
        now = time.time()
        self.active = {}
        for e in entries or []:
            if self._is_live(e, now):
                self.active[self._key(e['kind'], e['value'])] = dict(e)

    def snapshot(self):
        now = time.time()
        return [{'kind': v['kind'], 'value': v['value'], 'attack': v['attack'],
                 'strike': v['strike'],
                 'seconds_left': None if v['expires'] is None
                 else round(max(0, v['expires'] - now), 1)}
                for v in self.active.values()]
