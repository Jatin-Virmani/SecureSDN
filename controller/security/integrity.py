"""FEATURE 3 - Flow-table integrity checker (insider-threat defence).

Everything the controller installs is recorded here. Every few seconds the
controller asks each switch for its REAL flow table and compares:

  * ROGUE flow     - present in the switch, never installed by the controller
                     (an insider with shell access ran `ovs-ofctl add-flow`
                     to black-hole / redirect traffic).  -> alert, delete it.
  * DELETED flow   - a CRITICAL rule we installed (table-miss rule, or an
                     attacker's drop rule) vanished before its time
                     (insider ran `ovs-ofctl del-flows`).  -> alert, re-install.

Ordinary forwarding flows have idle timeouts and disappear naturally, so a
missing one is NOT suspicious; only critical rules are checked for deletion.

LEGITIMACY (robust across failover): every rule the controllers install carries
a secret cookie (COOKIE). A rule with that cookie is ours - whichever controller
installed it. A rule without it, and not in our records, is ROGUE.

A flow is fingerprinted as (table, priority, sorted match fields). The same
fingerprint function is applied to the match we SENT and the match the
switch REPORTS back (tested to round-trip identically).
"""
import hashlib
import time

from security import crypto_utils

# Secret cookie stamped on EVERY rule our controllers install. Derived from the
# admin HMAC key, so both controllers (c0/c1) compute the same value and an
# insider typing `ovs-ofctl add-flow` (cookie 0) cannot guess it.
COOKIE = int.from_bytes(hashlib.sha256(b"flow-cookie:" + crypto_utils.load_or_create_key()).digest()[:8], "big")

GRACE = 3.0            # a rule younger than this may not be in the stats reply yet
ALERT_COOLDOWN = 20.0  # don't re-alert the same fingerprint more often than this


def fingerprint(table_id, priority, match):
    return (int(table_id), int(priority),
            tuple(sorted((k, str(v)) for k, v in match.items())))


def describe(stat):
    """Human-readable (match, action) strings for an OFPFlowStats entry."""
    m = ','.join(f'{k}={v}' for k, v in stat.match.items()) or 'ANY'
    acts = []
    for inst in getattr(stat, 'instructions', []) or []:
        for a in getattr(inst, 'actions', []) or []:
            port = getattr(a, 'port', None)
            acts.append(f'output:{port}' if port is not None else type(a).__name__)
    return m, (','.join(acts) if acts else 'DROP')


class FlowIntegrity:
    def __init__(self):
        self.expected = {}       # (dpid, fp) -> {'critical','t','expires','label'}
        self._alerted = {}       # (dpid, fp) -> ts

    # ---- bookkeeping, called by the controller whenever it installs something ----
    def expect(self, dpid, priority, match, critical=False, expires=None,
               label='', table_id=0):
        self.expected[(dpid, fingerprint(table_id, priority, match))] = {
            'critical': critical, 't': time.time(), 'expires': expires, 'label': label}

    def forget(self, dpid, priority, match, table_id=0):
        self.expected.pop((dpid, fingerprint(table_id, priority, match)), None)

    # ---- the actual comparison ----
    def check(self, dpid, stats):
        """stats = list of OFPFlowStats. Returns (rogue_stats, missing_entries)."""
        now = time.time()
        present = {}
        for s in stats:
            present[fingerprint(s.table_id, s.priority, s.match)] = s

        rogue = []
        for fp, s in present.items():
            # legit = carries OUR secret cookie (installed by either controller,
            # so failover needs no hand-over of flow lists) or is in our records
            if getattr(s, 'cookie', 0) == COOKIE or (dpid, fp) in self.expected:
                continue
            last = self._alerted.get((dpid, fp), 0)
            if now - last >= ALERT_COOLDOWN:
                self._alerted[(dpid, fp)] = now
                rogue.append(s)

        missing = []
        for (d, fp), e in list(self.expected.items()):
            if d != dpid or fp in present:
                continue
            if now - e['t'] < GRACE:
                continue
            if e['expires'] is not None and now > e['expires']:
                del self.expected[(d, fp)]               # legitimately expired
            elif not e['critical']:
                del self.expected[(d, fp)]               # idle-timed-out: normal
            else:
                last = self._alerted.get((d, fp), 0)
                if now - last >= ALERT_COOLDOWN:
                    self._alerted[(d, fp)] = now
                    missing.append({'fp': fp, 'label': e['label']})
        return rogue, missing
