"""SecureSDN controller (final). Everything from stage 3 (detector, blocker,
HMAC admin channel, hash-chained audit log, live defence toggle) PLUS:

  1. Graduated blocking  - repeat offenders get longer bans (security/escalation.py)
  2. Controller failover - run two copies (NODE_ID=c0 / c1); a standby takes
                           over in seconds, keeping blocks + strikes (security/ha.py)
  3. Flow-table integrity - rogue/deleted switch rules (insider attacks) are
                           detected, removed/repaired, logged (security/integrity.py)

Run:  NODE_ID=c0 ryu-manager --ofp-tcp-listen-port 6653 controller/secure_controller.py
      NODE_ID=c1 ryu-manager --ofp-tcp-listen-port 6654 controller/secure_controller.py
(see scripts/run_c0.sh and scripts/run_c1.sh)
"""
import atexit
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, tcp, udp
from sdn_events import emit, reset
from security import detector as det_mod
from security import blocker as blk_mod
from security import audit_log
from security import command_queue
from security import escalation
from security import ha
from security import integrity as integ_mod

IDLE = 10
INTEGRITY_INTERVAL = 3          # seconds between flow-table audits per switch

# (dpid, port) of host-facing ports for THIS topology (topology/topo.py).
# Everything else is a trunk and is exempt from pktin_flood blocking.
EDGE_PORTS = {(2, 2), (2, 3), (3, 2), (3, 3)}   # h1,h2,h3,h4

# Known-good IP -> MAC bindings of the topology (seeds the ARP-spoof detector).
TRUSTED_BINDINGS = {f'10.0.0.{i}': f'00:00:00:00:00:0{i}' for i in range(1, 5)}

# edge port -> the host attached there (pktin_flood is blocked per PORT because the
# MACs are random; mapping the port back to its host lets strikes merge with that host's)
PORT_OWNER = {'2:2': '00:00:00:00:00:01', '2:3': '00:00:00:00:00:02',
              '3:2': '00:00:00:00:00:03', '3:3': '00:00:00:00:00:04'}

BLOCK_KIND = {
    'syn_flood': 'mac',
    'pktin_flood': 'port',
    'port_scan': 'ip',
    'arp_spoof': 'mac',
}


class SecureController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.node_id = os.environ.get('NODE_ID', 'c0')
        self.cluster = ha.Cluster(self.node_id)
        fresh = self.cluster.start()        # True => nobody else alive => fresh cluster
        if fresh:
            reset()
            audit_log.reset()
            command_queue.reset()
            self.cluster.clear_state()

        self.mac_to_port = {}
        self.datapaths = {}
        self.pktin = {}
        self.flow_cnt = {}
        self.rx_total = {}
        self.rx_pps = {}
        self._flow_buf = {}
        self._last_verify = {}

        self.integrity = integ_mod.FlowIntegrity()
        self.blocker = blk_mod.Blocker(integrity=self.integrity)
        self.escalator = escalation.Escalator()
        self.detector = det_mod.Detector(on_detect=self._on_detect,
                                         trusted_bindings=TRUSTED_BINDINGS)
        self.cmd_reader = command_queue.Reader()
        self.defense_on = os.environ.get('DEFENSE', 'on').lower() != 'off'

        if not fresh:                       # joining as standby: adopt leader's mode
            st = self.cluster.load_state()
            if st:
                self.defense_on = st.get('defense_on', self.defense_on)

        role = 'LEADER' if self.is_leader else 'STANDBY'
        emit('defense_mode', enabled=self.defense_on)
        audit_log.append('startup', node=self.node_id, role=role.lower(),
                         defense_on=self.defense_on)
        self.logger.info("[%s] %s  DEFENSE is %s (term %s)", self.node_id, role,
                         "ON" if self.defense_on else "OFF", self.cluster.term)
        atexit.register(self.cluster.release)   # clean exit => instant hand-over

        self.monitor = hub.spawn(self._monitor)
        self.admin_poller = hub.spawn(self._poll_admin_commands)
        self.ha_loop = hub.spawn(self._ha_loop)

    @property
    def is_leader(self):
        return self.cluster.is_leader

    # ================= high availability =================
    def _ha_loop(self):
        while True:
            hub.sleep(1)
            result = self.cluster.tick()
            emit('ha_heartbeat', node=self.node_id,
                 role='leader' if self.is_leader else 'standby',
                 term=self.cluster.term)
            if result and result[0] == 'took_over':
                self._take_over(result[1])
            elif result and result[0] == 'stepped_down':
                self.logger.warning("[%s] stepped down, %s is leader now",
                                    self.node_id, result[1]['by'])
                emit('stepped_down', node=self.node_id, by=result[1]['by'])
            if self.is_leader:
                self._save_state()

    def _save_state(self):
        self.cluster.save_state({
            'defense_on': self.defense_on,
            'blocks': self.blocker.export(),
            'offenders': self.escalator.export(),
            'cmd_seen': self.cmd_reader.seen,
        })

    def _take_over(self, info):
        st = self.cluster.load_state() or {}
        self.defense_on = st.get('defense_on', self.defense_on)
        self.blocker.load(st.get('blocks'))
        self.escalator.load(st.get('offenders'))
        self.cmd_reader.seen = st.get('cmd_seen', self.cmd_reader.seen)
        for dp in list(self.datapaths.values()):
            self._send_role(dp)
            self._install_table_miss(dp)
            self.blocker.reinstall(dp)
        gap = round(info['gap'], 2)
        kept = len(self.blocker.active)
        emit('failover', node=self.node_id, prev_leader=info['prev'], term=self.cluster.term,
             gap_s=gap, blocks_kept=kept, defense_on=self.defense_on)
        audit_log.append('failover', node=self.node_id, prev_leader=info['prev'],
                         term=self.cluster.term, gap_s=gap, blocks_kept=kept)
        self.logger.warning("FAILOVER: %s is now LEADER (term %s, %ss after %s's last "
                            "heartbeat, %d active blocks preserved)",
                            self.node_id, self.cluster.term, gap, info['prev'], kept)

    def _send_role(self, dp):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        role = ofp.OFPCR_ROLE_MASTER if self.is_leader else ofp.OFPCR_ROLE_SLAVE
        # generation_id must only ever grow; wall-clock milliseconds does that
        dp.send_msg(parser.OFPRoleRequest(dp, role, int(time.time() * 1000)))

    @set_ev_cls(ofp_event.EventOFPRoleReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def on_role_reply(self, ev):
        self.logger.info("[%s] s%s role confirmed: %s", self.node_id,
                         ev.msg.datapath.id, "MASTER" if ev.msg.role == 2 else
                         "SLAVE" if ev.msg.role == 3 else ev.msg.role)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def on_error(self, ev):
        m = ev.msg
        self.logger.debug("[%s] OF error type=%s code=%s", self.node_id, m.type, m.code)

    # ================= switch lifecycle =================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_connect(self, ev):
        dp = ev.msg.datapath
        self._send_role(dp)                 # MASTER if leader else SLAVE
        if self.is_leader:
            self._install_table_miss(dp)
        emit('switch_up', dpid=dp.id, node=self.node_id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        else:
            self.datapaths.pop(dp.id, None)

    def _install_table_miss(self, dp):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, parser.OFPMatch(), actions, critical=True,
                      label='table-miss (send to controller)')

    def add_flow(self, dp, priority, match, actions, idle=0, hard=0,
                 critical=False, label=''):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle, hard_timeout=hard,
            cookie=integ_mod.COOKIE))
        self.integrity.expect(dp.id, priority, match, critical=critical, label=label)

    # ================= detection callback =================
    def _identity(self, kind, value):
        """One identity per physical host so strikes accumulate across attack types."""
        if kind == 'ip':
            mac = self.detector.mac_for_ip(value)
            if mac:
                return f'mac:{mac}'
        if kind == 'port' and value in PORT_OWNER:
            return f'mac:{PORT_OWNER[value]}'
        return f'{kind}:{value}'

    def _on_detect(self, attack, target, evidence):
        emit('alert', attack=attack, target=target, evidence=evidence,
             defense_on=self.defense_on, node=self.node_id)
        audit_log.append('alert', attack=attack, target=target, evidence=evidence)
        self.logger.warning("ALERT %s target=%s %s", attack, target, evidence)

        if not self.defense_on:
            return
        kind = BLOCK_KIND[attack]
        if self.blocker.is_blocked(kind, target):
            return
        ident = self._identity(kind, target)
        strike, duration = self.escalator.record(ident, attack)
        did_block = self.blocker.block(list(self.datapaths.values()), kind, target,
                                       duration, attack=attack, strike=strike)
        if did_block:
            entry = self.blocker.get(kind, target)
            emit('block', kind=kind, value=target, attack=attack, strike=strike,
                 duration=duration, expires_at=entry['expires'], identity=ident,
                 forget_at=self.escalator.offenders[ident]['clear_at'])
            audit_log.append('block', kind=kind, value=target, attack=attack,
                             strike=strike, duration=duration)
            self.logger.warning("BLOCKED %s=%s (%s) strike #%d for %s", kind, target,
                                attack, strike, escalation.label(duration))
            self._save_state()

    # ================= forwarding + detection hook =================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        if not self.is_leader:
            return                           # standby must never act
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']
        self.pktin[dp.id] = self.pktin.get(dp.id, 0) + 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        src, dst = eth.src, eth.dst

        if self.blocker.is_port_blocked(dp.id, in_port):
            return
        if self.blocker.is_blocked('mac', src):
            return

        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
        dst_port = t.dst_port if t else (u.dst_port if u else None)
        src_ip = ip.src if ip else (arp_pkt.src_ip if arp_pkt else None)
        tcp_flags = t.bits if t else None

        if src_ip and self.blocker.is_blocked('ip', src_ip):
            return

        self.detector.on_packet(src, dp.id, in_port, src_ip=src_ip,
                                dst_port=dst_port, tcp_flags=tcp_flags,
                                is_edge_port=(dp.id, in_port) in EDGE_PORTS)
        if arp_pkt:
            self.detector.on_arp(arp_pkt.src_ip, arp_pkt.src_mac, src)

        # the detector may have just blocked this sender: don't forward this packet
        if (self.blocker.is_port_blocked(dp.id, in_port)
                or self.blocker.is_blocked('mac', src)
                or (src_ip and self.blocker.is_blocked('ip', src_ip))):
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[src] = in_port
        out_port = table.get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            if ip:
                kw = dict(in_port=in_port, eth_src=src, eth_dst=dst,
                          eth_type=ether_types.ETH_TYPE_IP,
                          ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
                if t:
                    kw.update(tcp_src=t.src_port, tcp_dst=t.dst_port)
                elif u:
                    kw.update(udp_src=u.src_port, udp_dst=u.dst_port)
                self.add_flow(dp, 10, parser.OFPMatch(**kw), actions, idle=IDLE)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_src=src,
                                        eth_dst=dst, eth_type=eth.ethertype)
                self.add_flow(dp, 1, match, actions, idle=IDLE)

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=msg.data))

    # ================= stats + flow-table integrity =================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def on_flow_stats(self, ev):
        msg = ev.msg
        dp = msg.datapath
        buf = self._flow_buf.setdefault(dp.id, [])
        buf.extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return                           # multipart reply: wait for the rest
        body = self._flow_buf.pop(dp.id)
        self.flow_cnt[dp.id] = len(body)
        now = time.time()
        if self.is_leader and now - self._last_verify.get(dp.id, 0) >= INTEGRITY_INTERVAL:
            self._last_verify[dp.id] = now
            self._verify_flows(dp, body)

    def _verify_flows(self, dp, body):
        rogue, missing = self.integrity.check(dp.id, body)
        emit('integrity_scan', dpid=dp.id, flows=len(body),
             rogue=len(rogue), missing=len(missing))
        ofp, parser = dp.ofproto, dp.ofproto_parser

        for n, stat in enumerate(rogue):
            match_s, action_s = integ_mod.describe(stat)
            target = f's{dp.id} priority={stat.priority}'
            ev = {'match': match_s, 'action': action_s}
            if n < 3:                      # never flood the feed/audit log
                self._integrity_alert('rogue_flow', target, ev)
                if self.defense_on:
                    emit('flow_removed', dpid=dp.id,
                     priority=stat.priority, **ev)
            if self.defense_on:
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, table_id=stat.table_id,
                    command=ofp.OFPFC_DELETE_STRICT, out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY, priority=stat.priority, match=stat.match))
                if n < 3:
                    audit_log.append('flow_removed', dpid=dp.id, priority=stat.priority, **ev)
                    self.logger.warning("REMOVED rogue flow on s%s: %s -> %s",
                                        dp.id, match_s, action_s)
        if len(rogue) > 3:
            self.logger.warning("... and %d more rogue flows on s%s", len(rogue) - 3, dp.id)
            audit_log.append('flow_removed_bulk', dpid=dp.id, count=len(rogue))

        for m in missing:
            target = f's{dp.id} {m["label"]}'
            self._integrity_alert('flow_deleted', target, {'rule': m['label']})
            if self.defense_on:
                if m['fp'][1] == 0:          # priority 0 = the table-miss rule
                    self._install_table_miss(dp)
                else:
                    self.blocker.reinstall(dp)
                emit('flow_restored', dpid=dp.id, rule=m['label'])
                audit_log.append('flow_restored', dpid=dp.id, rule=m['label'])
                self.logger.warning("RESTORED deleted rule on s%s: %s", dp.id, m['label'])

    def _integrity_alert(self, attack, target, evidence):
        emit('alert', attack=attack, target=target, evidence=evidence,
             defense_on=self.defense_on, node=self.node_id)
        audit_log.append('alert', attack=attack, target=target, evidence=evidence)
        self.logger.warning("ALERT %s target=%s %s", attack, target, evidence)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def on_port_stats(self, ev):
        dpid = ev.msg.datapath.id
        total = sum(s.rx_packets for s in ev.msg.body)
        prev = self.rx_total.get(dpid)
        self.rx_pps[dpid] = 0 if prev is None else max(0, total - prev)
        self.rx_total[dpid] = total

    def _monitor(self):
        while True:
            if not self.is_leader:
                hub.sleep(1)
                continue
            for dp in list(self.datapaths.values()):
                ofp, parser = dp.ofproto, dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
                dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))
            hub.sleep(1)
            for dpid in list(self.datapaths):
                emit('stats', dpid=dpid, packet_in=self.pktin.get(dpid, 0),
                     flows=self.flow_cnt.get(dpid, 0), rx_pps=self.rx_pps.get(dpid, 0))
                self.pktin[dpid] = 0
            for kind, value in self.blocker.sweep_expired():
                emit('unblock', kind=kind, value=value, reason='expired')
                audit_log.append('unblock', kind=kind, value=value, reason='expired')

    # ================= admin commands (HMAC-verified upstream) =================
    def _poll_admin_commands(self):
        while True:
            hub.sleep(1)
            if not self.is_leader:
                continue
            for cmd in self.cmd_reader.poll():
                action, kind, value = cmd['action'], cmd['kind'], cmd['value']
                dps = list(self.datapaths.values())
                if action == 'block':
                    if self.blocker.block(dps, kind, value, det_mod.BLOCK_SECONDS,
                                          attack='manual', strike=0):
                        entry = self.blocker.get(kind, value)
                        emit('block', kind=kind, value=value, attack='manual', strike=0,
                             duration=det_mod.BLOCK_SECONDS, expires_at=entry['expires'],
                             identity=self._identity(kind, value), forget_at=None)
                        audit_log.append('block', kind=kind, value=value, attack='manual')
                elif action == 'unblock':
                    if self.blocker.unblock(dps, kind, value):
                        self.escalator.on_unblock(self._identity(kind, value))
                    emit('unblock', kind=kind, value=value, reason='manual')
                    audit_log.append('unblock', kind=kind, value=value, reason='manual')
                elif action == 'defense':
                    self.defense_on = (value == 'on')
                    emit('defense_mode', enabled=self.defense_on)
                    audit_log.append('defense_mode', enabled=self.defense_on)
                    self.logger.warning("DEFENSE is now %s", "ON" if self.defense_on else "OFF")
                self._save_state()
