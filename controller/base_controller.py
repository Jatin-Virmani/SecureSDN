"""Stage 2 baseline controller: learning switch (OpenFlow 1.3) with
fine-grained per-conversation flow rules and per-second statistics events.
NO security yet - this is the 'before' network."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from sdn_events import emit, reset

IDLE = 10   # seconds; short so the flow table doesn't balloon under attack


class BaseController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.pktin = {}        # packet-ins since last tick, per switch
        self.flow_cnt = {}     # installed flows, per switch
        self.rx_total = {}     # total packets received on all ports
        self.rx_pps = {}       # packets/s through the switch
        reset()
        self.monitor = hub.spawn(self._monitor)

    # ---------- switch lifecycle ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_connect(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, parser.OFPMatch(), actions)   # table-miss
        emit('switch_up', dpid=dp.id)
        self.logger.info("switch %s connected", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        else:
            self.datapaths.pop(dp.id, None)

    def add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle, hard_timeout=hard))

    # ---------- forwarding ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
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
        table = self.mac_to_port.setdefault(dp.id, {})
        table[src] = in_port                       # learn
        out_port = table.get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip:                                  # fine-grained L3/L4 rule
                kw = dict(in_port=in_port, eth_src=src, eth_dst=dst,
                          eth_type=ether_types.ETH_TYPE_IP,
                          ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
                t, u = pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
                if t:
                    kw.update(tcp_src=t.src_port, tcp_dst=t.dst_port)
                elif u:
                    kw.update(udp_src=u.src_port, udp_dst=u.dst_port)
                self.add_flow(dp, 10, parser.OFPMatch(**kw), actions, idle=IDLE)
            else:                                   # ARP etc.: L2 rule
                match = parser.OFPMatch(in_port=in_port, eth_src=src,
                                        eth_dst=dst, eth_type=eth.ethertype)
                self.add_flow(dp, 1, match, actions, idle=IDLE)

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=msg.data))

    # ---------- statistics (feeds the dashboard and detector later) ----------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def on_flow_stats(self, ev):
        self.flow_cnt[ev.msg.datapath.id] = len(ev.msg.body)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def on_port_stats(self, ev):
        dpid = ev.msg.datapath.id
        total = sum(s.rx_packets for s in ev.msg.body)
        prev = self.rx_total.get(dpid)
        self.rx_pps[dpid] = 0 if prev is None else max(0, total - prev)
        self.rx_total[dpid] = total

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                ofp, parser = dp.ofproto, dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
                dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY))
            hub.sleep(1)
            for dpid in list(self.datapaths):
                emit('stats', dpid=dpid,
                     packet_in=self.pktin.get(dpid, 0),
                     flows=self.flow_cnt.get(dpid, 0),
                     rx_pps=self.rx_pps.get(dpid, 0))
                self.pktin[dpid] = 0
