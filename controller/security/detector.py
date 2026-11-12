"""Detector fed by the controller on every packet-in and every 1-second
stats tick. Four independent checks, each tied to a specific, distinct
traffic signature (each check was refined after live false positives, described below)

1. SYN_FLOOD  - one real source MAC causing an abnormally high packet-in
   rate (its SYNs keep changing source port, so every packet is a NEW
   flow the switch must ask about). Block target: that MAC.

   Only INITIAL SYNs count (SYN set, ACK not set) - otherwise a victim
   with nothing listening on the targeted port replies with one RST per
   SYN, each a new 5-tuple (since the attacker's source port keeps
   changing), which would make the victim's own MAC look like it's
   "flooding" too. Found via a live false positive: flooding h1->h2:80
   with no server on h2 flagged BOTH h1 and h2 before this fix.

2. PKTIN_FLOOD - many DISTINCT source MACs appearing on the same switch
   port in a short window (randomized-MAC flooding). A single MAC never
   repeats long enough to trip the SYN_FLOOD rate check, which is why
   this needs its own, different signal. Block target: the switch PORT
   (you can't block a MAC that never repeats).

3. PORT_SCAN  - one source IP sending INITIAL SYNs (SYN set, ACK not set)
   to many distinct destination ports in a short window. Checking the SYN
   flag (not just "has a dst_port") is required, otherwise the victim's
   own SYN-ACK/RST replies - which carry many different dst ports, one
   per probe they're answering - get miscounted as the victim scanning.
   Block target: the source IP.

4. ARP_SPOOF  - an ARP packet (reply OR request sender-fields) claims an
   IP -> MAC binding that contradicts a TRUSTED binding. Stage 4 fix: the
   trusted table is now SEEDED at startup with the topology's known
   bindings (like Dynamic ARP Inspection with a static binding table), so
   detection no longer depends on a lucky `pingall` having been run first,
   and a trusted binding is NEVER overwritten by a contradicting claim.
   Only ARP packets are looked at; checking every IP packet's
   (src_ip, eth_src) would falsely flag plain MAC spoofing as ARP spoofing.
   Block target: the MAC (Ethernet source) that sent the false ARP.
"""
import time
from collections import defaultdict, deque

# ---- tunables ----
SYN_RATE_THRESHOLD = 50        # packet-ins/sec from one source MAC -> suspicious
SYN_WINDOW = 2.0                # seconds

PORT_FLOOD_MAC_THRESHOLD = 15   # distinct MACs on one switch port in PORT_FLOOD_WINDOW
PORT_FLOOD_WINDOW = 2.0         # seconds

SCAN_PORT_THRESHOLD = 20        # distinct dst ports from one src IP in SCAN_WINDOW
SCAN_WINDOW = 3.0                # seconds

BLOCK_SECONDS = 30               # base ban length (strike 1) and manual-block length
ALERT_COOLDOWN = 10              # don't re-alert the same target more often than this

TCP_SYN = 0x02
TCP_ACK = 0x10


class Detector:
    def __init__(self, on_detect, trusted_bindings=None):
        """on_detect(attack_type, target, evidence) is called once per
        newly-detected offender (not re-fired every packet while a block
        on that same target is still active)."""
        self.on_detect = on_detect
        self._mac_pktin_times = defaultdict(deque)           # mac -> deque[ts]
        self._port_macs = defaultdict(lambda: deque())       # (dpid,port) -> deque[(ts, mac)]
        self._scan_ports = defaultdict(lambda: defaultdict(set))  # src_ip -> {bucket: {ports}}
        self._ip_mac = dict(trusted_bindings or {})           # ip -> trusted mac
        self._already_flagged = {}                            # (attack, target) -> expiry

    def _flag_once(self, attack, target, evidence):
        key = (attack, target)
        now = time.time()
        if now < self._already_flagged.get(key, 0):
            return                                            # already alerted recently
        self._already_flagged[key] = now + ALERT_COOLDOWN
        self.on_detect(attack, target, evidence)

    # ---- call this on every IP/TCP/UDP packet-in ----
    def on_packet(self, src_mac, dpid, in_port, src_ip=None,
                  dst_port=None, tcp_flags=None, is_edge_port=True):
        now = time.time()
        is_initial_syn = (tcp_flags is not None
                          and (tcp_flags & TCP_SYN) and not (tcp_flags & TCP_ACK))

        # 1. SYN_FLOOD: packet-in rate from one real MAC, counting ONLY
        #    initial SYNs - a victim's RST/RST-ACK replies never set SYN,
        #    so they can never inflate the victim's own rate here.
        if is_initial_syn:
            dq = self._mac_pktin_times[src_mac]
            dq.append(now)
            while dq and now - dq[0] > SYN_WINDOW:
                dq.popleft()
            rate = len(dq) / SYN_WINDOW
            if rate > SYN_RATE_THRESHOLD:
                self._flag_once('syn_flood', src_mac, {'rate_per_s': round(rate, 1)})

        # 2. PKTIN_FLOOD: distinct MACs churning through one EDGE port only.
        # Broadcast/flooded traffic re-appears with the same churn at every
        # trunk (switch-to-switch) port it crosses on its way outward - that
        # is topology, not evidence. Only a host-facing port seeing MAC churn
        # is evidence of a spoofing host actually attached there. Blocking a
        # trunk port would cut off every host behind it, which is worse than
        # the attack, so trunk ports are never evaluated or blocked here.
        if is_edge_port:
            pq = self._port_macs[(dpid, in_port)]
            pq.append((now, src_mac))
            while pq and now - pq[0][0] > PORT_FLOOD_WINDOW:
                pq.popleft()
            distinct = {m for _, m in pq}
            if len(distinct) > PORT_FLOOD_MAC_THRESHOLD:
                self._flag_once('pktin_flood', f'{dpid}:{in_port}',
                                 {'distinct_macs': len(distinct)})

        # 3. PORT_SCAN: reuses the same is_initial_syn computed above, so a
        #    victim's SYN-ACK/RST replies are never miscounted.
        if src_ip and dst_port is not None and is_initial_syn:
            bucket = int(now / SCAN_WINDOW)
            ports = self._scan_ports[src_ip][bucket]
            ports.add(dst_port)
            for b in list(self._scan_ports[src_ip]):
                if b < bucket - 1:
                    del self._scan_ports[src_ip][b]
            if len(ports) > SCAN_PORT_THRESHOLD:
                self._flag_once('port_scan', src_ip, {'distinct_ports': len(ports)})

    def mac_for_ip(self, ip):
        """Trusted MAC for an IP (used to give one host ONE identity for escalation)."""
        return self._ip_mac.get(ip)

    def on_arp(self, claimed_ip, claimed_mac, sender_eth_src):
        """Call for EVERY ARP packet (request or reply). `claimed_*` are the
        ARP sender fields; `sender_eth_src` is the real Ethernet source and is
        what gets blocked. A trusted binding is never overwritten; an unknown
        IP is learned on first sight (trust-on-first-use fallback)."""
        if not claimed_ip or claimed_ip == '0.0.0.0':
            return
        known = self._ip_mac.get(claimed_ip)
        if known is None:
            self._ip_mac[claimed_ip] = claimed_mac
        elif known != claimed_mac:
            self._flag_once('arp_spoof', sender_eth_src,
                            {'claimed_ip': claimed_ip, 'real_mac': known,
                             'claimed_mac': claimed_mac})
