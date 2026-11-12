#!/usr/bin/env python3
"""SecureSDN topology: core switch s1, edge switches s2/s3, hosts h1-h4.
Adds `attack`, `measure`, and `runall` commands to the Mininet CLI."""
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from attacks import lib


class SecureTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        hosts = [self.addHost(f'h{i}', ip=f'10.0.0.{i}/24',
                              mac=f'00:00:00:00:00:0{i}') for i in range(1, 5)]
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(hosts[0], s2)
        self.addLink(hosts[1], s2)
        self.addLink(hosts[2], s3)
        self.addLink(hosts[3], s3)


class SecureCLI(CLI):
    def do_attack(self, line):
        "attack <name> <src_host> <victim_host> <seconds>   e.g. attack syn_flood h3 h1 15"
        try:
            name, src, victim, secs = line.split()
            proc = lib.launch(self.mn, name, src, victim, float(secs))
        except (ValueError, KeyError) as e:
            print(f'usage error ({e}). names: {lib.ATTACKS}')
            return
        try:
            time.sleep(float(secs))
        except KeyboardInterrupt:
            pass
        lib.stop(proc)

    def do_insider(self, line):
        """insider <rogue|wipe> <switch>   simulate an INSIDER tampering with a switch
        rogue : plant a hidden priority-500 rule that black-holes traffic to h1
        wipe  : delete EVERY rule on the switch (table-miss + attacker drop rules)
        e.g.  insider rogue s2      insider wipe s3"""
        parts = line.split()
        if len(parts) != 2 or parts[0] not in ('rogue', 'wipe'):
            print('usage: insider <rogue|wipe> <switch>   e.g. insider rogue s2')
            return
        what, sw = parts
        try:
            node = self.mn.get(sw)
        except KeyError:
            print(f'no such switch {sw}')
            return
        if what == 'rogue':
            node.cmd(f'ovs-ofctl -O OpenFlow13 add-flow {sw} '
                     f'"priority=500,ip,nw_dst=10.0.0.1,actions=drop"')
            print(f'[insider] planted rogue rule on {sw}: ip->10.0.0.1 DROP (priority 500)')
        else:
            node.cmd(f'ovs-ofctl -O OpenFlow13 del-flows {sw}')
            print(f'[insider] wiped ALL flow rules on {sw}')

    def do_measure(self, line):
        "measure <label> [attack_name]   (attacker h3, victim h1, client h2)"
        parts = line.split()
        if not parts:
            print('usage: measure <label> [attack_name]')
            return
        lib.measure(self.mn, parts[0], attack=parts[1] if len(parts) > 1 else None)

    def do_runall(self, line):
        "runall <prefix>   baseline + every attack, results saved in results/"
        prefix = line.strip() or 'run'
        lib.measure(self.mn, f'{prefix}_baseline')
        for a in lib.ATTACKS:
            time.sleep(5)
            lib.measure(self.mn, f'{prefix}_{a}', attack=a)


if __name__ == '__main__':
    setLogLevel('info')
    # Two controllers for high availability: c0 (primary, :6653) and c1 (standby,
    # :6654). Every switch connects to BOTH; the controllers elect who leads.
    net = Mininet(topo=SecureTopo(), switch=OVSSwitch, controller=None,
                  autoSetMacs=False)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6654)
    net.start()
    net.waitConnected()
    services = lib.start_services(net)
    try:
        SecureCLI(net)
    finally:
        lib.stop(services)
        net.stop()
