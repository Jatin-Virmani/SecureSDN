"""Offline tests (no Mininet needed):  source .venv/bin/activate && python -m unittest -v tests.test_stage4
Uses a fake switch that just records every OpenFlow message the controller sends."""
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'controller'))

from ryu.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as parser
from security import escalation, integrity, blocker as blk_mod, ha, audit_log, command_queue
from security import detector as det_mod


class FakeDP:
    def __init__(self, dpid):
        self.id = dpid
        self.ofproto, self.ofproto_parser = ofp, parser
        self.sent = []

    def send_msg(self, m):
        self.sent.append(m)


def flow_stat(prio, match, out=None, table=0):
    acts = [parser.OFPActionOutput(out)] if out is not None else []
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)] if acts else []
    return parser.OFPFlowStats(table_id=table, priority=prio, match=match, instructions=inst, cookie=0)


class TestEscalation(unittest.TestCase):
    def test_ladder_and_quarantine(self):
        e = escalation.Escalator()
        got = [e.record('mac:aa', 'syn_flood') for _ in range(7)]
        self.assertEqual([d for _, d in got[:5]], escalation.LADDER)
        self.assertEqual([n for n, _ in got], [1, 2, 3, 4, 5, 6, 7])
        self.assertIsNone(got[5][1])                       # strike 6 => quarantine
        self.assertIsNone(got[6][1])

    def test_forgiveness_after_good_behaviour(self):
        e = escalation.Escalator()
        e.record('mac:aa', 'x')
        e.offenders['mac:aa']['clear_at'] = time.time() - 1
        self.assertEqual(e.strikes('mac:aa'), 0)
        self.assertEqual(e.record('mac:aa', 'x')[0], 1)

    def test_export_load(self):
        e = escalation.Escalator(); e.record('a', 'x'); e.record('a', 'x')
        e2 = escalation.Escalator(); e2.load(json.loads(json.dumps(e.export())))
        self.assertEqual(e2.strikes('a'), 2)


class TestBlocker(unittest.TestCase):
    def test_block_unblock_and_permanent(self):
        dps = [FakeDP(1), FakeDP(2)]
        integ = integrity.FlowIntegrity()
        b = blk_mod.Blocker(integrity=integ)
        self.assertTrue(b.block(dps, 'mac', '00:00:00:00:00:03', 30, 'syn_flood', 1))
        self.assertFalse(b.block(dps, 'mac', '00:00:00:00:00:03', 60, 'syn_flood', 2))
        self.assertEqual(len(dps[0].sent), 1)
        self.assertEqual(dps[0].sent[0].hard_timeout, 32)
        self.assertTrue(b.block(dps, 'ip', '10.0.0.3', None, 'port_scan', 6))   # quarantine
        self.assertEqual(dps[0].sent[-1].hard_timeout, 0)
        self.assertTrue(b.is_blocked('ip', '10.0.0.3'))
        b.block(dps, 'port', '2:2', 30, 'pktin_flood', 1)
        self.assertEqual(sum(1 for m in dps[1].sent), 3)     # port block only on s2
        self.assertEqual(sum(1 for m in dps[0].sent), 2)
        b.unblock(dps, 'ip', '10.0.0.3')
        self.assertFalse(b.is_blocked('ip', '10.0.0.3'))

    def test_export_load_reinstall(self):
        dp = FakeDP(1)
        b = blk_mod.Blocker(); b.block([dp], 'mac', 'aa:aa:aa:aa:aa:aa', 100, 'syn_flood', 2)
        b2 = blk_mod.Blocker(); b2.load(json.loads(json.dumps(b.export())))
        self.assertTrue(b2.is_blocked('mac', 'aa:aa:aa:aa:aa:aa'))
        dp2 = FakeDP(1); b2.reinstall(dp2)
        self.assertEqual(len(dp2.sent), 1)
        self.assertLessEqual(dp2.sent[0].hard_timeout, 102)


class TestIntegrity(unittest.TestCase):
    def test_fingerprint_roundtrip_through_wire_format(self):
        m = parser.OFPMatch(in_port=2, eth_src='00:00:00:00:00:03', eth_dst='00:00:00:00:00:01',
                            eth_type=0x800, ipv4_src='10.0.0.3', ipv4_dst='10.0.0.1',
                            ip_proto=6, tcp_src=1234, tcp_dst=80)
        buf = bytearray(); m.serialize(buf, 0)
        m2 = parser.OFPMatch.parser(bytes(buf), 0)
        self.assertEqual(integrity.fingerprint(0, 10, m), integrity.fingerprint(0, 10, m2))

    def test_rogue_and_deleted_detection(self):
        fi = integrity.FlowIntegrity()
        miss, legit = parser.OFPMatch(), parser.OFPMatch(in_port=2, eth_src='00:00:00:00:00:01')
        fi.expect(2, 0, miss, critical=True, label='table-miss')
        fi.expect(2, 1, legit)
        drop = parser.OFPMatch(eth_src='00:00:00:00:00:03')
        fi.expect(2, 1000, drop, critical=True, expires=time.time() + 100, label='block')
        for e in fi.expected.values():
            e['t'] -= 10                                  # age past GRACE
        rogue_m = parser.OFPMatch(eth_type=0x800, ipv4_src='10.0.0.1')
        stats = [flow_stat(0, miss, ofp.OFPP_CONTROLLER), flow_stat(1, legit, 3),
                 flow_stat(1000, drop), flow_stat(500, rogue_m)]          # 500 = insider's rule
        rogue, missing = fi.check(2, stats)
        self.assertEqual([s.priority for s in rogue], [500])
        self.assertEqual(integrity.describe(rogue[0])[1], 'DROP')
        self.assertEqual(missing, [])
        # insider deletes the table-miss + block rules; idle-expired forwarding flow is NOT reported
        rogue, missing = fi.check(2, [])
        self.assertEqual(sorted(m['label'] for m in missing), ['block', 'table-miss'])

    def test_cookie_makes_flows_legit_across_failover(self):
        fi = integrity.FlowIntegrity()                     # a brand-new leader: knows nothing
        fwd = parser.OFPMatch(in_port=2, eth_src='00:00:00:00:00:01')
        evil = parser.OFPMatch(eth_src='00:00:00:00:00:02')
        ours = flow_stat(10, fwd, 3); ours.cookie = integrity.COOKIE
        insider = flow_stat(10, evil, 3); insider.cookie = 0   # same priority, no cookie
        rogue, _ = fi.check(2, [ours, insider])
        self.assertEqual([s.match['eth_src'] for s in rogue], ['00:00:00:00:00:02'])

    def test_mass_failover_no_false_positives(self):
        fi = integrity.FlowIntegrity()
        flows = []
        for i in range(5000):
            f = flow_stat(10, parser.OFPMatch(in_port=2, tcp_src=1000 + i, ip_proto=6, eth_type=0x800), 3)
            f.cookie = integrity.COOKIE; flows.append(f)
        self.assertEqual(fi.check(3, flows)[0], [])


class TestDetector(unittest.TestCase):
    def test_arp_spoof_works_without_pingall(self):
        hits = []
        d = det_mod.Detector(lambda a, t, e: hits.append((a, t)),
                             {'10.0.0.2': '00:00:00:00:00:02'})
        d.on_arp('10.0.0.2', '00:00:00:00:00:02', '00:00:00:00:00:02')      # legit
        self.assertEqual(hits, [])
        d.on_arp('10.0.0.2', '00:00:00:00:00:03', '00:00:00:00:00:03')      # h3 lies
        self.assertEqual(hits, [('arp_spoof', '00:00:00:00:00:03')])
        self.assertEqual(d.mac_for_ip('10.0.0.2'), '00:00:00:00:00:02')     # never overwritten

    def test_attacker_equal_to_client_is_not_spoofing(self):
        hits = []
        d = det_mod.Detector(lambda a, t, e: hits.append(a), {'10.0.0.2': '00:00:00:00:00:02'})
        d.on_arp('10.0.0.2', '00:00:00:00:00:02', '00:00:00:00:00:02')
        self.assertEqual(hits, [])


class TestHA(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        ha.LOGS, ha.LEASE = self.tmp, os.path.join(self.tmp, 'leader.json')
        ha.STATE, ha.LOCK = os.path.join(self.tmp, 's.json'), os.path.join(self.tmp, '.lock')

    def test_election_and_failover(self):
        a, b = ha.Cluster('c0'), ha.Cluster('c1')
        self.assertTrue(a.start()); self.assertFalse(b.start())
        self.assertIsNone(a.tick()); self.assertIsNone(b.tick())
        a.save_state({'blocks': [1]})
        # c0 dies: lease goes stale
        lease = json.load(open(ha.LEASE)); lease['ts'] -= 10; json.dump(lease, open(ha.LEASE, 'w'))
        r = b.tick()
        self.assertEqual(r[0], 'took_over'); self.assertTrue(b.is_leader)
        self.assertEqual(r[1]['prev'], 'c0'); self.assertEqual(b.term, 2)
        self.assertEqual(b.load_state()['blocks'], [1])
        # zombie c0 wakes up: must step down
        self.assertEqual(a.tick()[0], 'stepped_down'); self.assertFalse(a.is_leader)

    def test_clean_release_is_instant(self):
        a, b = ha.Cluster('c0'), ha.Cluster('c1')
        a.start(); b.start(); a.release()
        self.assertEqual(b.tick()[0], 'took_over')


class TestCommandQueue(unittest.TestCase):
    def test_reader_skips_history(self):
        tmp = tempfile.mkdtemp(); command_queue.QUEUE_PATH = os.path.join(tmp, 'q.jsonl')
        command_queue.push('defense', 'defense', 'off')            # old command from a previous run
        r = command_queue.Reader()
        self.assertEqual(r.poll(), [])                              # NOT replayed
        command_queue.push('block', 'ip', '10.0.0.3')
        self.assertEqual(len(r.poll()), 1)


class TestAuditChain(unittest.TestCase):
    def test_tamper_detected(self):
        tmp = tempfile.mkdtemp(); audit_log.LOG_PATH = os.path.join(tmp, 'a.jsonl')
        for i in range(3):
            audit_log.append('x', i=i)
        self.assertTrue(audit_log.verify()['ok'])
        lines = open(audit_log.LOG_PATH).read().replace('"i": 1', '"i": 9')
        open(audit_log.LOG_PATH, 'w').write(lines)
        self.assertFalse(audit_log.verify()['ok'])


if __name__ == '__main__':
    unittest.main()
