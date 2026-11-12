"""Attack launcher + measurement helpers, used by topology/topo.py."""
import json
import os
import re
import time
from subprocess import DEVNULL

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKS_DIR = os.path.join(ROOT, 'attacks')
RESULTS_DIR = os.path.join(ROOT, 'results')
EVENTS = os.path.join(ROOT, 'logs', 'events.jsonl')
ATTACKS = ['ping_flood', 'syn_flood', 'port_scan', 'arp_spoof', 'pktin_flood']
ATTACK_MAX = 40          # attacks auto-stop after this many seconds


def start_services(net):
    """h1 is the victim server: plain HTTP server + iperf3 server."""
    h1 = net.get('h1')
    return [
        h1.popen(['python3', '-m', 'http.server', '80', '--bind', h1.IP()],
                 cwd='/tmp', stdout=DEVNULL, stderr=DEVNULL),
        h1.popen(['iperf3', '-s'], stdout=DEVNULL, stderr=DEVNULL),
    ]


def stop(procs):
    if not isinstance(procs, (list, tuple)):
        procs = [procs]
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()


def pick_client(src, victim):
    """A third host that is neither attacker nor victim. (Bug seen in testing:
    `attack arp_spoof h2 h1` used h2 as BOTH attacker and spoofed client, so the
    'spoofed' claim was h2's own true binding - nothing to detect.)"""
    return next(h for h in ('h2', 'h3', 'h4', 'h1') if h not in (src, victim))


def launch(net, name, src, victim, dur=ATTACK_MAX, client=None):
    """Start an attack from host `src` against `victim`. Returns a Popen."""
    client = client or pick_client(src, victim)
    s, v, c = net.get(src), net.get(victim), net.get(client)
    vip = v.IP()
    iface = s.defaultIntf().name
    py = lambda script, *a: ['python3', os.path.join(ATTACKS_DIR, script)] + [str(x) for x in a]
    if name == 'ping_flood':
        # ~10,000 pkts/s on ONE flow: stresses the data plane, not the controller
        cmd = ['hping3', '-1', '-i', 'u100', '-q', vip]
    elif name == 'syn_flood':
        # ~1,000 pkts/s; source port changes every packet -> every packet is a NEW flow
        cmd = ['hping3', '-S', '-p', '80', '-i', 'u1000', '-q', vip]
    elif name == 'port_scan':
        # repeated SYN scan of ports 1-3000
        cmd = ['sh', '-c',
               f'while true; do nmap -sS -n -p 1-3000 --max-rate 1000 {vip} '
               f'>/dev/null 2>&1; done']
    elif name == 'arp_spoof':
        # tell the victim "the client's IP is at my MAC"
        cmd = py('arp_spoof.py', iface, vip, v.MAC(), c.IP(), dur)
    elif name == 'pktin_flood':
        # random source MACs -> controller overload
        cmd = py('pktin_flood.py', iface, vip, dur)
    else:
        raise ValueError(f'unknown attack {name}; choose from {ATTACKS}')
    return s.popen(['timeout', str(dur)] + cmd, stdout=DEVNULL, stderr=DEVNULL)


# ---------- measurement ----------
def _ping_stats(out):
    loss = re.search(r'([\d.]+)% packet loss', out)
    rtt = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms', out)
    first = re.search(r'icmp_seq=1 .*?time=([\d.]+) ms', out)
    return {
        'loss_pct': float(loss.group(1)) if loss else 100.0,
        'avg_ms': float(rtt.group(2)) if rtt else None,
        'max_ms': float(rtt.group(3)) if rtt else None,
        'first_rtt_ms': float(first.group(1)) if first else None,
    }


def _iperf_mbps(out):
    try:
        j = json.loads(out[out.index('{'):])
        return round(j['end']['sum_received']['bits_per_second'] / 1e6, 2)
    except Exception:
        return 0.0


def _http(out):
    try:
        code, secs = out.split()
        return code == '200', round(float(secs) * 1000, 1)
    except Exception:
        return False, None


def _event_summary(t0, t1):
    per_sec, rx_peak, flows_peak = {}, 0, 0
    try:
        with open(EVENTS) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get('type') != 'stats' or not (t0 <= e['t'] <= t1):
                    continue
                sec = int(e['t'])
                per_sec[sec] = per_sec.get(sec, 0) + e['packet_in']
                rx_peak = max(rx_peak, e['rx_pps'])
                flows_peak = max(flows_peak, e['flows'])
    except FileNotFoundError:
        pass
    return {'packet_in_peak_per_s': max(per_sec.values(), default=0),
            'switch_rx_pps_peak': rx_peak, 'flows_peak': flows_peak}


def flush_flows(net, hosts):
    """Delete installed flows for these hosts so the next packets need the
    controller again (otherwise a warm flow table hides the effect)."""
    for sw in net.switches:
        for h in hosts:
            sw.cmd(f'ovs-ofctl -O OpenFlow13 del-flows {sw.name} eth_src={h.MAC()}')


def measure(net, label, attack=None, src='h3', victim='h1', client='h2'):
    """Legit client (h2) talks to victim (h1) while attacker (h3)
    optionally runs `attack`. Saves results/<label>.json."""
    hv, hc = net.get(victim), net.get(client)
    vip = hv.IP()
    hc.cmd(f'ping -c 2 -W 1 {vip}')                    # warm up ARP
    proc = None
    if attack:
        proc = launch(net, attack, src, victim, ATTACK_MAX, client)
        time.sleep(3)                                   # let the attack ramp up
    t0 = time.time()
    flush_flows(net, [hc, hv])                          # force new-flow setup under load
    ping = _ping_stats(hc.cmd(f'ping -c 20 -i 0.2 -W 1 {vip}'))
    mbps = _iperf_mbps(hc.cmd(f'timeout 15 iperf3 -c {vip} -t 5 -J'))
    http_ok, http_ms = _http(hc.cmd(
        f"curl -s -o /dev/null --max-time 3 -w '%{{http_code}} %{{time_total}}' http://{vip}/"))
    t1 = time.time()
    if proc:
        stop(proc)
    hv.cmd('ip neigh flush all')                        # undo ARP poisoning
    hc.cmd('ip neigh flush all')

    res = {'label': label, 'attack': attack or 'none', 'ts': int(t0)}
    res.update(ping)
    res.update({'iperf_mbps': mbps, 'http_ok': http_ok, 'http_ms': http_ms})
    res.update(_event_summary(t0, t1))
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(os.path.join(RESULTS_DIR, f'{label}.json'), 'w') as f:
        json.dump(res, f, indent=2)
    print(res)
    return res
