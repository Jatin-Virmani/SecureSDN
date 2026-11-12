"""Live dashboard backend. Reads logs/events.jsonl (written by the Ryu
controller(s)) INCREMENTALLY - only new bytes each poll - and keeps the
current state in memory. It never talks to Ryu directly. Every control
action (block/unblock/defense toggle) goes through the SAME HMAC-sign ->
verify -> command_queue path as the external admin API, so the dashboard is
not a backdoor around the security - it is just another client of it.

Run: python3 controller/dashboard_api.py     then open http://127.0.0.1:5000
"""
import json
import os
import sys
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, send_from_directory
from security import crypto_utils, command_queue, audit_log, escalation

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTS = os.path.join(ROOT, 'logs', 'events.jsonl')
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
NODE_DEAD_AFTER = 4.0        # seconds without a heartbeat => controller is DOWN

app = Flask(__name__, static_folder=None)


class Model:
    def __init__(self):
        self.pos = 0
        self.clear()

    def clear(self):
        self.alerts = deque(maxlen=200)
        self.blocks = {}            # "kind:value" -> block event
        self.offenders = {}         # identity -> {strikes,last_attack,forget_at}
        self.stats = {}             # dpid -> deque of samples
        self.defense_on = True
        self.nodes = {}             # node -> {t, role, term}
        self.failovers = deque(maxlen=10)
        self.integrity_events = deque(maxlen=12)
        self.scan = {}              # dpid -> {t, flows, rogue, missing}
        self.rogue_removed = 0
        self.rules_restored = 0
        self.total_alerts = 0
        self.total_blocks = 0

    def feed(self, e):
        et = e.get('type')
        if et == 'alert':
            self.alerts.append(e)
            self.total_alerts += 1
            if e.get('attack') in ('rogue_flow', 'flow_deleted'):
                self.integrity_events.append(
                    {'t': e['t'], 'kind': e['attack'], 'text': f"{e['target']}"})
        elif et == 'block':
            self.blocks[f"{e['kind']}:{e['value']}"] = e
            self.total_blocks += 1
            ident = e.get('identity')
            if ident and e.get('strike', 0) > 0:
                self.offenders[ident] = {'strikes': e['strike'], 'last_attack': e['attack'],
                                         'forget_at': e.get('forget_at'), 't': e['t']}
        elif et == 'unblock':
            self.blocks.pop(f"{e['kind']}:{e['value']}", None)
        elif et == 'stats':
            self.stats.setdefault(e['dpid'], deque(maxlen=60)).append(e)
        elif et == 'defense_mode':
            self.defense_on = e['enabled']
        elif et == 'ha_heartbeat':
            self.nodes[e['node']] = {'t': e['t'], 'role': e['role'], 'term': e['term']}
        elif et == 'failover':
            self.failovers.append(e)
        elif et == 'integrity_scan':
            self.scan[e['dpid']] = {'t': e['t'], 'flows': e['flows'],
                                    'rogue': e['rogue'], 'missing': e['missing']}
        elif et == 'flow_removed':
            self.rogue_removed += 1
            self.integrity_events.append({'t': e['t'], 'kind': 'removed',
                                          'text': f"s{e['dpid']} prio {e['priority']} ({e['action']}) deleted"})
        elif et == 'flow_restored':
            self.rules_restored += 1
            self.integrity_events.append({'t': e['t'], 'kind': 'restored',
                                          'text': f"s{e['dpid']} {e['rule']} re-installed"})

    def refresh(self):
        """Read only the new complete lines since last call."""
        try:
            size = os.path.getsize(EVENTS)
        except OSError:
            return
        if size < self.pos:                  # controller restarted and truncated the log
            self.pos = 0
            self.clear()
        if size == self.pos:
            return
        with open(EVENTS, 'rb') as f:
            f.seek(self.pos)
            chunk = f.read()
        end = chunk.rfind(b'\n')
        if end < 0:
            return
        self.pos += end + 1
        for line in chunk[:end].split(b'\n'):
            try:
                self.feed(json.loads(line))
            except ValueError:
                pass

    def snapshot(self):
        now = time.time()
        blocks = []
        for b in self.blocks.values():
            exp = b.get('expires_at')
            left = None if exp is None else round(exp - now, 1)
            if left is not None and left <= 0:
                continue
            blocks.append({'kind': b['kind'], 'value': b['value'], 'attack': b.get('attack'),
                           'strike': b.get('strike', 0), 'duration': b.get('duration'),
                           'seconds_left': left, 'label': escalation.label(b.get('duration'))
                           if b.get('strike') else '30s (manual)'})
        offenders = []
        for ident, o in self.offenders.items():
            if o['forget_at'] is not None and now > o['forget_at']:
                continue
            offenders.append({'identity': ident, 'strikes': o['strikes'],
                              'last_attack': o['last_attack'],
                              'next': escalation.label(escalation.duration_for(o['strikes'] + 1)),
                              'forget_in': None if o['forget_at'] is None
                              else round(o['forget_at'] - now)})
        nodes = {}
        for name in ('c0', 'c1'):
            n = self.nodes.get(name)
            alive = bool(n) and now - n['t'] < NODE_DEAD_AFTER
            nodes[name] = {'alive': alive, 'role': n['role'] if alive else 'down',
                           'term': n['term'] if n else 0}
        recent = [f for f in self.failovers if now - f['t'] < 20]
        total_flows = sum(s['flows'] for s in self.scan.values())
        last_scan = max((s['t'] for s in self.scan.values()), default=None)
        return {
            'alerts': list(reversed(list(self.alerts)[-15:])),
            'blocks': blocks,
            'offenders': offenders,
            'ladder': escalation.LADDER,
            'forget_after': escalation.FORGET_AFTER,
            'stats': {d: list(v) for d, v in self.stats.items()},
            'defense_on': self.defense_on,
            'nodes': nodes,
            'failovers': list(reversed(self.failovers)),
            'failover_banner': recent[-1] if recent else None,
            'integrity': {'events': list(reversed(self.integrity_events)),
                          'rogue_removed': self.rogue_removed,
                          'rules_restored': self.rules_restored,
                          'switches_scanned': len(self.scan),
                          'flows_verified': total_flows,
                          'last_scan_age': None if last_scan is None else round(now - last_scan, 1),
                          'violations_last_scan': sum(s['rogue'] + s['missing']
                                                      for s in self.scan.values())},
            'totals': {'alerts': self.total_alerts, 'blocks': self.total_blocks,
                       'failovers': len(self.failovers)},
            'server_time': now,
        }


MODEL = Model()


@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'dashboard.html')


@app.route('/api/state')
def api_state():
    MODEL.refresh()
    return jsonify(MODEL.snapshot())


@app.route('/api/chain')
def api_chain():
    return jsonify(audit_log.verify())


@app.route('/api/audit')
def api_audit():
    return jsonify([{'t': e.get('t'), 'type': e.get('type'),
                     'hash': (e.get('hash') or '')[:12],
                     'detail': ' '.join(f'{k}={v}' for k, v in e.items()
                                        if k not in ('prev', 'hash', 't', 'type'))[:90]}
                    for e in reversed(audit_log.tail(8))])


def _issue_command(action, kind, value):
    """Sign, verify, enqueue - the exact same gate admin_api.py uses."""
    cmd = crypto_utils.sign_command(action, f'{kind}:{value}')
    ok, reason = crypto_utils.verify_command(cmd)
    if not ok:
        audit_log.append('admin_rejected', reason=reason, action=action,
                         target=f'{kind}:{value}', source='dashboard')
        return False, reason
    command_queue.push(action, kind, value)
    audit_log.append('admin_accepted', action=action, kind=kind, value=value,
                     source='dashboard')
    return True, 'ok'


def _kv():
    body = request.get_json(force=True, silent=True) or {}
    return body.get('kind'), body.get('value')


@app.route('/ui/block', methods=['POST'])
def ui_block():
    kind, value = _kv()
    if kind not in ('ip', 'mac', 'port') or not value:
        return jsonify(ok=False, reason='bad kind/value'), 400
    ok, reason = _issue_command('block', kind, value)
    return jsonify(ok=ok, reason=reason)


@app.route('/ui/unblock', methods=['POST'])
def ui_unblock():
    kind, value = _kv()
    if kind not in ('ip', 'mac', 'port') or not value:
        return jsonify(ok=False, reason='bad kind/value'), 400
    ok, reason = _issue_command('unblock', kind, value)
    return jsonify(ok=ok, reason=reason)


@app.route('/ui/defense', methods=['POST'])
def ui_defense():
    body = request.get_json(force=True, silent=True) or {}
    value = body.get('value')
    if value not in ('on', 'off'):
        return jsonify(ok=False, reason='bad value'), 400
    ok, reason = _issue_command('defense', 'defense', value)
    return jsonify(ok=ok, reason=reason)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, threaded=True)
