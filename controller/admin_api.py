"""Small HTTP API an operator (or later, the dashboard) uses to force a
block/unblock. Runs as its OWN process (plain Python, not the Ryu venv's
eventlet loop), and only talks to the controller indirectly via
command_queue.py's file. Every request must carry a valid HMAC signature
(see security/crypto_utils.py) - an unsigned or replayed request is
rejected with 403 and never reaches the controller.

Run: python3 controller/admin_api.py
Then: python3 scripts/send_admin_command.py block ip 10.0.0.3
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from security import crypto_utils
from security import command_queue
from security import audit_log

app = Flask(__name__)


@app.route('/command', methods=['POST'])
def command():
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify(ok=False, reason='bad json'), 400

    ok, reason = crypto_utils.verify_command(payload)
    if not ok:
        audit_log.append('admin_rejected', reason=reason,
                         action=payload.get('action'), target=payload.get('target'))
        return jsonify(ok=False, reason=reason), 403

    action = payload['action']            # 'block', 'unblock', or 'defense'
    target = payload['target']            # "ip:10.0.0.3" / "mac:00:00:.." / "defense:on"
    kind, _, value = target.partition(':')
    valid = (
        (action in ('block', 'unblock') and kind in ('ip', 'mac', 'port') and value) or
        (action == 'defense' and kind == 'defense' and value in ('on', 'off'))
    )
    if not valid:
        return jsonify(ok=False, reason='bad action/target'), 400

    command_queue.push(action, kind, value)
    audit_log.append('admin_accepted', action=action, kind=kind, value=value)
    return jsonify(ok=True)


@app.route('/chain/verify', methods=['GET'])
def chain_verify():
    return jsonify(audit_log.verify())


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050)
