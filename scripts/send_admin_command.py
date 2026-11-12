#!/usr/bin/env python3
"""Sign and send an admin command to admin_api.py.
usage: send_admin_command.py <block|unblock> <ip|mac> <value>
       send_admin_command.py defense <on|off>
e.g.:  send_admin_command.py block ip 10.0.0.3
       send_admin_command.py defense off
"""
import os
import sys
import json
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'controller'))
from security import crypto_utils

action = sys.argv[1]
if action == 'defense':
    kind, value = 'defense', sys.argv[2]
else:
    kind, value = sys.argv[2], sys.argv[3]
cmd = crypto_utils.sign_command(action, f'{kind}:{value}')

req = urllib.request.Request(
    'http://127.0.0.1:5050/command',
    data=json.dumps(cmd).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST')
with urllib.request.urlopen(req) as resp:
    print(resp.status, resp.read().decode())
