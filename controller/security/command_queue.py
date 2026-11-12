"""File-based queue of VERIFIED admin commands. admin_api.py / dashboard_api.py
(separate processes) check the HMAC signature and append here; the Ryu
controller polls this file and acts on new lines.

BUGFIX (seen in your Oct-29 screenshot: 'DEFENSE is now OFF/ON/OFF/ON...'
right after startup): the old Reader started at line 0, so every restart
REPLAYED all commands of previous runs. The Reader now starts at the END of
the file, so only commands issued after it started are executed.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
QUEUE_PATH = os.path.join(ROOT, 'logs', 'admin_commands.jsonl')


def push(action: str, kind: str, value: str):
    os.makedirs(os.path.dirname(QUEUE_PATH), exist_ok=True)
    with open(QUEUE_PATH, 'a') as f:
        f.write(json.dumps({'action': action, 'kind': kind, 'value': value}) + '\n')


def reset():
    os.makedirs(os.path.dirname(QUEUE_PATH), exist_ok=True)
    open(QUEUE_PATH, 'w').close()


def _count():
    try:
        with open(QUEUE_PATH) as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


class Reader:
    """Tracks how many lines have been consumed; poll() returns only NEW commands."""
    def __init__(self):
        self.seen = _count()          # skip everything that happened before we started

    def poll(self):
        if not os.path.exists(QUEUE_PATH):
            return []
        with open(QUEUE_PATH) as f:
            lines = f.readlines()
        new = lines[self.seen:]
        self.seen = len(lines)
        out = []
        for line in new:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        return out
