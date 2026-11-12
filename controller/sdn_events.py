"""Tiny JSON-lines event bus. The controller (and later the security
modules) write events here; the dashboard and the measurement code read
from this same file."""
import json
import os
import time

LOG = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   '..', 'logs', 'events.jsonl'))
os.makedirs(os.path.dirname(LOG), exist_ok=True)


def reset():
    open(LOG, 'w').close()


def emit(etype, **data):
    rec = {'t': round(time.time(), 3), 'type': etype}
    rec.update(data)
    with open(LOG, 'a') as f:
        f.write(json.dumps(rec) + '\n')
