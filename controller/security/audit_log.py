"""Hash-chained audit log: each entry stores the SHA-256 hash of the
previous entry alongside its own data. Editing or deleting any past line
breaks every hash after it, which `verify()` detects. This is the
"tamper-evidence" demo piece - not encryption, just a chain you can check.
"""
import fcntl
import hashlib
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_PATH = os.path.join(ROOT, 'logs', 'audit_chain.jsonl')
GENESIS = '0' * 64


def _hash_entry(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def _last_hash() -> str:
    if not os.path.exists(LOG_PATH):
        return GENESIS
    last = None
    with open(LOG_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return GENESIS
    return json.loads(last)['hash']


def append(event_type: str, **data) -> dict:
    """Append one chained entry. An flock makes this safe when several
    processes (leader controller, dashboard, admin API) write at once."""
    if 'prev' in data or 'hash' in data:
        raise ValueError("'prev' and 'hash' are reserved chain fields")
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH + '.lock', 'w') as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            record = {'t': round(time.time(), 3), 'type': event_type, **data}
            prev = _last_hash()
            h = _hash_entry(prev, record)
            entry = {'prev': prev, 'hash': h, **record}
            with open(LOG_PATH, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            return entry
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


def tail(n=8):
    """Last n entries (for the dashboard)."""
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH) as f:
        lines = [l for l in f.read().splitlines() if l.strip()][-n:]
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except ValueError:
            out.append({'type': 'CORRUPT LINE', 'hash': '', 't': 0})
    return out


def verify() -> dict:
    """Walk the whole chain. Returns {'ok': bool, 'entries': n, 'break_at': i or None}."""
    if not os.path.exists(LOG_PATH):
        return {'ok': True, 'entries': 0, 'break_at': None}
    prev = GENESIS
    n = 0
    with open(LOG_PATH) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                entry = json.loads(line)
            except ValueError:
                return {'ok': False, 'entries': n, 'break_at': i}
            stored_hash = entry.get('hash')
            stored_prev = entry.get('prev')
            if stored_prev != prev:
                return {'ok': False, 'entries': n, 'break_at': i}
            record = {k: v for k, v in entry.items() if k not in ('prev', 'hash')}
            recomputed = _hash_entry(stored_prev, record)
            if recomputed != stored_hash:
                return {'ok': False, 'entries': n, 'break_at': i}
            prev = stored_hash
    return {'ok': True, 'entries': n, 'break_at': None}


def reset():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, 'w').close()


if __name__ == '__main__':
    result = verify()
    print(json.dumps(result, indent=2))
    exit(0 if result['ok'] else 1)
