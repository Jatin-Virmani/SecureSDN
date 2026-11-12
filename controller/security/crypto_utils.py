"""HMAC-signed admin commands (block/unblock a host), with a timestamp
and nonce so a captured command can't be replayed later.

This does NOT replace OpenFlow/TLS - it protects a separate small HTTP
API (controller/admin_api.py) that an operator or the dashboard uses to
force-block or unblock a host. Without this, anyone who can reach that
API could block/unblock hosts at will.
"""
import hashlib
import hmac
import json
import os
import secrets
import time

KEY_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), 'certs', 'admin_hmac.key')
MAX_SKEW = 30          # seconds a command's timestamp may differ from "now"
_seen_nonces = {}      # nonce -> expiry time, prevents replay


def load_or_create_key():
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, 'rb') as f:
            return f.read()
    key = secrets.token_bytes(32)
    with open(KEY_PATH, 'wb') as f:
        f.write(key)
    os.chmod(KEY_PATH, 0o600)
    return key


_KEY = load_or_create_key()


def _canonical(payload: dict) -> bytes:
    # sort_keys makes the signature independent of dict ordering
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()


def sign_command(action: str, target: str) -> dict:
    """Build a signed command envelope. `action`: 'block' or 'unblock'."""
    payload = {'action': action, 'target': target,
               'ts': time.time(), 'nonce': secrets.token_hex(8)}
    mac = hmac.new(_KEY, _canonical(payload), hashlib.sha256).hexdigest()
    payload['mac'] = mac
    return payload


def verify_command(payload: dict) -> (bool, str):
    """Returns (ok, reason). Checks signature, freshness, and replay."""
    payload = dict(payload)
    mac = payload.pop('mac', None)
    if not mac:
        return False, 'missing mac'
    expected = hmac.new(_KEY, _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return False, 'bad signature'

    now = time.time()
    ts = payload.get('ts')
    if ts is None or abs(now - ts) > MAX_SKEW:
        return False, 'stale or future timestamp'

    nonce = payload.get('nonce')
    if not nonce:
        return False, 'missing nonce'
    _prune_nonces(now)
    if nonce in _seen_nonces:
        return False, 'replay detected'
    _seen_nonces[nonce] = now + MAX_SKEW * 2
    return True, 'ok'


def _prune_nonces(now):
    for n, exp in list(_seen_nonces.items()):
        if exp < now:
            del _seen_nonces[n]
