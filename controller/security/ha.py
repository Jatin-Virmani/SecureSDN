"""FEATURE 2 - Controller failover (active/standby high availability).

Two identical controller processes run at once (NODE_ID=c0 and NODE_ID=c1).
Every OpenFlow switch connects to BOTH. Exactly one is the LEADER (OpenFlow
role MASTER); the other is the STANDBY (role SLAVE - it hears nothing and
changes nothing).

Leader election = a lease file (logs/leader.json) guarded by flock:
  - the leader renews the lease every second;
  - the standby checks it every second; if the lease is older than
    LEASE_TIMEOUT seconds (leader crashed / hung) - or was released by a
    clean shutdown - the standby takes it over with term+1.

State that must survive a failover (active blocks, strike counts, defence
mode, how far the admin command queue was read) is written by the leader
every second to logs/shared_state.json and loaded by the new leader. The
drop rules themselves live in the switches, so attackers stay blocked even
during the few seconds with no leader.
"""
import contextlib
import fcntl
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS = os.path.join(ROOT, 'logs')
LEASE = os.path.join(LOGS, 'leader.json')
STATE = os.path.join(LOGS, 'shared_state.json')
LOCK = os.path.join(LOGS, '.leader.lock')
LEASE_TIMEOUT = float(os.environ.get('HA_LEASE', '3'))


def _atomic_write(path, obj):
    tmp = path + '.tmp.' + str(os.getpid())
    with open(tmp, 'w') as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _read(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


@contextlib.contextmanager
def _locked():
    os.makedirs(LOGS, exist_ok=True)
    with open(LOCK, 'w') as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


class Cluster:
    def __init__(self, node_id):
        self.node_id = node_id
        self.is_leader = False
        self.term = 0

    def _lease(self, now):
        return {'id': self.node_id, 'term': self.term, 'ts': now, 'pid': os.getpid()}

    def start(self):
        """Called once at process start. Returns True if this node became the
        leader of a FRESH cluster (nobody else alive) - caller then resets logs."""
        with _locked():
            lease, now = _read(LEASE), time.time()
            if lease is None or now - lease.get('ts', 0) > LEASE_TIMEOUT:
                self.term = (lease or {}).get('term', 0) + 1
                _atomic_write(LEASE, self._lease(now))
                self.is_leader = True
                return True
            self.term = lease['term']
            return False

    def tick(self):
        """Call every second. Returns None, ('took_over', info) or ('stepped_down', info)."""
        with _locked():
            lease, now = _read(LEASE), time.time()
            if self.is_leader:
                if lease and lease.get('id') != self.node_id and lease.get('term', 0) >= self.term:
                    self.is_leader = False
                    self.term = lease['term']
                    return ('stepped_down', {'by': lease['id']})
                _atomic_write(LEASE, self._lease(now))
                return None
            if lease is None or now - lease.get('ts', 0) > LEASE_TIMEOUT:
                prev = (lease or {}).get('id', '?')
                gap = now - (lease or {}).get('ts', now)
                self.term = (lease or {}).get('term', 0) + 1
                _atomic_write(LEASE, self._lease(now))
                self.is_leader = True
                return ('took_over', {'prev': prev, 'gap': gap})
            self.term = lease.get('term', self.term)
            return None

    def release(self):
        """Clean shutdown: hand over immediately instead of waiting for the timeout."""
        if not self.is_leader:
            return
        try:
            with _locked():
                lease = _read(LEASE)
                if lease and lease.get('id') == self.node_id:
                    lease['ts'] = 0
                    _atomic_write(LEASE, lease)
        except Exception:
            pass

    def save_state(self, state):
        state = dict(state, node=self.node_id, term=self.term, ts=time.time())
        _atomic_write(STATE, state)

    def load_state(self):
        return _read(STATE)

    @staticmethod
    def clear_state():
        for p in (STATE,):
            with contextlib.suppress(OSError):
                os.remove(p)
