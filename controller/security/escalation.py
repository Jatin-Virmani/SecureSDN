"""FEATURE 1 - Graduated (escalating) blocking.

A first-time offender gets a short ban. Each repeat offence climbs a ladder:

    strike 1 ->  30 s
    strike 2 ->  60 s
    strike 3 -> 120 s
    strike 4 -> 300 s
    strike 5 -> 600 s
    strike 6+ -> QUARANTINE (no expiry - only an admin can unblock)

Strikes are remembered per OFFENDER IDENTITY, not per attack type: if h3 does
a syn_flood and later a port_scan, it is still the same host and keeps
climbing the ladder (the controller maps an IP back to its trusted MAC).

Strikes are forgotten after FORGET_AFTER seconds of good behaviour counted
from the moment the last ban ends, so one old mistake is not held against a
host forever. Override via env vars:
    BLOCK_LADDER="30,60,120,300,600"   STRIKE_MEMORY=300
"""
import os
import time

LADDER = [int(x) for x in os.environ.get('BLOCK_LADDER', '30,60,120,300,600').split(',')
          if x.strip()]
FORGET_AFTER = float(os.environ.get('STRIKE_MEMORY', '300'))


def duration_for(strike):
    """Ban length in seconds for the Nth strike (1-based); None = quarantine."""
    return LADDER[strike - 1] if 1 <= strike <= len(LADDER) else None


def label(seconds):
    if seconds is None:
        return 'QUARANTINE'
    return f'{seconds // 60}m' if seconds >= 60 and seconds % 60 == 0 else f'{seconds}s'


class Escalator:
    def __init__(self):
        self.offenders = {}    # identity -> {strikes,last_attack,last,clear_at}

    def _live(self, ident, now):
        e = self.offenders.get(ident)
        if e and e['clear_at'] is not None and now > e['clear_at']:
            del self.offenders[ident]          # good behaviour long enough: forgiven
            return None
        return e

    def strikes(self, ident):
        e = self._live(ident, time.time())
        return e['strikes'] if e else 0

    def next_duration(self, ident):
        return duration_for(self.strikes(ident) + 1)

    def record(self, ident, attack):
        """Register a new offence. Returns (strike_number, ban_seconds|None)."""
        now = time.time()
        e = self._live(ident, now)
        n = (e['strikes'] if e else 0) + 1
        d = duration_for(n)
        clear_at = None if d is None else now + d + FORGET_AFTER
        self.offenders[ident] = {'strikes': n, 'last_attack': attack,
                                 'last': now, 'clear_at': clear_at}
        return n, d

    def on_unblock(self, ident):
        """Admin lifted a ban: a quarantined host starts its forgiveness clock."""
        e = self.offenders.get(ident)
        if e and e['clear_at'] is None:
            e['clear_at'] = time.time() + FORGET_AFTER

    def export(self):
        return dict(self.offenders)

    def load(self, data):
        self.offenders = {k: dict(v) for k, v in (data or {}).items()}
