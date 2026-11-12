#!/usr/bin/env bash
# Simulate a controller CRASH (kill -9 the current leader) for the failover demo.
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json, os, signal
l = json.load(open('logs/leader.json'))
print(f"killing leader {l['id']} (pid {l['pid']}, term {l['term']})")
os.kill(l['pid'], signal.SIGKILL)
PY
