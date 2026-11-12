#!/usr/bin/env bash
# Terminal 1: PRIMARY controller (start this FIRST). Optional: DEFENSE=off
cd "$(dirname "$0")/.." && source .venv/bin/activate
NODE_ID=c0 exec ryu-manager --ofp-tcp-listen-port 6653 controller/secure_controller.py
