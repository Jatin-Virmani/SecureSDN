#!/usr/bin/env bash
# Terminal 2: STANDBY controller (takes over automatically if c0 dies).
cd "$(dirname "$0")/.." && source .venv/bin/activate
NODE_ID=c1 exec ryu-manager --ofp-tcp-listen-port 6654 --wsapi-port 8081 controller/secure_controller.py
