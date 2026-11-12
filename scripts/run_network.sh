#!/usr/bin/env bash
# Terminal 3: Mininet network (system python + sudo, NOT the venv)
cd "$(dirname "$0")/.."
sudo python3 topology/topo.py
