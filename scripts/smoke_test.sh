#!/usr/bin/env bash
# Quick check that ryu-manager and the venv are healthy.
set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate
echo "ryu-manager:"
ryu-manager --version
echo
echo "key imports:"
python -c "import eventlet, flask, scapy; print('OK')"
