#!/usr/bin/env bash
# Terminal 4: dashboard -> http://127.0.0.1:5000
cd "$(dirname "$0")/.." && source .venv/bin/activate
python3 controller/dashboard_api.py
