#!/usr/bin/env bash
# Verify the tamper-evident audit log chain.
cd "$(dirname "$0")/.."
source .venv/bin/activate
python3 controller/security/audit_log.py
