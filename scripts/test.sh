#!/usr/bin/env bash
# Offline tests for the new features (no Mininet needed)
cd "$(dirname "$0")/.." && source .venv/bin/activate
python -W ignore -m unittest -v tests.test_stage4
