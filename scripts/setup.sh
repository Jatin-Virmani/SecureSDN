#!/usr/bin/env bash
# Run once: bash scripts/setup.sh
# Installs system packages + creates the Python 3.9 venv for Ryu.
set -e

echo "== 1. System packages =="
sudo apt update
sudo apt install -y mininet openvswitch-switch openvswitch-common \
  openssl hping3 nmap tcpdump iperf3 net-tools git build-essential \
  python3-scapy curl
sudo systemctl enable --now openvswitch-switch

echo "== 2. uv (fast Python package manager) =="
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "== 3. Python 3.9 venv for Ryu =="
cd "$(dirname "$0")/.."
uv venv --python 3.9 .venv
# shellcheck disable=SC1091
source .venv/bin/activate
uv pip install "setuptools<66" wheel pbr
uv pip install --no-build-isolation ryu "eventlet==0.30.2"
uv pip install -r requirements.txt

echo
echo "Setup done."
echo "Then: source .venv/bin/activate && ryu-manager --version"
