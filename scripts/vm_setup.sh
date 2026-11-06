#!/usr/bin/env bash
# One-time setup for a fresh Ubuntu 24.04 Vultr VM. Run as root:  bash scripts/vm_setup.sh
set -euo pipefail

apt-get update && apt-get -y upgrade
apt-get -y install git ufw curl gnupg ca-certificates

# Docker
if ! command -v docker >/dev/null; then curl -fsSL https://get.docker.com | sh; fi

# gVisor (runsc)
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update && apt-get -y install runsc
fi
runsc install
systemctl restart docker

# Firewall: SSH + web only
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "--- gVisor check (expect gVisor kernel messages) ---"
docker run --rm --runtime=runsc alpine dmesg || echo "gVisor test FAILED"
echo "Next: git clone the repo to /opt/patch-loop, cp .env.example .env, fill it, docker compose up -d --build"
