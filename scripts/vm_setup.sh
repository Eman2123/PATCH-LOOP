#!/usr/bin/env bash
# One-time setup for a fresh Ubuntu 24.04 Vultr VM. Run as root:  bash scripts/vm_setup.sh
set -euo pipefail

apt-get update
# Full upgrade is slow on weak disks and not needed; run with SKIP_UPGRADE=0 to enable it.
[ "${SKIP_UPGRADE:-1}" = "1" ] || apt-get -y upgrade
apt-get -y install git ufw curl gnupg ca-certificates

# Docker
# Ubuntu's own packages first: more reliable than get.docker.com on flaky networks (curl "bad record mac").
if ! command -v docker >/dev/null; then
  apt-get -y install docker.io docker-compose-v2 \
    || { curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && sh /tmp/get-docker.sh; }
fi
systemctl enable --now docker

# gVisor (runsc). Non-fatal: if the download fails, leave SANDBOX_RUNTIME empty in .env (plain hardened Docker).
install_gvisor() {
  if ! command -v runsc >/dev/null; then
    curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
      > /etc/apt/sources.list.d/gvisor.list
    apt-get update && apt-get -y install runsc
  fi
  runsc install
  systemctl restart docker
}
install_gvisor || echo "gVisor install FAILED: set SANDBOX_RUNTIME= (empty) in .env and do not claim gVisor in the demo"

# Firewall: SSH + web only
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "--- gVisor check (expect gVisor kernel messages) ---"
command -v runsc >/dev/null && { docker run --rm --runtime=runsc alpine dmesg || echo "gVisor test FAILED"; }
echo "Next: git clone the repo to /opt/patch-loop, cp .env.example .env, fill it, docker compose up -d --build"
