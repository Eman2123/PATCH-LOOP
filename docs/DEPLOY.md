# Deploy on a Vultr VM

1. Create Cloud Compute (Ubuntu 24.04, 4 vCPU / 8 GB, no GPU). Firewall: 22 (your IP), 80, 443.
2. `ssh root@VM_IP`, then:
   ```
   git clone https://github.com/Eman2123/PATCH-LOOP.git /opt/patch-loop
   cd /opt/patch-loop && bash scripts/vm_setup.sh
   ```
3. `cp .env.example .env` and set `VULTR_API_KEY`, `MODEL_NAME`, `DOMAIN` (use `<ip-with-dashes>.sslip.io` if you have no domain), `SANDBOX_RUNTIME=runsc`.
4. `docker compose up -d --build`
5. Check: `curl https://$DOMAIN/health` should show `"docker": true, "image": true, "runtime_available": true`.

Security notes: the backend port is never published (only Caddy on 80/443). Sandbox containers get no network, no mounts,
no env and no docker socket. The socket is mounted into the trusted backend only, which starts them.
Continuous deploy: `.github/workflows/deploy.yml` needs repo secrets `VM_HOST`, `VM_USER`, `VM_SSH_KEY`.
