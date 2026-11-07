# Submission checklist (lablab.ai, Vultr Agent Rush, Track 1)

The deadline was not confirmed on the event page. Internal target: **7 Nov 19:00 PKT**.

## Required deliverables
- [ ] Public GitHub repo, MIT license, README (done: `README.md`, `LICENSE`)
- [ ] Backend deployed on a **Vultr Cloud Compute** VM
- [ ] **Vultr Serverless Inference** used by the agents (`MODEL_NAME` chosen with `scripts/model_test.py`)
- [ ] Isolated sandbox (Docker + gVisor `runsc`), shown working in `/health` and the Containment Lab
- [ ] Public demo URL (HTTPS via Caddy; `<ip-with-dashes>.sslip.io` if there is no domain)
- [ ] Demo video under 5 minutes with one containment moment (`docs/DEMO_SCRIPT.md`)
- [ ] Architecture explanation (`docs/ARCHITECTURE.md`; paste the diagram into the submission)
- [ ] Submitted on lablab.ai, then re-opened from a logged-out browser to verify

## Before submitting
- [ ] One full loop (4 rounds x 5 attacks) and one held-out eval saved in `results/`
- [ ] README says "preliminary", lists limits, and contains no number that is not in `results/`
- [ ] `git log` and the repo contain no key or token (search for `github_pat`, `sk-`, `VULTR_API_KEY=`)
- [ ] Any token pasted into chat or a terminal has been **revoked** (GitHub, Vultr)
- [ ] `ADMIN_TOKEN` set on the VM so strangers cannot start expensive loops from the public URL
- [ ] CI is green on `main`; the deploy workflow secrets (`VM_HOST`, `VM_USER`, `VM_SSH_KEY`) are set or the workflow is disabled
- [ ] Demo works from a phone on mobile data (not only your own network)

## If something breaks
| Problem | Fallback |
|---|---|
| Model slow or rate-limited | smaller N, temperature 0, cache; use `/replay/{id}` for the demo |
| Attacker too weak | `use_fixed_attacks` (fixed payloads) |
| Patcher returns bad JSON | retries, then `template_patcher_only` |
| gVisor not available on the VM | run with plain Docker hardening, say so in the video, do not claim gVisor |
| Live demo flaky | pre-recorded video as the primary deliverable |
