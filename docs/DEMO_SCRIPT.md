# 90-second demo script

Record from a **finished run in replay mode** if the live model is slow. Always keep a backup recording.
Say "preliminary" once, clearly. Do not say a number you did not read off the screen.

| Time | On screen | Say |
|---|---|---|
| 0-10 s | Title + one-line diagram | "AI agents read web pages and run code. One poisoned page can leak your secrets. Static allow-lists are either too loose or break the agent. PATCH LOOP lets the agent get attacked, patch its own permissions, and prove the patch didn't break its job." |
| 10-30 s | Round 0 live feed: attack, tool calls, **red canary hit** | "Round 0 runs with a permissive policy. The attacker hides an instruction in a web page. The agent reads `.env` and sends it out. The verdict comes from a deterministic state diff, not from an LLM: the canary sink was hit." |
| 30-55 s | Patch card (diff) + utility gate | "The patcher proposes a patch. It can only narrow permissions. We re-run the same attack, then run ten benign office tasks. A patch is accepted only if the agent loses at most one task. Here it was accepted / rejected because..." |
| 55-75 s | Dual chart: ASR down, utility flat | "Across four rounds, attack success rate falls while utility stays within one task of baseline. We show both, because blocking everything would also give zero attacks." |
| 75-90 s | Held-out panel, then business value | "Held-out attack families the patcher never saw: encoded exfiltration, multi-step chains, argument smuggling. Here is how four configurations did, with confidence intervals. Results are preliminary and the world is simulated. For teams shipping agents, every attack becomes a small, reviewable policy diff with a measured cost." |

## Containment moment (required, 10-15 s, put it inside or right after the 55-75 s slot)

Open **Containment Lab**, click **Network exfiltration** and **Memory bomb**. Show:
- status `contained`, evidence line, and the gVisor kernel log from `/containment/kernel`
- "Real attacks, run inside a gVisor sandbox with no network, no capabilities and a 256 MB limit. The memory bomb was killed; the network call never left."

If the held-out result is **not** better than the baseline, say so: "the patches overfit the training families." That is
a finding, not a failure, and it is more credible than a polished claim.

## Before recording

- [ ] `GET /health` shows docker, image and runtime available
- [ ] one complete run saved in `results/` and visible via `/replay/{id}`
- [ ] held-out eval finished for the same policy version
- [ ] browser zoom 110-125%, dark mode off or on consistently, notifications silenced
- [ ] video under 5 minutes (target 60-90 s), no API key or token visible on screen or in the terminal
