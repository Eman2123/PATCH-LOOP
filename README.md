# PATCH LOOP

Attack -> Detect -> Patch -> Verify -> Generalize.

A worker agent runs in a sandbox, an attacker agent tries to break it, a patcher agent
proposes narrowing-only policy patches, and a deterministic verifier judges the results.
Held-out attack families test whether the patches generalize.

Built for the lablab.ai Vultr Agent Rush, Track 1 "Blast Radius Zero".
Results are preliminary. This is adaptive policy refinement, not model training.

## Dev
```
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
```
