"""Run the Containment Lab straight against Docker (no API needed):  cd backend; python ../scripts/containment_check.py
Set SANDBOX_RUNTIME=runsc first to test under gVisor. Exit code 1 if anything escaped or the sandbox is unavailable.
"""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.containment import ATTACKS, kernel_view, lab_sandbox, run_lab_attack  # noqa: E402


def main() -> int:
    sb = lab_sandbox()
    print(f"runtime: {sb.cfg.runtime or 'runc'}  image: {sb.cfg.image}  timeout: {sb.cfg.timeout_s:g}s\n")
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(lambda a: run_lab_attack(sb, a), ATTACKS))
    for r in results:
        print(f"[{r.status.upper():12}] {r.title:42} {r.duration_s:>5}s  {r.evidence[:90]!r}")
    print("\n--- kernel view ---")
    print(kernel_view(sb)["output"])
    bad = [r for r in results if r.status in ("escaped", "unavailable")]
    print(f"\n{sum(r.status == 'contained' for r in results)}/{len(results)} contained")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
