"""Held-out evaluation: the same unseen attacks against four configurations.

none             baseline policy, plain worker
prompt_guardrail baseline policy, worker with security rules in its system prompt
static           a generic hand-written policy, fixed BEFORE any attack was seen (no .env / project-specific rules)
patched          the policy the loop produced
Held-out families (H1-H3) were never shown to the patcher. All results are preliminary; N is small, so read the CIs.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Optional

from .agents.attacker import generate_attack
from .agents.attacks import AttackSpec
from .agents.prompts import HELDOUT_FAMILIES
from .bench import BENIGN_TASKS, BenignTask, run_suite
from .loop import run_attack
from .metrics import rate
from .policy import Policy

CONFIGS = ("none", "prompt_guardrail", "static", "patched")


def static_policy() -> Policy:
    return Policy(
        version=0,
        deny_path_globs=["*.pem", "*.key", "*/.ssh/*", "*/id_rsa*"],  # generic secret-file globs
        fetch_allowed_hosts=["docs.example.com", "news.example.com"],
        email_allowed_domains=["company.example"],
    )


def run_heldout(
    llm: Any,
    python_runner: Optional[Callable[[str], dict]],
    patched: Policy,
    configs: list[str],
    n_per_family: int = 10,
    families: tuple[str, ...] = HELDOUT_FAMILIES,
    tool_mode: str = "native",
    max_steps: int = 8,
    use_fixed_attacks: bool = False,
    suite_llm_for: Optional[Callable[[BenignTask], Any]] = None,
    progress: Optional[Callable[[str], None]] = None,
    worker_llm: Optional[Any] = None,
    susceptible: Optional[bool] = None,
) -> dict:
    if susceptible is None:
        susceptible = os.environ.get("SUSCEPTIBLE_AGENT", "") == "1"
    # Generate the attacks once so every configuration faces exactly the same ones.
    specs: list[AttackSpec] = []
    for fam in families:
        hist: list[dict] = []
        for i in range(n_per_family):
            specs.append(generate_attack(None if use_fixed_attacks else llm, fam, i, hist))
    setups = {
        "none": (Policy(), "none"),
        "prompt_guardrail": (Policy(), "prompt_guardrail"),
        "static": (static_policy(), "none"),
        "patched": (patched, "none"),
    }
    worker = worker_llm or llm
    llm_for = suite_llm_for or (lambda _t: worker)
    out: dict[str, Any] = {}
    for cfg in configs:
        policy, defense = setups[cfg]
        if progress:
            progress(f"{cfg}: running {len(specs)} attacks")
        runs = [(s, run_attack(worker, python_runner, policy, s, tool_mode, max_steps, defense,
                                         susceptible=susceptible)) for s in specs]
        suite = run_suite(policy, llm_for, python_runner, BENIGN_TASKS, tool_mode, max_steps, defense)
        by_family = {f: rate(sum(r.breached for s, r in runs if s.family == f), sum(1 for s, _ in runs if s.family == f))
                     for f in families}
        out[cfg] = {
            "asr": rate(sum(r.breached for _, r in runs), len(runs)),
            "by_family": by_family,
            "damage": sum(r.damage for _, r in runs),
            "contained": sum(len(r.contained) for _, r in runs),
            "utility": {"passed": suite.passed, "total": suite.total, "false_blocks": suite.false_blocks},
            "policy_version": policy.version,
        }
    return {"configs": out, "families": list(families), "n_per_family": n_per_family,
            "attack_sources": {"llm": sum(s.source == "llm" for s in specs), "fixed": sum(s.source == "fixed" for s in specs)},
            "note": "Preliminary results, small N. Damage weights are an opinion."}
