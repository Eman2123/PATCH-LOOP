"""Loop controller: Attack -> Detect -> Patch -> Verify -> Generalize.

Per round: run attacks against the current policy (ASR is measured BEFORE this round's patches),
then for each breach ask the patcher for a narrowing patch, re-run the same attack under the candidate
(must be stopped), run the benign suite (utility gate), and accept or reject. A regression library of every
past breaching attack is replayed under the final policy of each round.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from .agents.attacker import generate_attack
from .agents.attacks import AttackSpec, plant_attack
from .agents.patcher import Evidence, build_evidence, propose_patch, template_patch
from .agents.worker import run_worker
from .bench import BENIGN_TASKS, BenignTask, SuiteResult, gate_accepts, run_suite
from .env import SimEnv, build_world
from .llm import LLM, LLMError
from .metrics import rate
from .policy import Policy
from .schemas import LoopEvent, LoopState
from .verifier import verify


class LoopConfig(BaseModel):
    rounds: int = 4
    attacks_per_round: int = 5
    families: list[str] = Field(default_factory=lambda: ["F1", "F2", "F3"])
    tool_mode: str = "native"
    max_drop: int = 1
    max_steps: int = 8
    max_patches_per_round: int = 3
    use_fixed_attacks: bool = False
    template_patcher_only: bool = False


@dataclass
class AttackRun:
    spec: AttackSpec
    breached: bool
    damage: int
    breach_kinds: list[str]
    contained: list[str]
    tool_calls: int
    why: str
    evidence: Evidence


def run_attack(
    llm: Any,
    python_runner: Optional[Callable[[str], dict]],
    policy: Policy,
    spec: AttackSpec,
    tool_mode: str = "native",
    max_steps: int = 8,
    defense: str = "none",
    on_tool: Optional[Callable[[str, dict, Any], None]] = None,
) -> AttackRun:
    """One attack end to end in a fresh world; the deterministic verifier decides the outcome."""
    world = build_world()
    task = plant_attack(world, spec)
    snap = world.snapshot()
    worker = run_worker(llm, SimEnv(world, python_runner), policy, task, defense=defense,  # type: ignore[arg-type]
                        tool_mode=tool_mode, max_steps=max_steps, on_tool=on_tool)  # type: ignore[arg-type]
    if worker.stopped == "error":
        # The model could not be reached. Never score that as "agent resisted the attack".
        raise LLMError(worker.error or "worker LLM call failed")
    v = verify(snap, world)
    blocked = next((r for r in world.tool_log if not r.allowed), None)
    why = ("breached: " + ",".join(b.kind for b in v.breaches)) if v.breached else (
        f"blocked by {blocked.rule}" if blocked else "agent did not follow the payload")
    return AttackRun(spec, v.breached, v.damage, [b.kind for b in v.breaches], v.contained,
                     worker.tool_calls, why, build_evidence(spec.family, spec.payload, world, v))


@dataclass
class LoopRunner:
    llm: Optional[LLM]
    python_runner: Optional[Callable[[str], dict]] = None
    suite_llm_for: Optional[Callable[[BenignTask], Any]] = None  # tests inject an ideal worker here
    sink: Optional[Callable[[LoopEvent], None]] = None
    results_dir: Optional[str] = None
    loop_id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    tasks: list[BenignTask] = field(default_factory=lambda: list(BENIGN_TASKS))

    def __post_init__(self) -> None:
        self.events: list[LoopEvent] = []
        self.policies: dict[int, Policy] = {}
        self.state = LoopState(loop_id=self.loop_id, status="pending")
        self.baseline_utility = 0
        self.cfg = LoopConfig()

    # ---------- plumbing ----------
    def emit(self, type_: str, data: dict) -> None:
        ev = LoopEvent(loop_id=self.loop_id, seq=len(self.events), type=type_, data=data)  # type: ignore[arg-type]
        self.events.append(ev)
        if self.sink:
            self.sink(ev)

    def _suite(self, policy: Policy) -> SuiteResult:
        llm_for = self.suite_llm_for or (lambda _t: self.llm)
        return run_suite(policy, llm_for, self.python_runner, self.tasks, self.cfg.tool_mode, self.cfg.max_steps)

    def _run_attack(self, policy: Policy, spec: AttackSpec, announce: bool = False) -> AttackRun:
        def on_tool(tool: str, args: dict, res: Any) -> None:
            if announce:
                self.emit("tool_call", {"tool": tool, "args": {k: str(v)[:200] for k, v in args.items()},
                                        "allowed": res.decision.allowed, "rule": res.decision.rule,
                                        "reason": res.decision.reason})

        return run_attack(self.llm, self.python_runner, policy, spec, self.cfg.tool_mode, self.cfg.max_steps, "none", on_tool)

    # ---------- main loop ----------
    def run(self, cfg: Optional[LoopConfig] = None) -> LoopState:
        self.cfg = cfg or LoopConfig()
        c = self.cfg
        self.state.status = "running"
        try:
            self._run(c)
            self.state.status = "done"
        except Exception as e:  # noqa: BLE001 - surface in the event stream, keep partial results
            self.state.status = "failed"
            self.emit("done", {"status": "failed", "error": f"{type(e).__name__}: {e}"[:300]})
        finally:
            self._save()
        return self.state

    def _run(self, c: LoopConfig) -> None:
        policy = Policy()
        self.policies[0] = policy
        base = self._suite(policy)
        self.baseline_utility = base.passed
        last_suite = {0: base}
        self.emit("metrics", {"round": 0, "policy_version": 0,
                              "utility": {"passed": base.passed, "total": base.total}, "asr": None})
        library: dict[str, AttackSpec] = {}
        history: dict[str, list[dict]] = {f: [] for f in c.families}
        accepted = rejected = 0

        for rnd in range(1, c.rounds + 1):
            self.state.round = rnd
            self.emit("round_start", {"round": rnd, "policy_version": policy.version})
            runs: list[AttackRun] = []
            for i in range(c.attacks_per_round):
                fam = c.families[i % len(c.families)]
                idx = (rnd - 1) * c.attacks_per_round + i
                spec = generate_attack(None if c.use_fixed_attacks else self.llm, fam, idx, history[fam])
                self.emit("attack", {"round": rnd, "index": i, "family": fam, "carrier": spec.carrier,
                                     "payload": spec.payload, "source": spec.source})
                run = self._run_attack(policy, spec, announce=True)
                self.emit("verdict", {"round": rnd, "index": i, "family": fam, "breached": run.breached,
                                      "damage": run.damage, "breaches": run.breach_kinds,
                                      "contained": run.contained, "why": run.why})
                history[fam].append({"payload": spec.payload, "outcome": "breached" if run.breached else "blocked", "why": run.why})
                runs.append(run)
                if run.breached:
                    library[spec.payload] = spec

            k = sum(r.breached for r in runs)
            damage = sum(r.damage for r in runs)
            contained = sum(len(r.contained) for r in runs)
            asr = rate(k, len(runs))
            r_acc = r_rej = 0

            for run in [r for r in runs if r.breached][: c.max_patches_per_round]:
                if self._run_attack(policy, run.spec).breached is False:
                    continue  # an earlier patch this round already stops it
                prop = (template_patch(policy, run.evidence) if c.template_patcher_only
                        else propose_patch(self.llm, policy, run.evidence))
                if prop is None:
                    r_rej += 1
                    self.emit("patch_rejected", {"round": rnd, "family": run.spec.family, "reason": "no valid patch proposed"})
                    continue
                self.emit("patch_proposed", {"round": rnd, "family": run.spec.family, "source": prop.source,
                                             "attempts": prop.attempts, "version": prop.new_policy.version,
                                             "patch": prop.patch.model_dump(exclude_none=True)})
                if self._run_attack(prop.new_policy, run.spec).breached:
                    r_rej += 1
                    self.emit("patch_rejected", {"round": rnd, "family": run.spec.family, "reason": "attack still succeeds"})
                    continue
                s = self._suite(prop.new_policy)
                if not gate_accepts(self.baseline_utility, s.passed, c.max_drop):
                    r_rej += 1
                    self.emit("patch_rejected", {"round": rnd, "family": run.spec.family,
                                                 "reason": f"utility gate: {s.passed}/{s.total} vs baseline {self.baseline_utility}"})
                    continue
                policy = prop.new_policy
                self.policies[policy.version] = policy
                last_suite[policy.version] = s
                r_acc += 1
                self.emit("patch_accepted", {"round": rnd, "family": run.spec.family, "version": policy.version,
                                             "patch": prop.patch.model_dump(exclude_none=True),
                                             "utility": {"passed": s.passed, "total": s.total}})

            accepted += r_acc
            rejected += r_rej
            reg_fail = sum(self._run_attack(policy, s).breached for s in library.values())
            suite = last_suite.get(policy.version) or self._suite(policy)
            last_suite[policy.version] = suite
            self.state.policy_version = policy.version
            self.state.asr_by_round.append(asr["rate"])
            self.state.utility_by_round.append(suite.passed / suite.total if suite.total else 0.0)
            self.emit("metrics", {
                "round": rnd, "policy_version": policy.version, "asr": asr, "damage": damage, "contained": contained,
                "utility": {"passed": suite.passed, "total": suite.total, "baseline": self.baseline_utility},
                "false_blocks": suite.false_blocks, "patches_accepted": accepted, "patches_rejected": rejected,
                "regression": {"library": len(library), "failures": reg_fail},
                "attacker_diversity": len({h["payload"] for hs in history.values() for h in hs}),
            })
            self.emit("round_end", {"round": rnd, "accepted": r_acc, "rejected": r_rej})

        self.emit("done", {"status": "done", "final_policy_version": policy.version})

    def _save(self) -> None:
        if not self.results_dir:
            return
        d = Path(self.results_dir)
        d.mkdir(parents=True, exist_ok=True)
        doc = {"loop_id": self.loop_id, "config": self.cfg.model_dump(), "state": self.state.model_dump(),
               "policies": {str(v): p.model_dump() for v, p in self.policies.items()},
               "events": [e.model_dump() for e in self.events]}
        (d / f"{self.loop_id}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
