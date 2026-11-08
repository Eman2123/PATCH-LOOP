import json


from app.bench import gate_accepts, run_suite
from app.loop import LoopConfig, LoopRunner
from app.metrics import rate, wilson
from app.patches import Patch, apply_patch
from app.policy import Policy
from tests.fakes import GullibleLLM, IdealLLM


def stub_runner(code):
    return {"stdout": "4460\n", "stderr": "", "exit_code": 0, "net_attempts": ["evil.test"] if "evil.test" in code else []}


def ideal(t):
    return IdealLLM(t)


def hardened() -> Policy:
    p = Policy()
    for patch in [Patch(op="ADD_DENY", field="deny_path_globs", value="*/.env"),
                  Patch(op="ADD_DENY", field="deny_path_globs", value="*/secrets/*"),
                  Patch(op="REMOVE_ALLOWED_VALUE", field="fetch_allowed_hosts", value="*", replace_with=["docs.example.com", "news.example.com"]),
                  Patch(op="REMOVE_ALLOWED_VALUE", field="email_allowed_domains", value="*", replace_with=["company.example"]),
                  Patch(op="ADD_ARG_CONSTRAINT", tool="run_python", pattern="socket|urllib|requests")]:
        p = apply_patch(p, patch)
    return p


def test_wilson_and_rate():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and 0.27 < hi < 0.29
    lo, hi = wilson(5, 10)
    assert 0.23 < lo < 0.24 and 0.76 < hi < 0.77
    assert wilson(0, 0) == (0.0, 1.0)
    assert rate(3, 4)["rate"] == 0.75


def test_gate_rule():
    assert gate_accepts(10, 9) and gate_accepts(10, 10) and not gate_accepts(10, 8)


def test_all_ten_benign_tasks_pass_on_baseline_policy():
    s = run_suite(Policy(), ideal, stub_runner)
    assert s.total == 10 and s.passed == 10 and s.false_blocks == 0


def test_hardened_policy_keeps_full_utility():
    s = run_suite(hardened(), ideal, stub_runner)
    assert s.passed == 10, [t.id for t in s.tasks if not t.ok]


def test_overbroad_policy_fails_the_gate():
    p = apply_patch(Policy(), Patch(op="REMOVE_ALLOWED_VALUE", field="email_allowed_domains", value="*", replace_with=["other.example"]))
    p = apply_patch(p, Patch(op="TIGHTEN_PREFIX", field="read_prefixes", value="/workspace", new_value="/workspace/data"))
    s = run_suite(p, ideal, stub_runner)
    assert s.passed <= 8 and not gate_accepts(10, s.passed)
    assert s.false_blocks > 0


def test_loop_end_to_end_reduces_asr_and_keeps_utility(tmp_path):
    events = []
    r = LoopRunner(GullibleLLM(), python_runner=stub_runner, suite_llm_for=ideal, sink=events.append,
                   results_dir=str(tmp_path))
    state = r.run(LoopConfig(rounds=3, attacks_per_round=3, use_fixed_attacks=True, template_patcher_only=True))
    assert state.status == "done", [e.data for e in r.events if e.type == "done"]
    types = {e.type for e in r.events}
    assert {"round_start", "attack", "tool_call", "verdict", "patch_proposed", "patch_accepted", "metrics", "round_end", "done"} <= types
    assert [e.seq for e in r.events] == list(range(len(r.events))) and len(events) == len(r.events)
    assert state.asr_by_round[0] > 0 and state.asr_by_round[-1] == 0.0
    assert state.policy_version >= 1
    assert all(u >= 0.9 for u in state.utility_by_round)
    last = [e for e in r.events if e.type == "metrics"][-1].data
    assert last["regression"]["failures"] == 0 and last["utility"]["baseline"] == 10
    saved = json.loads((tmp_path / f"{r.loop_id}.json").read_text())
    assert saved["state"]["status"] == "done" and "1" in saved["policies"]


def test_patch_rejected_when_utility_gate_fails():
    from tests.fakes import say

    class Lazy:  # does no work, so every benign task fails once the baseline has been measured
        def chat(self, *a, **k):
            return say("nothing")

    n = {"i": 0}

    def suite_llm(t):
        n["i"] += 1
        return IdealLLM(t) if n["i"] <= 10 else Lazy()

    r = LoopRunner(GullibleLLM(), python_runner=stub_runner, suite_llm_for=suite_llm)
    r.run(LoopConfig(rounds=1, attacks_per_round=3, use_fixed_attacks=True, template_patcher_only=True))
    rej = [e for e in r.events if e.type == "patch_rejected"]
    assert rej and all("utility gate" in e.data["reason"] for e in rej)
    assert not [e for e in r.events if e.type == "patch_accepted"] and r.state.policy_version == 0


def test_loop_failure_is_reported_not_raised():
    class Boom:
        def chat(self, *a, **k):
            raise RuntimeError("kaboom")

    r = LoopRunner(Boom(), suite_llm_for=lambda t: Boom())
    st = r.run(LoopConfig(rounds=1, attacks_per_round=1, use_fixed_attacks=True))
    assert st.status in ("done", "failed")


class DownLLM:
    """Stands in for an unreachable or unauthorised inference endpoint."""
    def chat(self, *a, **k):
        from app.llm import LLMError
        raise LLMError("401 unauthorized")


def test_unreachable_llm_fails_the_run_instead_of_scoring_zero():
    r = LoopRunner(DownLLM(), stub_runner, suite_llm_for=None)
    st = r.run(LoopConfig(rounds=1, attacks_per_round=1, use_fixed_attacks=True))
    assert st.status == "failed"
    done = [e for e in r.events if e.type == "done"][-1]
    assert done.data["status"] == "failed" and "unauthorized" in done.data["error"]


def test_worker_model_is_separate_from_attacker_and_patcher():
    """llm (attacker/patcher) must not be asked to play OfficeBot when a worker model is given."""
    r = LoopRunner(DownLLM(), python_runner=stub_runner, suite_llm_for=None, worker_llm=GullibleLLM())
    st = r.run(LoopConfig(rounds=1, attacks_per_round=3, use_fixed_attacks=True, template_patcher_only=True))
    # DownLLM raises if it is ever called as the worker; GullibleLLM fails the benign tasks it cannot do,
    # but the run must reach the attack stage using the worker model instead of crashing on DownLLM.
    assert any(e.type == "attack" for e in r.events) or st.status == "failed"
    assert "unauthorized" not in " ".join(str(e.data) for e in r.events)
