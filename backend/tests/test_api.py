import json
import time

import pytest

pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from app.evaluation import run_heldout, static_policy  # noqa: E402
from app.main import Deps, create_app  # noqa: E402
from app.policy import Policy  # noqa: E402
from tests.fakes import GullibleLLM, IdealLLM  # noqa: E402
from tests.test_bench_loop import hardened, stub_runner  # noqa: E402


def make_client(tmp_path, **kw):
    deps = Deps(make_llm=lambda: GullibleLLM(), suite_llm_for=lambda t: IdealLLM(t), python_runner=stub_runner,
                use_default_sandbox=False)
    return TestClient(create_app(deps, str(tmp_path / "t.db"), str(tmp_path / "res"), **kw))


def wait(client, path, key="status", done=("done", "failed"), timeout=30):
    t = time.time()
    while time.time() - t < timeout:
        body = client.get(path).json()
        if body[key] in done:
            return body
        time.sleep(0.1)
    raise AssertionError("timeout")


START = {"rounds": 2, "attacks_per_round": 3, "use_fixed_attacks": True, "template_patcher_only": True}


def test_full_api_flow(tmp_path):
    c = make_client(tmp_path)
    r = c.post("/loop/start", json=START)
    assert r.status_code == 200
    lid = r.json()["loop_id"]
    state = wait(c, f"/loop/{lid}")
    assert state["status"] == "done" and state["policy_version"] >= 1 and len(state["asr_by_round"]) == 2

    # SSE replays the full history and then closes
    with c.stream("GET", f"/loop/{lid}/events") as s:
        data = [json.loads(line[6:]) for line in s.iter_lines() if line.startswith("data: ")]
    assert data[0]["seq"] == 0 and data[-1]["type"] == "done" and [d["seq"] for d in data] == list(range(len(data)))
    with c.stream("GET", f"/loop/{lid}/events?from_seq=5") as s:
        assert json.loads([ln for ln in s.iter_lines() if ln.startswith("data: ")][0][6:])["seq"] == 5

    assert c.get(f"/replay/{lid}").json() == data
    p = c.get(f"/policy/{state['policy_version']}", params={"loop_id": lid})
    assert p.status_code == 200 and p.json()["version"] == state["policy_version"]
    assert c.get(f"/policy/{state['policy_version']}").status_code == 200  # latest loop fallback
    assert c.get("/policy/99").status_code == 404
    assert any(x["id"] == lid for x in c.get("/loops").json())

    e = c.post("/eval/heldout", json={"policy_version": state["policy_version"], "n_per_family": 2,
                                      "use_fixed_attacks": True})
    assert e.status_code == 200
    ev = wait(c, f"/eval/{e.json()['eval_id']}")
    assert ev["status"] == "done"
    cfgs = ev["result"]["configs"]
    assert set(cfgs) == {"none", "prompt_guardrail", "static", "patched"}
    assert cfgs["none"]["asr"]["n"] == 6 and cfgs["patched"]["asr"]["rate"] <= cfgs["none"]["asr"]["rate"]
    assert (tmp_path / "res").exists()


def test_unknown_ids_404(tmp_path):
    c = make_client(tmp_path)
    for path in ("/loop/nope", "/loop/nope/events", "/replay/nope", "/eval/nope"):
        assert c.get(path).status_code == 404


def test_validation_and_heldout_families_rejected(tmp_path):
    c = make_client(tmp_path)
    assert c.post("/loop/start", json={"rounds": 99}).status_code == 422
    assert c.post("/loop/start", json={"families": ["H1"]}).status_code == 422  # held-out never used in hardening
    assert c.post("/eval/heldout", json={"policy_version": 0}).status_code == 404  # no loop yet


def test_only_one_job_at_a_time(tmp_path):
    c = make_client(tmp_path)
    c.post("/loop/start", json={**START, "rounds": 3})
    r2 = c.post("/loop/start", json=START)
    assert r2.status_code in (200, 409)  # 409 unless the first already finished
    if r2.status_code == 409:
        assert "busy" in r2.json()["detail"]


def test_missing_llm_is_503(tmp_path):
    def nokey():
        raise RuntimeError("VULTR_API_KEY is not set")

    c = TestClient(create_app(Deps(make_llm=nokey, use_default_sandbox=False), str(tmp_path / "t.db"), str(tmp_path)))
    assert c.post("/loop/start", json=START).status_code == 503


def test_admin_token(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret")
    c = make_client(tmp_path)
    assert c.post("/loop/start", json=START).status_code == 401
    assert c.post("/loop/start", json=START, headers={"X-Admin-Token": "s3cret"}).status_code == 200
    assert c.get("/loops").status_code == 200  # reads stay public


def test_heldout_static_vs_patched_direct():
    res = run_heldout(GullibleLLM(), stub_runner, hardened(), ["none", "static", "patched"], 2,
                      use_fixed_attacks=True, suite_llm_for=lambda t: IdealLLM(t))
    assert res["configs"]["none"]["asr"]["rate"] > res["configs"]["patched"]["asr"]["rate"]
    assert res["configs"]["patched"]["utility"]["passed"] == 10
    assert static_policy().deny_path_globs and Policy().fetch_allowed_hosts == ["*"]
