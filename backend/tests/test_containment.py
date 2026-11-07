import pytest

from app.containment import ATTACKS, BY_ID, judge, kernel_view, run_lab_attack
from app.sandbox import SandboxConfig, SandboxResult


class FakeSandbox:
    cfg = SandboxConfig(runtime="runsc", timeout_s=10)

    def __init__(self, result):
        self.result, self.calls = result, []

    def run(self, argv, stdin=None):
        self.calls.append((list(argv), stdin))
        return self.result


def test_every_attack_script_compiles_and_has_a_verdict_marker():
    for a in ATTACKS:
        compile(a.code, a.id, "exec")
        assert a.id in BY_ID
        if a.expect == "marker":
            assert "BLOCKED" in a.code and "ESCAPED" in a.code
    assert len({a.id for a in ATTACKS}) == len(ATTACKS) == 7


def test_judge_marker_attacks():
    a = BY_ID["net_exfil"]
    assert judge(a, SandboxResult(stdout="BLOCKED: x -> OSError\n"))[0] == "contained"
    assert judge(a, SandboxResult(stdout="ESCAPED: connected to evil.test 80\nBLOCKED: y"))[0] == "escaped"
    assert judge(a, SandboxResult(stdout="", stderr="Traceback...", exit_code=1))[0] == "inconclusive"
    assert judge(a, SandboxResult(stderr="docker not found", exit_code=127, infra_error=True))[0] == "unavailable"


def test_judge_memory_and_timeout():
    m, h = BY_ID["memory_bomb"], BY_ID["cpu_hang"]
    assert judge(m, SandboxResult(stdout="allocated 224 MB\n", exit_code=137))[0] == "contained"
    assert judge(m, SandboxResult(stdout="allocated 1024 MB\nESCAPED: allocated 1 GB", exit_code=0))[0] == "escaped"
    assert judge(m, SandboxResult(stdout="allocated 32 MB\n", exit_code=0))[0] == "inconclusive"
    assert judge(h, SandboxResult(timed_out=True, exit_code=124, duration_s=10.0))[0] == "contained"
    assert judge(h, SandboxResult(exit_code=0))[0] == "inconclusive"


def test_run_sends_code_over_stdin_and_reports_runtime():
    sb = FakeSandbox(SandboxResult(stdout="BLOCKED: ok\n", duration_s=1.2))
    r = run_lab_attack(sb, BY_ID["priv_esc"])
    assert r.status == "contained" and r.runtime == "runsc" and r.timeout_s == 10
    assert sb.calls[0][1] == BY_ID["priv_esc"].code and sb.calls[0][0][:2] == ["python", "-I"]


def test_kernel_view():
    k = kernel_view(FakeSandbox(SandboxResult(stdout="Linux 4.4.0\n[    0.0] Starting gVisor...\n")))
    assert k["runtime"] == "runsc" and "gVisor" in k["output"] and k["available"]


def test_endpoints(tmp_path):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from app.main import Deps, create_app

    sb = FakeSandbox(SandboxResult(stdout="BLOCKED: ok\n"))
    c = TestClient(create_app(Deps(lab_sandbox=lambda: sb, use_default_sandbox=False), str(tmp_path / "t.db"), str(tmp_path)))
    lst = c.get("/containment/attacks").json()
    assert len(lst) == 7 and {"id", "title", "goal", "code"} <= set(lst[0])
    assert c.post("/containment/run/net_exfil").json()["status"] == "contained"
    assert c.post("/containment/run/not_real").status_code == 404
    assert c.post("/containment/run/net_exfil", json={"code": "print(1)"}).status_code == 200  # body ignored: no user code
    assert sb.calls[-1][1] == BY_ID["net_exfil"].code
    assert "output" in c.get("/containment/kernel").json()
