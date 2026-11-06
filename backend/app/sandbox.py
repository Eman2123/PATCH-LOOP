"""Docker/gVisor sandbox for the run_python tool.

Every run_python call gets a brand-new container that is destroyed afterwards.
Hardening (all of it is asserted in tests/test_sandbox.py):
  --network none            no network at all
  --cap-drop ALL            no Linux capabilities
  --security-opt no-new-privileges
  --read-only               root filesystem is read-only (only a small noexec tmpfs on /tmp)
  --memory/--memory-swap    256m, no swap
  --pids-limit, --cpus      fork bombs and CPU hogging are bounded
  --user 65534:65534        nobody, never root
  timeout 20s               container is force-removed on timeout
  no -v / --mount / --env   no host files, no docker.sock, no secrets inside the sandbox
Set SANDBOX_RUNTIME=runsc to run the container under gVisor.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Sequence

Executor = Callable[..., "subprocess.CompletedProcess[str]"]

SANDBOX_ARGV = ["python", "-I", "-"]  # code is piped over stdin, never put in argv or a file


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "patchloop-sandbox:latest"
    runtime: Optional[str] = None  # "runsc" => gVisor
    memory: str = "256m"
    cpus: str = "0.5"
    pids_limit: int = 64
    timeout_s: float = 20.0
    max_output: int = 4000
    tmpfs_size: str = "16m"
    docker_bin: str = "docker"

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "SandboxConfig":
        e = os.environ if env is None else env
        d = cls()
        return cls(
            image=e.get("SANDBOX_IMAGE", d.image),
            runtime=(e.get("SANDBOX_RUNTIME") or None),
            memory=e.get("SANDBOX_MEMORY", d.memory),
            cpus=e.get("SANDBOX_CPUS", d.cpus),
            pids_limit=int(e.get("SANDBOX_PIDS", d.pids_limit)),
            timeout_s=float(e.get("SANDBOX_TIMEOUT_S", d.timeout_s)),
            max_output=int(e.get("SANDBOX_MAX_OUTPUT", d.max_output)),
            docker_bin=e.get("DOCKER_BIN", d.docker_bin),
        )


@dataclass
class SandboxResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    infra_error: bool = False  # docker itself failed (no daemon, missing image/runtime)
    duration_s: float = 0.0
    net_attempts: list[str] = field(default_factory=list)

    @property
    def killed(self) -> bool:
        return self.exit_code == 137  # SIGKILL: OOM killer or forced kill


# ---------- network-attempt detection (dashboard only, never a security control) ----------
_NET_API = re.compile(
    r"\b(socket|urllib|urlopen|requests|httpx|http\.client|aiohttp|ftplib|smtplib|telnetlib|paramiko)\b"
)
_NET_FAIL = re.compile(
    r"Network is unreachable|Name or service not known|Temporary failure in name resolution|"
    r"nodename nor servname|No route to host|Connection refused|gaierror|URLError|"
    r"ConnectionError|MaxRetryError|NameResolutionError|ConnectError",
    re.IGNORECASE,
)
_URL_HOST = re.compile(r"https?://(?:[^/\s'\"@]*@)?([A-Za-z0-9._\-\[\]:]+)", re.IGNORECASE)
_CONNECT_HOST = re.compile(
    r"(?:connect\(\s*\(|gethostbyname\(|create_connection\(\s*\()\s*['\"]([^'\"]+)['\"]"
)


def detect_net_attempts(code: str, stderr: str) -> list[str]:
    """Hosts the code tried to reach. Needs a network API in the code AND a network failure."""
    if not _NET_FAIL.search(stderr or ""):
        return []
    hosts: list[str] = []
    for m in _URL_HOST.finditer(code):
        hosts.append(re.sub(r":\d+$", "", m.group(1)).lower())
    for m in _CONNECT_HOST.finditer(code):
        hosts.append(m.group(1).lower())
    if not hosts and not _NET_API.search(code):
        return []
    seen: list[str] = []
    for h in hosts or ["unknown"]:
        if h not in seen:
            seen.append(h)
    return seen


def _text(x: object) -> str:
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", "replace")
    return str(x)


class DockerSandbox:
    def __init__(self, config: Optional[SandboxConfig] = None, executor: Optional[Executor] = None):
        self.cfg = config or SandboxConfig()
        self._exec: Executor = executor or subprocess.run

    # ---------- command construction ----------
    def build_run_cmd(self, name: str, container_argv: Sequence[str] = SANDBOX_ARGV) -> list[str]:
        c = self.cfg
        cmd = [
            c.docker_bin, "run", "--rm", "-i", "--name", name,
            "--label", "patchloop=sandbox",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={c.tmpfs_size}",
            "--memory", c.memory,
            "--memory-swap", c.memory,
            "--cpus", c.cpus,
            "--pids-limit", str(c.pids_limit),
            "--user", "65534:65534",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
        ]
        if c.runtime:
            cmd += ["--runtime", c.runtime]
        cmd.append(c.image)
        cmd += list(container_argv)
        return cmd

    # ---------- execution ----------
    def run_python(self, code: str) -> SandboxResult:
        res = self.run(SANDBOX_ARGV, stdin=code)
        res.net_attempts = detect_net_attempts(code, res.stderr)
        return res

    def run(self, container_argv: Sequence[str], stdin: Optional[str] = None) -> SandboxResult:
        """Run one command in a fresh container and destroy the container afterwards."""
        c = self.cfg
        name = f"pl-sbx-{uuid.uuid4().hex[:12]}"
        cmd = self.build_run_cmd(name, container_argv)
        t0 = time.monotonic()
        res = SandboxResult()
        try:
            cp = self._exec(cmd, input=stdin, capture_output=True, text=True, timeout=c.timeout_s)
            res.stdout, res.stderr, res.exit_code = _text(cp.stdout), _text(cp.stderr), cp.returncode
            if cp.returncode in (125, 126, 127):  # docker could not start the container
                res.infra_error = True
        except subprocess.TimeoutExpired as e:
            res.timed_out = True
            res.exit_code = 124
            res.stdout = _text(e.stdout)
            res.stderr = _text(e.stderr) + f"\n[sandbox] killed after {c.timeout_s:g}s timeout"
        except FileNotFoundError:
            res.infra_error = True
            res.exit_code = 127
            res.stderr = f"[sandbox] docker binary not found: {c.docker_bin}"
        finally:
            self._destroy(name)
        res.duration_s = round(time.monotonic() - t0, 3)
        res.stdout = res.stdout[: c.max_output]
        res.stderr = res.stderr[: c.max_output]
        return res

    def _destroy(self, name: str) -> None:
        """Belt and braces: --rm removes a finished container, this removes a timed-out one."""
        try:
            self._exec(
                [self.cfg.docker_bin, "rm", "-f", name],
                input=None, capture_output=True, text=True, timeout=15,
            )
        except Exception:
            pass  # a failed cleanup must never crash the loop

    # ---------- health ----------
    def status(self) -> dict:
        """Cheap checks for /health and the deploy checklist."""
        c = self.cfg
        out = {"docker": False, "image": False, "runtime": c.runtime or "runc", "runtime_available": False}
        try:
            info = self._exec(
                [c.docker_bin, "info", "--format", "{{json .Runtimes}}"],
                input=None, capture_output=True, text=True, timeout=10,
            )
            out["docker"] = info.returncode == 0
            runtimes = _text(info.stdout)
            out["runtime_available"] = (c.runtime or "runc") in runtimes if info.returncode == 0 else False
            img = self._exec(
                [c.docker_bin, "image", "inspect", c.image],
                input=None, capture_output=True, text=True, timeout=10,
            )
            out["image"] = img.returncode == 0
        except Exception:
            pass
        return out


def make_python_runner(sandbox: DockerSandbox) -> Callable[[str], dict]:
    """Adapter for SimEnv(python_runner=...): runner(code) -> dict."""

    def runner(code: str) -> dict:
        r = sandbox.run_python(code)
        return {
            "stdout": r.stdout,
            "stderr": r.stderr,
            "exit_code": r.exit_code,
            "net_attempts": r.net_attempts,
        }

    return runner


def default_sandbox() -> DockerSandbox:
    return DockerSandbox(SandboxConfig.from_env())
