"""SimEnv: executes tool calls against a World, always behind the gateway.

Flow for every call: gateway.check_tool_call -> (blocked: no state change) or
(allowed: perform on the simulated world and record side effects).
"""
from __future__ import annotations

from email.utils import parseaddr
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

from pydantic import BaseModel

from ..gateway import check_redirect, check_tool_call, normalize_path
from ..policy import Policy
from ..schemas import Decision
from .world import Outbound, Page, ToolRecord, World

# runner(code) -> {"stdout": str, "stderr": str, "exit_code": int, "net_attempts": [host, ...]}
PythonRunner = Callable[[str], dict]
MAX_OUTPUT = 4000


class ToolResult(BaseModel):
    ok: bool
    output: str
    decision: Decision


class SimEnv:
    def __init__(self, world: World, python_runner: Optional[PythonRunner] = None, max_redirects: int = 3):
        self.world = world
        self.python_runner = python_runner
        self.max_redirects = max_redirects

    # ---------- entry point ----------
    def execute(self, policy: Policy, tool: str, args: dict[str, Any]) -> ToolResult:
        decision = check_tool_call(policy, tool, args)
        self.world.tool_log.append(
            ToolRecord(tool=tool, args=dict(args), allowed=decision.allowed, reason=decision.reason, rule=decision.rule)
        )
        if not decision.allowed:
            return ToolResult(ok=False, output=f"BLOCKED by policy: {decision.reason}", decision=decision)
        handler = getattr(self, f"_do_{tool}", None)
        if handler is None:
            return ToolResult(ok=False, output=f"tool {tool} not implemented", decision=decision)
        try:
            ok, out = handler(policy, args)
        except Exception as e:  # a tool must never crash the loop
            ok, out = False, f"tool error: {type(e).__name__}"
        return ToolResult(ok=ok, output=out[:MAX_OUTPUT], decision=decision)

    # ---------- filesystem ----------
    def _do_list_files(self, policy: Policy, args: dict[str, Any]) -> tuple[bool, str]:
        p = normalize_path(args.get("path", "."), policy.workspace_root)
        if p is None:
            return False, "invalid path"
        prefix = p.rstrip("/") + "/"
        names: set[str] = set()
        for f in self.world.files:
            if f.startswith(prefix):
                rest = f[len(prefix):]
                names.add(rest.split("/")[0] + ("/" if "/" in rest else ""))
        if not names:
            return False, "no such directory"
        return True, "\n".join(sorted(names))

    def _do_read_file(self, policy: Policy, args: dict[str, Any]) -> tuple[bool, str]:
        p = normalize_path(args.get("path"), policy.workspace_root)
        if p is None or p not in self.world.files:
            return False, "no such file"
        return True, self.world.files[p]

    def _do_write_file(self, policy: Policy, args: dict[str, Any]) -> tuple[bool, str]:
        p = normalize_path(args.get("path"), policy.workspace_root)
        content = args.get("content", "")
        if p is None or not isinstance(content, str):
            return False, "invalid write"
        self.world.files[p] = content
        return True, f"wrote {len(content)} bytes to {p}"

    # ---------- simulated web ----------
    def _lookup(self, url: str) -> Optional[Page]:
        base = url.split("#")[0]
        if base in self.world.pages:
            return self.world.pages[base]
        s = urlsplit(base)
        bare = urlunsplit((s.scheme, s.netloc.lower(), s.path, "", ""))
        return self.world.pages.get(bare)

    def _do_fetch_url(self, policy: Policy, args: dict[str, Any]) -> tuple[bool, str]:
        url = args["url"]
        for _ in range(self.max_redirects + 1):
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
            sink = self.world.host_is_canary(host)
            self.world.outbound.append(Outbound(kind="fetch", target=url, payload=url, sink=sink))
            if sink:
                return True, "HTTP 200\nok"  # the attacker's server answers everything
            page = self._lookup(url)
            if page is None:
                return False, "HTTP 404\nnot found"
            if page.redirect_to:
                nxt = urljoin(url, page.redirect_to)
                d = check_redirect(policy, nxt)  # re-validate every hop, never trust
                self.world.tool_log.append(
                    ToolRecord(tool="redirect", args={"to": nxt}, allowed=d.allowed, reason=d.reason, rule=d.rule)
                )
                if not d.allowed:
                    return False, f"BLOCKED redirect: {d.reason}"
                url = nxt
                continue
            return page.status == 200, f"HTTP {page.status}\n{page.body}"
        return False, "too many redirects"

    # ---------- email ----------
    def _do_send_email(self, policy: Policy, args: dict[str, Any]) -> tuple[bool, str]:
        to = str(args.get("to", ""))
        subject = str(args.get("subject", ""))
        body = str(args.get("body", ""))
        addr = parseaddr(to)[1]
        domain = addr.split("@")[-1].lower().rstrip(".")
        sink = self.world.host_is_canary(domain)
        self.world.outbound.append(
            Outbound(kind="email", target=addr, payload=f"{addr}\n{subject}\n{body}", sink=sink)
        )
        return True, f"email queued to {addr}"

    # ---------- sandboxed python ----------
    def _do_run_python(self, policy: Policy, args: dict[str, Any]) -> tuple[bool, str]:
        if self.python_runner is None:
            return False, "sandbox unavailable"
        res = self.python_runner(args["code"])
        for host in res.get("net_attempts", []):
            self.world.contained.append(f"network:{host}")
        out = (res.get("stdout", "") or "") + (res.get("stderr", "") or "")
        return res.get("exit_code", 1) == 0, out
