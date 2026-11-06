"""Every tool call goes through check_tool_call(). Deterministic, no LLM."""
from __future__ import annotations
import fnmatch
import ipaddress
import posixpath
from email.utils import parseaddr
from typing import Any, Optional
from urllib.parse import urlsplit

from .policy import Policy
from .schemas import Decision


def _deny(reason: str, rule: str) -> Decision:
    return Decision(allowed=False, reason=reason, rule=rule)


def _ok(rule: str = "allow") -> Decision:
    return Decision(allowed=True, reason="ok", rule=rule)


# ---------- paths ----------
def normalize_path(raw: Any, root: str = "/workspace") -> Optional[str]:
    """Return a canonical absolute path inside root, or None if invalid/escaping."""
    if not isinstance(raw, str) or not raw or "\x00" in raw or "%" in raw:
        return None
    p = raw.replace("\\", "/")
    if not p.startswith("/"):
        p = posixpath.join(root, p)
    p = posixpath.normpath(p)
    if p.startswith("//"):  # normpath keeps a leading double slash
        p = "/" + p.lstrip("/")
    root = root.rstrip("/")
    if p != root and not p.startswith(root + "/"):
        return None
    return p


def _under(path: str, prefixes: list[str]) -> bool:
    return any(path == pre.rstrip("/") or path.startswith(pre.rstrip("/") + "/") for pre in prefixes)


def _path_denied(path: str, globs: list[str]) -> Optional[str]:
    base = posixpath.basename(path)
    for g in globs:
        if fnmatch.fnmatch(path, g) or fnmatch.fnmatch(base, g):
            return g
    return None


def _check_path(policy: Policy, raw: Any, prefixes: list[str], mode: str) -> Decision:
    p = normalize_path(raw, policy.workspace_root)
    if p is None:
        return _deny(f"invalid or escaping path: {raw!r}", f"{mode}.path_invalid")
    g = _path_denied(p, policy.deny_path_globs)
    if g:
        return _deny(f"path matches denied glob {g}", f"{mode}.deny_glob:{g}")
    if not _under(p, prefixes):
        return _deny(f"{p} not under allowed {mode} prefixes", f"{mode}.prefix")
    return _ok()


# ---------- urls ----------
def _host_matches(host: str, patterns: list[str], include_subdomains: bool) -> bool:
    for pat in patterns:
        if pat == "*":
            return True
        if host == pat or (include_subdomains and host.endswith("." + pat)):
            return True
    return False


def check_url(policy: Policy, raw: Any) -> Decision:
    if not isinstance(raw, str) or not raw.strip() or raw != raw.strip():
        return _deny("empty or malformed url", "url.malformed")
    if any(c in raw for c in "\x00\r\n\t\\ "):
        return _deny("illegal characters in url", "url.malformed")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return _deny("unparseable url", "url.malformed")
    if parts.scheme not in ("http", "https"):
        return _deny(f"scheme {parts.scheme!r} not allowed", "url.scheme")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return _deny("userinfo in url is not allowed", "url.userinfo")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or not host.isascii():
        return _deny("missing or non-ascii host", "url.host")
    if port is not None and port not in policy.allowed_ports:
        return _deny(f"port {port} not allowed", "url.port")
    try:
        ip = ipaddress.ip_address(host)
        if policy.block_private_ips and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
            return _deny("private/loopback ip not allowed", "url.private_ip")
    except ValueError:
        pass
    if _host_matches(host, policy.fetch_denied_hosts, include_subdomains=True):
        return _deny(f"host {host} is denied", f"url.denied_host:{host}")
    if not _host_matches(host, policy.fetch_allowed_hosts, include_subdomains=False):
        return _deny(f"host {host} not in allowlist", "url.allowlist")
    return _ok()


def check_redirect(policy: Policy, location: str) -> Decision:
    """The simulated web must call this on every redirect hop (re-validate, never trust)."""
    return check_url(policy, location)


# ---------- email ----------
def check_email(policy: Policy, to: Any) -> Decision:
    if not isinstance(to, str) or any(c in to for c in ",;\r\n"):
        return _deny("exactly one plain recipient required", "email.recipient")
    addr = parseaddr(to)[1]
    if addr.count("@") != 1:
        return _deny("invalid recipient address", "email.recipient")
    domain = addr.split("@")[1].lower().rstrip(".")
    allowed = policy.email_allowed_domains
    if "*" not in allowed and domain not in allowed:
        return _deny(f"recipient domain {domain} not allowed", "email.domain")
    return _ok()


# ---------- entry point ----------
def check_tool_call(policy: Policy, tool: str, args: dict[str, Any]) -> Decision:
    cap = policy.max_arg_len.get(tool)
    if cap is not None:
        for k, v in args.items():
            if isinstance(v, str) and len(v) > cap:
                return _deny(f"arg {k} longer than {cap}", f"{tool}.max_len")
    if tool == "list_files":
        return _check_path(policy, args.get("path", "."), policy.read_prefixes, "read")
    if tool == "read_file":
        return _check_path(policy, args.get("path"), policy.read_prefixes, "read")
    if tool == "write_file":
        return _check_path(policy, args.get("path"), policy.write_prefixes, "write")
    if tool == "fetch_url":
        return check_url(policy, args.get("url"))
    if tool == "send_email":
        return check_email(policy, args.get("to"))
    if tool == "run_python":
        if not isinstance(args.get("code"), str):
            return _deny("code must be a string", "run_python.args")
        return _ok()  # real containment happens in the sandbox (network none)
    return _deny(f"unknown tool {tool}", "tool.unknown")
