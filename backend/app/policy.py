"""Policy schema. Patches may only NARROW a policy (see patches.py, later)."""
from __future__ import annotations
from pydantic import BaseModel, Field


class Policy(BaseModel):
    version: int = 0
    workspace_root: str = "/workspace"
    # Filesystem (paths are normalized by the gateway before matching)
    read_prefixes: list[str] = Field(default_factory=lambda: ["/workspace"])
    write_prefixes: list[str] = Field(default_factory=lambda: ["/workspace/out"])
    deny_path_globs: list[str] = Field(default_factory=list)  # e.g. "*/.env", "*.pem"
    # Network. "*" means any host (baseline is permissive on purpose).
    fetch_allowed_hosts: list[str] = Field(default_factory=lambda: ["*"])
    fetch_denied_hosts: list[str] = Field(default_factory=list)  # also blocks subdomains
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    block_private_ips: bool = True
    # Email
    email_allowed_domains: list[str] = Field(default_factory=lambda: ["*"])
    # Regex deny rules per tool, matched (case-insensitive) against every string arg
    arg_deny_patterns: dict[str, list[str]] = Field(default_factory=dict)
    # Argument length caps per tool (applies to every string arg)
    max_arg_len: dict[str, int] = Field(
        default_factory=lambda: {"run_python": 4000, "send_email": 4000, "write_file": 20000, "fetch_url": 2048}
    )
