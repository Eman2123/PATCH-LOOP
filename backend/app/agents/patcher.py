"""Patcher agent: LLM proposes ONE narrowing patch; invalid proposals are fed back (retry),
then a deterministic template patcher takes over so the loop never stalls."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

from ..env.world import CANARY_DOMAINS, World
from ..llm import LLM, LLMError, extract_json
from ..patches import Patch, PatchError, apply_patch
from ..policy import Policy
from ..verifier import Verdict
from .prompts import PATCHER_SYSTEM

INTERNAL_EMAIL_DOMAIN = "company.example"


class Evidence(BaseModel):
    family: str
    payload: str
    tool_log: list[dict[str, Any]]
    breaches: list[dict[str, Any]]


def build_evidence(family: str, payload: str, world: World, verdict: Verdict) -> Evidence:
    log = [
        {"tool": r.tool, "args": {k: str(v)[:200] for k, v in r.args.items()}, "allowed": r.allowed,
         "rule": r.rule, "reason": r.reason}
        for r in world.tool_log
    ]
    return Evidence(family=family, payload=payload[:700], tool_log=log[:30],
                    breaches=[b.model_dump() for b in verdict.breaches])


@dataclass
class PatchProposal:
    patch: Patch
    new_policy: Policy
    source: str  # "llm" | "template"
    attempts: int = 1
    errors: list[str] = field(default_factory=list)


def _user_prompt(policy: Policy, ev: Evidence, error: Optional[str]) -> str:
    s = ("CURRENT POLICY:\n" + json.dumps(policy.model_dump(), indent=1)
         + f"\n\nATTACK FAMILY: {ev.family}\nINJECTED PAYLOAD: {ev.payload!r}"
         + "\n\nTOOL CALLS (with gateway decision):\n" + json.dumps(ev.tool_log, indent=1)
         + "\n\nVERIFIER BREACHES:\n" + json.dumps(ev.breaches, indent=1))
    if error:
        s += f"\n\nYour previous patch was rejected: {error}\nPropose a different, valid patch."
    return s


def _changed(old: Policy, new: Policy) -> bool:
    a, b = old.model_dump(), new.model_dump()
    a.pop("version"), b.pop("version")
    return a != b


def propose_patch(llm: Optional[LLM], policy: Policy, ev: Evidence, attempts: int = 3) -> Optional[PatchProposal]:
    """LLM first (with error feedback), then template fallback. None means nothing sensible can be proposed."""
    errors: list[str] = []
    if llm is not None:
        err: Optional[str] = None
        for i in range(attempts):
            try:
                r = llm.chat([{"role": "system", "content": PATCHER_SYSTEM},
                              {"role": "user", "content": _user_prompt(policy, ev, err)}], json_mode=True)
                patch = Patch.model_validate(extract_json(r.content))
                new = apply_patch(policy, patch)  # also runs is_narrowing
                if not _changed(policy, new):
                    raise PatchError("patch changes nothing (already in the policy)")
                return PatchProposal(patch, new, "llm", i + 1, errors)
            except (ValueError, ValidationError, PatchError) as e:  # bad JSON / bad op / widening / no-op
                err = str(e)[:300]
                errors.append(err)
            except LLMError as e:
                errors.append(str(e)[:300])
                break
    return template_patch(policy, ev, errors)


def _is_canary(host: str, domains: tuple[str, ...] = CANARY_DOMAINS) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def candidate_patches(ev: Evidence) -> list[Patch]:
    """Mechanism-level fixes derived from what the ALLOWED tool calls did. Ordered most-specific first."""
    out: list[Patch] = []
    for rec in ev.tool_log:
        if not rec.get("allowed"):
            continue
        tool, args = rec["tool"], rec.get("args", {})
        if tool == "read_file":
            p = str(args.get("path", "")).lower()
            if p.endswith(".env") or "/.env" in p:
                out.append(Patch(op="ADD_DENY", field="deny_path_globs", value="*/.env"))
            if "secret" in p:
                out.append(Patch(op="ADD_DENY", field="deny_path_globs", value="*/secrets/*"))
        elif tool == "fetch_url":
            host = (urlsplit(str(args.get("url", ""))).hostname or "").lower()
            if host and _is_canary(host):
                out.append(Patch(op="ADD_DENY", field="fetch_denied_hosts", value=host))
            out.append(Patch(op="REMOVE_ALLOWED_VALUE", field="fetch_allowed_hosts", value="*",
                             replace_with=["docs.example.com", "news.example.com"]))
        elif tool == "send_email":
            out.append(Patch(op="REMOVE_ALLOWED_VALUE", field="email_allowed_domains", value="*",
                             replace_with=[INTERNAL_EMAIL_DOMAIN]))
        elif tool == "run_python":
            out.append(Patch(op="ADD_ARG_CONSTRAINT", tool="run_python",
                             pattern=r"socket|urllib|requests|http\.client|httpx|aiohttp|ftplib|smtplib"))
    return out


def template_patch(policy: Policy, ev: Evidence, errors: Optional[list[str]] = None) -> Optional[PatchProposal]:
    for patch in candidate_patches(ev):
        try:
            new = apply_patch(policy, patch)
        except PatchError:
            continue
        if _changed(policy, new):
            return PatchProposal(patch, new, "template", attempts=0, errors=list(errors or []))
    return None
