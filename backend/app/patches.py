"""Narrowing-only policy patches. A patch can only make the policy stricter.

Two layers: apply_patch() builds the new policy, then is_narrowing() independently
re-checks old -> new (defense in depth, so a bug in one patch type cannot widen the policy).
"""
from __future__ import annotations
import re
from typing import Literal, Optional, Union

from pydantic import BaseModel

from .gateway import normalize_path
from .policy import Policy

PatchOp = Literal["ADD_DENY", "REMOVE_ALLOWED_VALUE", "TIGHTEN_PREFIX", "ADD_ARG_CONSTRAINT", "CAP_ARG_LENGTH"]

DENY_FIELDS = {"deny_path_globs", "fetch_denied_hosts"}
ALLOW_FIELDS = {"read_prefixes", "write_prefixes", "fetch_allowed_hosts", "email_allowed_domains", "allowed_ports"}
PREFIX_FIELDS = {"read_prefixes", "write_prefixes"}
TOOLS = {"list_files", "read_file", "write_file", "fetch_url", "send_email", "run_python"}
MAX_PATTERN_LEN = 200


class PatchError(ValueError):
    pass


class Patch(BaseModel):
    """Flat shape so the LLM patcher can emit it as plain JSON."""
    op: PatchOp
    field: Optional[str] = None          # ADD_DENY, REMOVE_ALLOWED_VALUE, TIGHTEN_PREFIX
    value: Optional[Union[str, int]] = None
    new_value: Optional[str] = None      # TIGHTEN_PREFIX: the narrower prefix
    replace_with: Optional[list[str]] = None  # REMOVE_ALLOWED_VALUE on "*": concrete replacements
    tool: Optional[str] = None           # ADD_ARG_CONSTRAINT, CAP_ARG_LENGTH
    pattern: Optional[str] = None        # ADD_ARG_CONSTRAINT: regex to deny
    max_len: Optional[int] = None        # CAP_ARG_LENGTH


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise PatchError(msg)


def _under(child: str, parent: str) -> bool:
    parent = parent.rstrip("/")
    return child.startswith(parent + "/")


def apply_patch(policy: Policy, patch: Patch) -> Policy:
    new = policy.model_copy(deep=True)
    op = patch.op

    if op == "ADD_DENY":
        _need(patch.field in DENY_FIELDS, f"ADD_DENY field must be one of {sorted(DENY_FIELDS)}")
        _need(isinstance(patch.value, str) and patch.value.strip() != "", "ADD_DENY needs a string value")
        val = patch.value.strip()
        if patch.field == "fetch_denied_hosts":
            val = val.lower().rstrip(".")
            _need("*" not in val and "/" not in val and "@" not in val, "invalid host")
        lst = getattr(new, patch.field)
        if val not in lst:
            lst.append(val)

    elif op == "REMOVE_ALLOWED_VALUE":
        _need(patch.field in ALLOW_FIELDS, f"REMOVE_ALLOWED_VALUE field must be one of {sorted(ALLOW_FIELDS)}")
        lst = getattr(new, patch.field)
        want = int(patch.value) if patch.field == "allowed_ports" else patch.value
        _need(want in lst, f"{want!r} not present in {patch.field}")
        lst.remove(want)
        if patch.replace_with:
            _need(want == "*" and patch.field in {"fetch_allowed_hosts", "email_allowed_domains"},
                  "replace_with only valid when removing '*' from a host/domain list")
            for r in patch.replace_with:
                _need(isinstance(r, str) and r.strip() and "*" not in r, "replace_with must be concrete values")
                r = r.strip().lower().rstrip(".")
                if r not in lst:
                    lst.append(r)

    elif op == "TIGHTEN_PREFIX":
        _need(patch.field in PREFIX_FIELDS, f"TIGHTEN_PREFIX field must be one of {sorted(PREFIX_FIELDS)}")
        old = normalize_path(patch.value, policy.workspace_root)
        nw = normalize_path(patch.new_value, policy.workspace_root)
        _need(old is not None and nw is not None, "invalid prefix")
        lst = getattr(new, patch.field)
        _need(old in [p.rstrip("/") for p in lst], f"{old} not in {patch.field}")
        _need(_under(nw, old), "new prefix must be strictly inside the old prefix")
        lst[:] = [nw if p.rstrip("/") == old else p for p in lst]

    elif op == "ADD_ARG_CONSTRAINT":
        _need(patch.tool in TOOLS, "unknown tool")
        _need(isinstance(patch.pattern, str) and 0 < len(patch.pattern) <= MAX_PATTERN_LEN, "bad pattern length")
        try:
            re.compile(patch.pattern)
        except re.error as e:
            raise PatchError(f"invalid regex: {e}")
        lst = new.arg_deny_patterns.setdefault(patch.tool, [])
        if patch.pattern not in lst:
            lst.append(patch.pattern)

    elif op == "CAP_ARG_LENGTH":
        _need(patch.tool in TOOLS, "unknown tool")
        _need(isinstance(patch.max_len, int) and patch.max_len > 0, "max_len must be a positive int")
        cur = new.max_arg_len.get(patch.tool)
        _need(cur is None or patch.max_len < cur, "new cap must be lower than the current cap")
        new.max_arg_len[patch.tool] = patch.max_len

    new.version = policy.version + 1
    ok, why = is_narrowing(policy, new)
    if not ok:
        raise PatchError(f"patch would widen policy: {why}")
    return new


# ---------- independent subset check ----------
def _items_subset(new: list, old: list) -> bool:
    return "*" in old or all(x in old for x in new if x != "*") and "*" not in new


def is_narrowing(old: Policy, new: Policy) -> tuple[bool, str]:
    """True only if everything `new` allows, `old` also allowed."""
    if old.workspace_root != new.workspace_root:
        return False, "workspace_root changed"
    for f in ("fetch_allowed_hosts", "email_allowed_domains"):
        if not _items_subset(getattr(new, f), getattr(old, f)):
            return False, f"{f} widened"
    if not set(new.allowed_ports) <= set(old.allowed_ports):
        return False, "allowed_ports widened"
    for f in PREFIX_FIELDS:
        oldp = [p.rstrip("/") for p in getattr(old, f)]
        for p in getattr(new, f):
            p = p.rstrip("/")
            if not any(p == o or _under(p, o) for o in oldp):
                return False, f"{f}: {p} not inside old prefixes"
    if old.block_private_ips and not new.block_private_ips:
        return False, "block_private_ips disabled"
    for f in DENY_FIELDS:
        if not set(getattr(old, f)) <= set(getattr(new, f)):
            return False, f"{f} lost an entry"
    for tool, pats in old.arg_deny_patterns.items():
        if not set(pats) <= set(new.arg_deny_patterns.get(tool, [])):
            return False, f"arg_deny_patterns lost an entry for {tool}"
    for tool, cap in old.max_arg_len.items():
        nc = new.max_arg_len.get(tool)
        if nc is None or nc > cap:
            return False, f"max_arg_len widened for {tool}"
    return True, "ok"
