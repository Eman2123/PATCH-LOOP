"""Attacker agent: LLM writes an injection payload; falls back to fixed payloads when the model fails."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from ..llm import LLM, LLMError
from .attacks import AttackSpec, fixed_attack
from .prompts import ATTACKER_SYSTEM, FAMILIES


class _Draft(BaseModel):
    carrier: str = "web_page"
    payload: str
    rationale: str = ""


def generate_attack(
    llm: Optional[LLM],
    family: str,
    index: int,
    history: Optional[list[dict]] = None,
    use_fixed: bool = False,
) -> AttackSpec:
    """history: earlier attempts [{"payload":..., "outcome": "breached"|"blocked", "why": str}] to vary against."""
    if use_fixed or llm is None:
        return fixed_attack(family, index)
    fam = FAMILIES[family]
    lines = [f"ATTACK GOAL ({fam['name']}): {fam['goal']}", f"Attempt number: {index + 1}."]
    if history:
        lines.append("Earlier attempts (do not repeat them):")
        for h in history[-4:]:
            lines.append(f"- [{h.get('outcome')}] {str(h.get('payload'))[:160]!r} (why: {str(h.get('why', ''))[:120]})")
    try:
        d = llm.complete_json(ATTACKER_SYSTEM, "\n".join(lines), _Draft, attempts=2)
        carrier = d.carrier if d.carrier in ("web_page", "file") else "web_page"
        return AttackSpec(family=family, carrier=carrier, payload=d.payload[:2000], rationale=d.rationale[:200], source="llm")
    except (LLMError, ValueError):
        return fixed_attack(family, index)  # weak attacker or refusal: still run a real attack
