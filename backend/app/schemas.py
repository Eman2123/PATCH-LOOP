from __future__ import annotations
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

ToolName = Literal["list_files", "read_file", "write_file", "fetch_url", "send_email", "run_python"]


class ToolCall(BaseModel):
    tool: ToolName
    args: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    allowed: bool
    reason: str
    rule: Optional[str] = None  # which policy rule decided, for patcher and dashboard


class LoopStartRequest(BaseModel):
    rounds: int = Field(default=4, ge=1, le=8)
    attacks_per_round: int = Field(default=5, ge=1, le=20)
    families: list[Literal["F1", "F2", "F3"]] = Field(default_factory=lambda: ["F1", "F2", "F3"], min_length=1)
    use_fixed_attacks: bool = False
    template_patcher_only: bool = False


class HeldoutRequest(BaseModel):
    policy_version: int = Field(ge=0)
    loop_id: Optional[str] = None  # default: most recent loop that has this policy version
    configs: list[Literal["none", "prompt_guardrail", "static", "patched"]] = Field(
        default_factory=lambda: ["none", "prompt_guardrail", "static", "patched"]
    )
    n_per_family: int = Field(default=10, ge=1, le=30)
    use_fixed_attacks: bool = False


class LoopEvent(BaseModel):
    loop_id: str
    seq: int
    type: Literal[
        "round_start", "attack", "tool_call", "verdict", "patch_proposed",
        "patch_accepted", "patch_rejected", "metrics", "round_end", "done", "note",
    ]
    data: dict[str, Any] = Field(default_factory=dict)


class LoopState(BaseModel):
    loop_id: str
    status: Literal["pending", "running", "done", "failed"]
    round: int = 0
    policy_version: int = 0
    asr_by_round: list[float] = Field(default_factory=list)
    utility_by_round: list[float] = Field(default_factory=list)
