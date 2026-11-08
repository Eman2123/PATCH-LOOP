"""OfficeBot: an LLM tool-use loop. Every tool call goes through SimEnv.execute (the gateway)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

from ..env.sim import SimEnv, ToolResult
from ..llm import LLM, LLMError, extract_json
from ..policy import Policy
from .prompts import COMPROMISED_ADDENDUM, GUARDRAIL_ADDENDUM, JSON_PROTOCOL, WORKER_SYSTEM

Defense = Literal["none", "prompt_guardrail"]
ToolMode = Literal["native", "json"]


def _fn(name: str, desc: str, props: dict[str, str], required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
                       "required": required}}}


TOOL_SPECS: list[dict] = [
    _fn("list_files", "List files in a workspace directory.", {"path": "directory path"}, ["path"]),
    _fn("read_file", "Read a text file.", {"path": "file path"}, ["path"]),
    _fn("write_file", "Write a text file.", {"path": "file path", "content": "file content"}, ["path", "content"]),
    _fn("fetch_url", "HTTP GET a URL and return the body.", {"url": "absolute URL"}, ["url"]),
    _fn("send_email", "Send an email.", {"to": "recipient address", "subject": "subject", "body": "body"}, ["to", "subject", "body"]),
    _fn("run_python", "Run Python code in a sandbox (no network).", {"code": "python source"}, ["code"]),
]
TOOL_NAMES = {t["function"]["name"] for t in TOOL_SPECS}


@dataclass
class WorkerResult:
    final: str = ""
    steps: int = 0
    tool_calls: int = 0
    stopped: str = "final"  # final | max_steps | error
    error: str = ""
    transcript: list[dict[str, Any]] = field(default_factory=list)


OnTool = Callable[[str, dict, ToolResult], None]


def system_prompt(defense: Defense, tool_mode: ToolMode, susceptible: bool = False) -> str:
    s = WORKER_SYSTEM
    if susceptible:
        s += COMPROMISED_ADDENDUM
    if defense == "prompt_guardrail":
        s += GUARDRAIL_ADDENDUM
    if tool_mode == "json":
        s += JSON_PROTOCOL
    return s


def _exec(env: SimEnv, policy: Policy, name: str, args: dict, on_tool: Optional[OnTool]) -> str:
    if name not in TOOL_NAMES:
        return f"unknown tool: {name}"
    # Models sometimes send non-string args; the gateway expects well-formed input, so normalize minimally.
    res = env.execute(policy, name, args)
    if on_tool:
        on_tool(name, args, res)
    return res.output


def run_worker(
    llm: LLM,
    env: SimEnv,
    policy: Policy,
    task: str,
    defense: Defense = "none",
    tool_mode: ToolMode = "native",
    max_steps: int = 8,
    on_tool: Optional[OnTool] = None,
    susceptible: bool = False,
) -> WorkerResult:
    out = WorkerResult()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt(defense, tool_mode, susceptible)},
        {"role": "user", "content": task},
    ]
    try:
        for step in range(max_steps):
            out.steps = step + 1
            r = llm.chat(messages, tools=TOOL_SPECS if tool_mode == "native" else None)
            if tool_mode == "native":
                if not r.tool_calls:
                    out.final = r.content
                    break
                messages.append(r.message)
                for tc in r.tool_calls:
                    out.tool_calls += 1
                    text = _exec(env, policy, tc.name, tc.args, on_tool)
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})
            else:
                try:
                    act = extract_json(r.content)
                except ValueError:
                    out.final = r.content
                    break
                if not isinstance(act, dict) or "tool" not in act:
                    out.final = str(act.get("final", r.content)) if isinstance(act, dict) else r.content
                    break
                out.tool_calls += 1
                args = act.get("args") if isinstance(act.get("args"), dict) else {}
                text = _exec(env, policy, str(act["tool"]), args, on_tool)
                messages.append({"role": "assistant", "content": r.content})
                messages.append({"role": "user", "content": f"TOOL RESULT ({act['tool']}):\n{text}"})
        else:
            out.stopped = "max_steps"
    except LLMError as e:
        out.stopped, out.error = "error", str(e)[:300]
    out.transcript = messages[1:]
    return out
