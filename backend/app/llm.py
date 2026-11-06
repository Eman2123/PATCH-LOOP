"""Thin OpenAI-compatible client for Vultr Serverless Inference.

Responsibilities: retries with backoff, in-memory (+ optional JSONL) cache so temp-0 reruns
are free, tolerant JSON extraction (fences, <think> blocks), and complete_json() which
re-prompts with the validation error when a model returns bad JSON.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence, Type, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


class LLMJSONError(LLMError):
    pass


@dataclass
class ToolCallReq:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class ChatResult:
    content: str
    tool_calls: list[ToolCallReq] = field(default_factory=list)
    message: dict[str, Any] = field(default_factory=dict)  # assistant message, ready to append to history
    usage: dict[str, int] = field(default_factory=dict)
    cached: bool = False


# ---------- JSON helpers ----------
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> Any:
    """Pull the first JSON object/array out of a model reply. Raises ValueError if none parses."""
    if not isinstance(text, str):
        raise ValueError("reply is not text")
    text = _THINK.sub("", text).strip()
    candidates = [text] + _FENCE.findall(text)
    dec = json.JSONDecoder()
    for cand in candidates:
        cand = cand.strip()
        for i, ch in enumerate(cand):
            if ch in "{[":
                try:
                    obj, _ = dec.raw_decode(cand[i:])
                    return obj
                except json.JSONDecodeError:
                    continue
    raise ValueError("no JSON found in reply")


def _parse_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        v = extract_json(raw or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


_RETRYABLE_NAMES = {"RateLimitError", "APIConnectionError", "APITimeoutError", "InternalServerError"}


def _retryable(e: Exception) -> bool:
    code = getattr(e, "status_code", None)
    return type(e).__name__ in _RETRYABLE_NAMES or code in (408, 409, 429) or (isinstance(code, int) and code >= 500)


class LLM:
    def __init__(
        self,
        client: Any,
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        cache_path: Optional[str] = None,
    ):
        self.client = client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.retries = retries
        self._sleep = sleep
        self.json_mode_supported = True
        self.calls = 0  # real API calls (cache hits excluded)
        self._cache: dict[str, dict] = {}
        self._cache_path = Path(cache_path) if cache_path else None
        if self._cache_path and self._cache_path.exists():
            for line in self._cache_path.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                    self._cache[row["k"]] = row["v"]
                except (json.JSONDecodeError, KeyError):
                    continue

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **kw: Any) -> "LLM":
        from openai import OpenAI  # imported lazily so tests never need network or a key

        env = env if env is not None else os.environ
        key = env.get("VULTR_API_KEY", "")
        if not key:
            raise LLMError("VULTR_API_KEY is not set")
        client = OpenAI(api_key=key, base_url=env.get("VULTR_BASE_URL", "https://api.vultrinference.com/v1"))
        return cls(client, env.get("MODEL_NAME", "glm-5.3"), cache_path=env.get("LLM_CACHE_PATH") or None, **kw)

    # ---------- core call ----------
    def _key(self, messages: Sequence[dict], tools: Optional[Sequence[dict]], json_mode: bool) -> str:
        blob = json.dumps([self.model, self.temperature, messages, tools, json_mode], sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def chat(
        self,
        messages: Sequence[dict],
        tools: Optional[Sequence[dict]] = None,
        json_mode: bool = False,
        use_cache: bool = True,
    ) -> ChatResult:
        key = self._key(messages, tools, json_mode)
        if use_cache and key in self._cache:
            return self._from_cached(self._cache[key])
        kwargs: dict[str, Any] = dict(
            model=self.model, messages=list(messages), temperature=self.temperature, max_tokens=self.max_tokens
        )
        if tools:
            kwargs["tools"] = list(tools)
        if json_mode and self.json_mode_supported:
            kwargs["response_format"] = {"type": "json_object"}
        resp = self._create_with_retry(kwargs)
        msg = resp.choices[0].message
        tool_calls = []
        raw_calls = getattr(msg, "tool_calls", None) or []
        for tc in raw_calls:
            tool_calls.append(ToolCallReq(id=tc.id, name=tc.function.name, args=_parse_args(tc.function.arguments)))
        content = getattr(msg, "content", None) or ""
        assistant: dict[str, Any] = {"role": "assistant", "content": content}
        if raw_calls:
            assistant["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}}
                for tc in raw_calls
            ]
        u = getattr(resp, "usage", None)
        usage = {"prompt": getattr(u, "prompt_tokens", 0) or 0, "completion": getattr(u, "completion_tokens", 0) or 0}
        result = ChatResult(content=content, tool_calls=tool_calls, message=assistant, usage=usage)
        if use_cache:
            self._store(key, result)
        return result

    def _create_with_retry(self, kwargs: dict[str, Any]) -> Any:
        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                self.calls += 1
                return self.client.chat.completions.create(**kwargs)
            except Exception as e:  # noqa: BLE001 - classify below
                last = e
                if "response_format" in kwargs and getattr(e, "status_code", None) == 400:
                    self.json_mode_supported = False  # endpoint rejects json_object: drop it for good
                    kwargs = {k: v for k, v in kwargs.items() if k != "response_format"}
                    continue
                if not _retryable(e) or attempt == self.retries:
                    break
                self._sleep(min(2 ** attempt, 8))
        raise LLMError(f"LLM call failed: {type(last).__name__}: {last}") from last

    # ---------- cache ----------
    def _store(self, key: str, r: ChatResult) -> None:
        row = {"content": r.content, "message": r.message, "usage": r.usage,
               "tool_calls": [{"id": t.id, "name": t.name, "args": t.args} for t in r.tool_calls]}
        self._cache[key] = row
        if self._cache_path:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"k": key, "v": row}) + "\n")

    @staticmethod
    def _from_cached(row: dict) -> ChatResult:
        return ChatResult(
            content=row["content"], message=row["message"], usage=row.get("usage", {}), cached=True,
            tool_calls=[ToolCallReq(**t) for t in row.get("tool_calls", [])],
        )

    # ---------- structured output ----------
    def complete_json(self, system: str, user: str, model_cls: Type[T], attempts: int = 3) -> T:
        """Ask for JSON matching model_cls; on bad JSON or a failed validation, feed the error back and retry."""
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        err = "unknown"
        for _ in range(attempts):
            r = self.chat(messages, json_mode=True)
            try:
                return model_cls.model_validate(extract_json(r.content))
            except (ValueError, ValidationError) as e:
                err = str(e)[:300]
                messages = messages + [
                    {"role": "assistant", "content": r.content},
                    {"role": "user", "content": f"That reply was invalid: {err}\nReply again with ONLY one valid JSON object."},
                ]
        raise LLMJSONError(f"no valid JSON after {attempts} attempts: {err}")
