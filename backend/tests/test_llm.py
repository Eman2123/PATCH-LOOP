from types import SimpleNamespace as NS

import pytest
from pydantic import BaseModel

from app.llm import LLM, LLMError, LLMJSONError, extract_json


def reply(content="", tool_calls=None):
    msg = NS(content=content, tool_calls=tool_calls)
    return NS(choices=[NS(message=msg)], usage=NS(prompt_tokens=3, completion_tokens=2))


def tc(id_, name, args):
    return NS(id=id_, function=NS(name=name, arguments=args))


class FakeClient:
    def __init__(self, items):
        self.items = list(items)
        self.kwargs = []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kw):
        self.kwargs.append(kw)
        it = self.items.pop(0)
        if isinstance(it, Exception):
            raise it
        return it


class HttpErr(Exception):
    def __init__(self, code):
        self.status_code = code


def make(items, **kw):
    c = FakeClient(items)
    return LLM(c, "m", sleep=lambda s: None, **kw), c


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('Sure!\n```json\n{"a": 2}\n```') == {"a": 2}
    assert extract_json('<think>hmm {"x":0}</think>{"a": 3} trailing') == {"a": 3}
    assert extract_json('prefix {"a": {"b": [1,2]}} suffix') == {"a": {"b": [1, 2]}}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_chat_parses_tool_calls():
    llm, _ = make([reply("", [tc("1", "read_file", '{"path": "a.txt"}')])])
    r = llm.chat([{"role": "user", "content": "x"}], tools=[{"type": "function"}])
    assert r.tool_calls[0].name == "read_file" and r.tool_calls[0].args == {"path": "a.txt"}
    assert r.message["tool_calls"][0]["function"]["arguments"] == '{"path": "a.txt"}'


def test_bad_tool_args_become_empty_dict():
    llm, _ = make([reply("", [tc("1", "read_file", "not json")])])
    assert llm.chat([{"role": "user", "content": "x"}]).tool_calls[0].args == {}


def test_cache_avoids_second_call():
    llm, c = make([reply("one")])
    m = [{"role": "user", "content": "x"}]
    assert llm.chat(m).content == "one"
    again = llm.chat(m)
    assert again.content == "one" and again.cached and len(c.kwargs) == 1


def test_disk_cache_roundtrip(tmp_path):
    path = str(tmp_path / "c.jsonl")
    llm, _ = make([reply("hello")], cache_path=path)
    m = [{"role": "user", "content": "x"}]
    llm.chat(m)
    llm2, c2 = make([], cache_path=path)
    assert llm2.chat(m).content == "hello" and not c2.kwargs


def test_retries_rate_limit_then_succeeds():
    llm, c = make([HttpErr(429), HttpErr(503), reply("ok")])
    assert llm.chat([{"role": "user", "content": "x"}]).content == "ok" and len(c.kwargs) == 3


def test_non_retryable_error_raises():
    llm, c = make([HttpErr(401)])
    with pytest.raises(LLMError):
        llm.chat([{"role": "user", "content": "x"}])
    assert len(c.kwargs) == 1


def test_json_mode_rejected_falls_back_without_response_format():
    llm, c = make([HttpErr(400), reply('{"a":1}')])
    llm.chat([{"role": "user", "content": "x"}], json_mode=True)
    assert "response_format" in c.kwargs[0] and "response_format" not in c.kwargs[1]
    assert llm.json_mode_supported is False


class Shape(BaseModel):
    n: int


def test_complete_json_retries_with_feedback():
    llm, c = make([reply("not json"), reply('{"n": "abc"}'), reply('{"n": 5}')])
    assert llm.complete_json("sys", "usr", Shape).n == 5
    last_user = c.kwargs[2]["messages"][-1]["content"]
    assert "invalid" in last_user


def test_complete_json_gives_up():
    llm, _ = make([reply("x"), reply("y")])
    with pytest.raises(LLMJSONError):
        llm.complete_json("s", "u", Shape, attempts=2)


def test_from_env_requires_key():
    with pytest.raises(LLMError):
        LLM.from_env({})


def test_empty_reply_cut_off_by_length_is_an_error_not_a_cached_answer():
    msg = NS(content="", tool_calls=None)
    cut = NS(choices=[NS(message=msg, finish_reason="length")], usage=NS(prompt_tokens=3, completion_tokens=20))
    llm, _ = make([cut])
    with pytest.raises(LLMError, match="ran out of tokens"):
        llm.chat([{"role": "user", "content": "hi"}])
    assert llm._cache == {}


def test_from_env_gives_reasoning_models_room(monkeypatch):
    import sys, types
    fake = types.ModuleType("openai"); fake.OpenAI = lambda **k: object()
    monkeypatch.setitem(sys.modules, "openai", fake)
    assert LLM.from_env({"VULTR_API_KEY": "k"}).max_tokens == 4096
    assert LLM.from_env({"VULTR_API_KEY": "k", "LLM_MAX_TOKENS": "8000"}).max_tokens == 8000
