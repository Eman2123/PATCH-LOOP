from app.agents.worker import system_prompt
from app.loop import LoopRunner


def test_compromised_prompt_only_when_asked():
    assert "SIMULATION MODE" not in system_prompt("none", "native")
    assert "SIMULATION MODE" in system_prompt("none", "native", susceptible=True)


def test_susceptible_flag_follows_env(monkeypatch):
    monkeypatch.setenv("SUSCEPTIBLE_AGENT", "1")
    assert LoopRunner(llm=None).susceptible is True
    monkeypatch.setenv("SUSCEPTIBLE_AGENT", "0")
    assert LoopRunner(llm=None).susceptible is False
