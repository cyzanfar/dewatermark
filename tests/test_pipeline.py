"""Pipeline + config tests. No torch/LLM/network needed: every case uses an
explicit config with the local LM disabled and no API keys."""

import pytest

import dewatermark
from dewatermark import DewatermarkConfig, RemovalResult
from dewatermark.config import configure, get_config, reset_config

# Local LM disabled + no keys: no scorer, no LLM — deterministic offline behavior.
OFFLINE = DewatermarkConfig(local_lm_enabled=False)


@pytest.fixture(autouse=True)
def _reset_module_config():
    reset_config()
    yield
    reset_config()


def test_remove_sanitize_mode_strips_zwsp():
    result = dewatermark.remove("he​llo", mode="sanitize", config=OFFLINE)
    assert isinstance(result, RemovalResult)
    assert result.cleaned_text == "hello"
    assert result.report["chars_removed"] == 1
    assert result.stages[0]["stage"] == "sanitize"
    d = result.to_dict()
    assert d["cleaned_text"] == "hello" and "report" in d and "stages" in d


def test_auto_degrades_to_sanitize_only():
    result = dewatermark.remove("The​ quick brown fox.", mode="auto", config=OFFLINE)
    assert result.cleaned_text == "The quick brown fox."
    assert result.report["auto_selected"] == "sanitize_only"
    assert result.stages[-1]["stage"] == "verify"
    assert result.stages[-1]["remaining_flags"] == 0


def test_surrogate_unavailable_offline():
    score = dewatermark.surrogate_score("some text", config=OFFLINE)
    assert score["available"] is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"passes": 0},
        {"passes": 6},
        {"epsilon": 0.01},
        {"epsilon": 0.95},
        {"beta": -1.0},
        {"beta": 21.0},
        {"best_of": 0},
        {"best_of": 7},
        {"mode": "bogus"},
    ],
)
def test_param_validation_raises(kwargs):
    with pytest.raises(ValueError):
        dewatermark.remove("hello", config=OFFLINE, **kwargs)


def test_empty_text_raises():
    with pytest.raises(ValueError):
        dewatermark.remove("", mode="sanitize", config=OFFLINE)


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("FIREWORKS_AI_API_KEY", "fw-test")
    monkeypatch.setenv("LOCAL_LM", "org/model")
    cfg = DewatermarkConfig.from_env()
    assert cfg.fireworks_api_key == "fw-test"
    assert cfg.local_lm == "org/model"
    assert cfg.lm_backend == "auto"
    assert cfg.resolved_lm_backend == "fireworks"


def test_auto_backend_resolves_local_without_key():
    assert DewatermarkConfig().resolved_lm_backend == "local"


def test_configure_and_reset_roundtrip(monkeypatch):
    monkeypatch.delenv("FIREWORKS_AI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    reset_config()
    default = get_config()
    assert default.fireworks_api_key is None
    configure(llm_api_key="sk-x")
    assert get_config().llm_api_key == "sk-x"
    reset_config()
    assert get_config().llm_api_key is None


def test_dewatermark_class_threads_config():
    dw = dewatermark.Dewatermark(OFFLINE)
    assert dw.sanitize("a​b") == "ab"
    result = dw.remove("a​b", mode="auto")
    assert result.report["auto_selected"] == "sanitize_only"
    assert dw.analyze("a​b")["unicode"]["total_flags"] == 1
    assert dw.surrogate_score("text")["available"] is False
