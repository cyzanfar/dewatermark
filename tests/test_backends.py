from dataclasses import replace

import pytest

from dewatermark import bira, fireworks, paraphraser, scoring
from dewatermark.config import DewatermarkConfig
from dewatermark.providers import register_provider, unregister_provider


class Response:
    status_code = 200
    text = "ok"

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


LOCAL_REMOTE = DewatermarkConfig(
    fireworks_api_key="secret",
    fireworks_base_url="http://127.0.0.1:8080/v1",
    lm_backend="fireworks",
)


def test_fireworks_availability_and_scoring(monkeypatch):
    assert not fireworks.available(DewatermarkConfig())
    assert fireworks.available(LOCAL_REMOTE)
    response = Response(
        {
            "choices": [
                {
                    "logprobs": {
                        "tokens": ["hello", " world", "!"],
                        "token_logprobs": [None, -1.0, -2.0],
                        "token_ids": [1, 2, 3],
                        "text_offset": [0, 5, 11],
                    }
                }
            ]
        }
    )
    monkeypatch.setattr(fireworks, "post_json", lambda *_args, **_kwargs: response)
    info = fireworks.self_information("hello world", LOCAL_REMOTE)
    assert info[0]["token_id"] == 2
    assert info[0]["surprisal_bits"] > 1
    assert fireworks.surrogate_score("hello world", LOCAL_REMOTE)["available"]


def test_fireworks_chat_and_bira(monkeypatch):
    response = Response({"choices": [{"message": {"content": "A rewritten sentence here."}}]})
    monkeypatch.setattr(fireworks, "post_json", lambda *_args, **_kwargs: response)
    assert fireworks.chat("system", "A source sentence here.", config=LOCAL_REMOTE).startswith("A")
    monkeypatch.setattr(
        fireworks,
        "self_information",
        lambda *_args: [{"token_id": 2, "surprisal_bits": 9.0}],
    )
    output, detail = fireworks.bira_rewrite("A source sentence here.", config=LOCAL_REMOTE)
    assert output == "A rewritten sentence here."
    assert detail["quality"]["passed"]


def test_paraphraser_chat_and_recursive_quality(monkeypatch):
    with pytest.raises(paraphraser.LLMError):
        paraphraser.chat("system", "text", 1.0, config=DewatermarkConfig())
    cfg = DewatermarkConfig(llm_api_key="secret", llm_base_url="http://127.0.0.1:8080/v1")
    response = Response({"choices": [{"message": {"content": "Facts remain exactly here."}}]})
    monkeypatch.setattr(paraphraser, "post_json", lambda *_args, **_kwargs: response)
    assert paraphraser.chat("system", "Facts stay exactly here.", 1.0, config=cfg)
    monkeypatch.setattr(paraphraser, "chat", lambda *_args, **_kwargs: "Facts remain exactly here.")
    output, stages = paraphraser.recursive_paraphrase("Facts stay exactly here.", 1, cfg)
    assert output == "Facts remain exactly here."
    assert stages[0]["quality"]["passed"]


def test_remote_call_budget_and_unavailable_local_bira():
    cfg = DewatermarkConfig(llm_api_key="x", llm_base_url="http://127.0.0.1:1", max_remote_calls=1)
    output, stages = paraphraser.recursive_paraphrase("Source text remains.", 2, cfg)
    assert output == "Source text remains."
    assert "exceed budget" in stages[0]["error"]
    output, detail = bira.bira_rewrite(
        "Source text remains.", config=DewatermarkConfig(local_lm_enabled=False)
    )
    assert output == "Source text remains."
    assert "unavailable" in detail["error"]


def test_custom_scorer_provider_and_cache_helpers(tmp_path):
    class CustomScorer:
        def __init__(self, _config):
            pass

        def available(self):
            return True

        def self_information(self, _text):
            return [{"token_id": 1, "token_str": "x", "start": 0, "end": 1, "surprisal_bits": 9.0}]

        def score(self, _text):
            return {"available": True}

    register_provider("custom-scorer", CustomScorer)
    try:
        cfg = replace(DewatermarkConfig(local_lm_enabled=False), scorer_provider="custom-scorer")
        assert scoring.available(cfg)
        assert scoring.surrogate_score("x", cfg)["high_surprisal_fraction"] == 1.0
    finally:
        unregister_provider("custom-scorer")
    assert scoring.model_cached(str(tmp_path))
    scoring.clear_cache()
    assert scoring.cache_info() == {"models": []}
