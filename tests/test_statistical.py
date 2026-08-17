from dewatermark import sira
from dewatermark.config import DewatermarkConfig, assert_remote_allowed


def _si_for_words(text):
    out = []
    cursor = 0
    for i, word in enumerate(text.split()):
        start = text.index(word, cursor)
        end = start + len(word)
        cursor = end
        out.append(
            {
                "token_str": word,
                "start": start,
                "end": end,
                "surprisal_bits": float(i),
                "token_id": i,
            }
        )
    return out


def test_sira_masks_proportion_not_eight_token_cap():
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    text = " ".join("word" + alphabet[i // 26] + alphabet[i % 26] for i in range(100))
    spans = sira.select_mask(_si_for_words(text), epsilon=0.3)
    assert len(spans) == 30


def test_sira_uses_reference_and_quality_gate(monkeypatch):
    text = "Alpha beta gamma delta epsilon zeta eta theta iota kappa."
    monkeypatch.setattr(sira.scoring, "self_information", lambda *_: _si_for_words(text))
    calls = []

    def fake_chat(system, prompt, **_kwargs):
        calls.append((system, prompt))
        if len(calls) == 1:
            return "Alpha beta gamma delta epsilon zeta eta theta iota kappa."
        return text

    monkeypatch.setattr(sira, "chat", fake_chat)
    cfg = DewatermarkConfig(
        local_lm_enabled=False, llm_api_key="x", llm_base_url="http://127.0.0.1:9999"
    )
    out, detail = sira.sira_rewrite(text, 0.3, cfg)
    assert out == text
    assert "<REFERENCE>" in calls[1][1]
    assert detail["quality"]["passed"]


def test_remote_processing_requires_opt_in():
    cfg = DewatermarkConfig()
    try:
        assert_remote_allowed("https://example.com", cfg)
    except PermissionError:
        pass
    else:
        raise AssertionError("remote URL should require consent")
    assert_remote_allowed("http://127.0.0.1:8000", cfg)


def test_non_http_endpoint_is_always_rejected():
    cfg = DewatermarkConfig(allow_remote_processing=True)
    try:
        assert_remote_allowed("file:///tmp/socket", cfg)
    except PermissionError:
        pass
    else:
        raise AssertionError("non-http endpoint should be rejected")


def test_endpoint_credentials_are_rejected():
    cfg = DewatermarkConfig(allow_remote_processing=True)
    try:
        assert_remote_allowed("https://user:secret@example.com", cfg)
    except PermissionError:
        pass
    else:
        raise AssertionError("URL credentials should be rejected")
