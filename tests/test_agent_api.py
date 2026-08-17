import asyncio
import json
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

import dewatermark
from dewatermark import DewatermarkConfig
from dewatermark.cli import EXIT_OK, EXIT_PROCESSING, main
from dewatermark.providers import unregister_provider

OFFLINE = DewatermarkConfig(local_lm_enabled=False)


def test_config_repr_and_serialization_redact_secrets():
    class PrivateScorer:
        def __repr__(self):
            return "semantic-scorer-secret"

        def __call__(self, _source, _candidate):
            return 1.0

    cfg = DewatermarkConfig(
        fireworks_api_key="fw-secret",
        llm_api_key="llm-secret",
        semantic_scorer=PrivateScorer(),
    )
    assert "fw-secret" not in repr(cfg)
    assert "llm-secret" not in repr(cfg)
    assert "semantic-scorer-secret" not in repr(cfg)
    assert cfg.to_dict()["fireworks_api_key"] == "***"
    assert cfg.to_dict()["llm_api_key"] == "***"
    assert "fw-secret" not in str(cfg.to_dict(redact_secrets=False))
    assert "llm-secret" not in str(cfg.to_dict(redact_secrets=False))


def test_namespaced_environment_takes_precedence(monkeypatch):
    monkeypatch.setenv("LOCAL_LM", "legacy/model")
    monkeypatch.setenv("DEWATERMARK_LOCAL_LM", "new/model")
    assert DewatermarkConfig.from_env().local_lm == "new/model"


def test_invalid_environment_is_actionable(monkeypatch):
    monkeypatch.setenv("DEWATERMARK_ALLOW_MODEL_DOWNLOAD", "sometimes")
    try:
        DewatermarkConfig.from_env()
    except dewatermark.ConfigurationError as exc:
        assert "must be true or false" in str(exc)
        assert exc.__cause__ is None
    else:
        raise AssertionError("invalid boolean should fail")


def test_invalid_numeric_environment_does_not_retain_private_cause(monkeypatch):
    secret = "private-invalid-environment-value"
    monkeypatch.setenv("DEWATERMARK_MAX_REMOTE_CALLS", secret)
    with pytest.raises(dewatermark.ConfigurationError) as caught:
        DewatermarkConfig.from_env()
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "endpoint",
    [
        "file:///tmp/provider",
        "https://user:private@example.test/v1",
        "https://example.test/v1?api_key=private",
        "https://example.test/v1#private",
    ],
)
def test_config_rejects_credential_bearing_or_non_http_endpoints(endpoint):
    with pytest.raises(dewatermark.ConfigurationError):
        DewatermarkConfig(llm_base_url=endpoint)


def test_remove_default_is_auto_and_schema_is_stable():
    result = dewatermark.remove("a\u200bb", config=OFFLINE)
    payload = result.to_dict()
    assert result.report["mode"] == "auto"
    assert payload["schema_version"] == "1.0"
    assert payload["report"]["schema_version"] == "1.0"
    assert payload["cleaned_text"] == "ab"


def test_capabilities_and_plan_are_machine_readable():
    caps = dewatermark.capabilities(OFFLINE)
    planned = dewatermark.plan("sanitize", OFFLINE).to_dict()
    assert caps["schema_version"] == "1.0"
    assert caps["assurance"]["operations"] == ["inspect", "plan", "apply", "verify"]
    assert any(
        item["registered_name"] == "anthropic-claude"
        and item["metadata"]["status"] == "unsupported_pending_spec"
        for item in caps["detector_capabilities"]
    )
    assert planned["available"] is True
    assert planned["network_required"] is False
    schema = dewatermark.removal_result_schema()
    assert schema["properties"]["stages"]["items"]["properties"]["accepted"]
    checked_in = json.loads(
        (Path(__file__).parents[1] / "schemas/removal-result-v1.json").read_text()
    )
    assert checked_in == schema
    for kind, filename in (
        ("evidence-receipt", "evidence-receipt-v1.json"),
        ("detector-capability", "detector-capability-v1.json"),
        ("command-detector", "command-detector-protocol-v1.json"),
    ):
        expected = json.loads((Path(__file__).parents[1] / "schemas" / filename).read_text())
        assert dewatermark.public_schema(kind) == expected


def test_plan_describes_remote_paraphrase_without_loading_models():
    cfg = replace(
        OFFLINE,
        llm_api_key="secret",
        llm_base_url="http://127.0.0.1:8080",
        allow_remote_processing=True,
    )
    planned = dewatermark.plan("paraphrase", cfg)
    assert planned.available
    assert planned.backend == "llm"
    assert planned.network_required


def test_provider_extension_and_registry():
    class Rewriter:
        capability = dewatermark.CapabilityManifest(
            identifier="test-provider",
            kind="transformer",
            schemes=("test",),
        )

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text.replace("large", "big"), {"strategy": "test"}

    dewatermark.register_provider("test-provider", Rewriter)
    try:
        cfg = replace(OFFLINE, rewriter_provider="test-provider")
        result = dewatermark.remove("A large change.", config=cfg)
        assert result.cleaned_text == "A big change."
        assert result.stages[1].backend == "test-provider"
    finally:
        unregister_provider("test-provider")


def test_event_hook_never_receives_source_text():
    events = []
    source = "private source text"
    cfg = replace(OFFLINE, event_handler=events.append)
    dewatermark.remove(source, mode="sanitize", config=cfg)
    assert events[0]["event"] == "pipeline.started"
    assert events[-1]["event"] == "pipeline.finished"
    assert any(event["event"] == "stage.finished" for event in events)
    assert source not in json.dumps(events)


def test_broken_event_hook_does_not_break_processing(caplog):
    private = "private-source-or-credential"

    def broken(_event):
        raise RuntimeError(private)

    cfg = replace(OFFLINE, event_handler=broken)
    assert dewatermark.remove("a\u200bb", mode="sanitize", config=cfg).cleaned_text == "ab"
    assert private not in caplog.text
    assert "details redacted" in caplog.text


def test_batch_collects_per_item_failures_and_preserves_order():
    items = dewatermark.remove_many(["a\u200bb", "", "c\u200bd"], mode="sanitize", config=OFFLINE)
    assert [item.index for item in items] == [0, 1, 2]
    assert items[0].result.cleaned_text == "ab"
    assert not items[1].succeeded
    assert items[2].result.cleaned_text == "cd"


def test_async_api():
    result = asyncio.run(dewatermark.aremove("a\u200bb", mode="sanitize", config=OFFLINE))
    assert result.cleaned_text == "ab"


def test_input_budget_is_enforced():
    cfg = replace(OFFLINE, max_input_chars=3)
    try:
        dewatermark.remove("four", mode="sanitize", config=cfg)
    except ValueError as exc:
        assert "max_input_chars" in str(exc)
    else:
        raise AssertionError("input budget should be enforced")


def test_cli_json_and_dry_run(capsys):
    assert main(["sanitize", "a\u200bb", "--format", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["cleaned_text"] == "ab"
    assert main(["remove", "--mode", "sanitize", "--dry-run"]) == EXIT_OK
    planned = json.loads(capsys.readouterr().out)
    assert planned["backend"] == "unicode"


def test_cli_jsonl(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", StringIO('{"text":"a\\u200bb"}\nnot-json\n'))
    assert main(["remove", "--mode", "sanitize", "--format", "jsonl"]) == EXIT_PROCESSING
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert rows[0]["cleaned_text"] == "ab"
    assert rows[1]["status"] == "failed"
