import asyncio
import json
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

import dewatermark
import dewatermark.providers as providers
import dewatermark.scoring as scoring
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
        local_lm="/private/model/tenant-secret",
        llm_base_url="https://example.test/private-endpoint-secret",
        semantic_scorer=PrivateScorer(),
    )
    assert "fw-secret" not in repr(cfg)
    assert "llm-secret" not in repr(cfg)
    assert "semantic-scorer-secret" not in repr(cfg)
    assert "tenant-secret" not in repr(cfg)
    assert "private-endpoint-secret" not in repr(cfg)
    assert cfg.to_dict()["fireworks_api_key"] == "***"
    assert cfg.to_dict()["llm_api_key"] == "***"
    assert "fw-secret" not in str(cfg.to_dict(redact_secrets=False))
    assert "llm-secret" not in str(cfg.to_dict(redact_secrets=False))
    assert "tenant-secret" not in str(cfg.to_dict(redact_secrets=False))
    assert "private-endpoint-secret" not in str(cfg.to_dict(redact_secrets=False))


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


def test_capability_discovery_and_planning_do_not_probe_model_storage(monkeypatch):
    def forbidden(_model):
        raise AssertionError("discovery probed model storage")

    monkeypatch.setattr(scoring, "model_cached", forbidden)
    private_model = "private/model/path/with-credential"
    cfg = replace(OFFLINE, local_lm=private_model)
    capabilities = dewatermark.capabilities(cfg)
    planned = dewatermark.plan("auto", cfg).to_dict()

    assert capabilities["dependency_probe"] == "loaded_modules_only"
    assert capabilities["local_model_cache_probe"] == "in_process_only"
    assert private_model not in json.dumps(capabilities)
    assert planned["available"] is False


def test_capability_discovery_and_planning_do_not_register_builtins(monkeypatch):
    monkeypatch.setattr(providers, "_detectors", {})
    monkeypatch.setattr(providers, "_detector_manifests", {})
    monkeypatch.setattr(providers, "_detector_identities", {})
    monkeypatch.setattr(providers, "_detector_revisions", {})
    monkeypatch.setattr(providers, "_detector_entry_points", {})
    monkeypatch.setattr(providers, "_provider_entry_points", {})

    def forbidden(*_args, **_kwargs):
        raise AssertionError("capability discovery mutated the detector registry")

    monkeypatch.setattr(providers, "register_detector", forbidden)
    capabilities = dewatermark.capabilities(OFFLINE)
    planned = dewatermark.create_plan(
        "plain source", mode="sanitize", detector="unicode", config=OFFLINE
    )

    assert any(
        item["registered_name"] == "unicode" for item in capabilities["detector_capabilities"]
    )
    assert planned["execution"]["available"] is True


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


def test_cli_jsonl_invalid_item_does_not_abort_later_rows(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin",
        StringIO('{"text":"a\\u200bb"}\n{"text":123}\n{"text":"c\\u200bd"}\n'),
    )

    assert main(["remove", "--mode", "sanitize", "--format", "jsonl"]) == EXIT_PROCESSING
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["line"] for row in rows] == [1, 2, 3]
    assert rows[0]["cleaned_text"] == "ab"
    assert rows[1] == {
        "schema_version": "1.0",
        "line": 2,
        "status": "failed",
        "error": "line is not valid JSON with a text field",
    }
    assert rows[2]["cleaned_text"] == "cd"


def test_cli_jsonl_redacts_per_item_processing_exceptions(monkeypatch, capsys):
    secret = "private-source bearer-secret /private/model"

    def process(source, _args, _config):
        if source == "bad":
            raise RuntimeError(secret)
        return {"cleaned_text": source, "report": {"status": "success"}}

    monkeypatch.setattr("dewatermark.cli._remove_one", process)
    monkeypatch.setattr("sys.stdin", StringIO('{"text":"ok"}\n{"text":"bad"}\n{"text":"later"}\n'))

    assert main(["remove", "--mode", "sanitize", "--format", "jsonl"]) == EXIT_PROCESSING
    output = capsys.readouterr().out
    rows = [json.loads(line) for line in output.splitlines()]
    assert [row["line"] for row in rows] == [1, 2, 3]
    assert rows[1]["error"] == "line processing failed; details redacted"
    assert rows[2]["cleaned_text"] == "later"
    assert secret not in output
