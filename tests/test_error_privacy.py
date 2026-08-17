import io
import json
from dataclasses import replace

import pytest
import requests

import dewatermark.providers as providers
import dewatermark.scoring as scoring
from dewatermark import (
    CapabilityManifest,
    ConfigurationError,
    detectors,
    extension_safety,
    fireworks,
    http,
    mcp_server,
    paraphraser,
    scanner,
    server,
    sira,
)
from dewatermark.cli import EXIT_PROCESSING, main
from dewatermark.config import DewatermarkConfig
from dewatermark.providers import register_provider, unregister_provider
from dewatermark.request_context import ResourceBudgetExceeded, safe_error

SECRET = "private-source bearer-secret /private/model https://user:pass@example.test"
REMOTE = DewatermarkConfig(
    llm_api_key="credential",
    llm_base_url="http://127.0.0.1:8080/v1",
    fireworks_api_key="credential",
    fireworks_base_url="http://127.0.0.1:8080/v1",
    allow_remote_processing=True,
)


class _MalformedResponse:
    status_code = 200

    def json(self):
        raise ValueError(SECRET)


def _assert_private_error(exc: BaseException) -> None:
    assert SECRET not in str(exc)
    assert exc.__cause__ is None


def test_remote_transport_discards_request_exception(monkeypatch):
    monkeypatch.setattr(
        http.requests,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(requests.ConnectionError(SECRET)),
    )
    with pytest.raises(http.HTTPTransportError) as caught:
        http.post_json(
            "http://127.0.0.1/x",
            headers={"Authorization": SECRET},
            body={"text": SECRET},
            timeout=1,
            retries=0,
            config=REMOTE,
        )
    _assert_private_error(caught.value)


def test_malformed_remote_bodies_and_model_identifiers_are_redacted(monkeypatch):
    monkeypatch.setattr(paraphraser, "post_json", lambda *_args, **_kwargs: _MalformedResponse())
    with pytest.raises(paraphraser.LLMError) as llm_error:
        paraphraser.chat("system", SECRET, 1.0, config=REMOTE)
    _assert_private_error(llm_error.value)

    monkeypatch.setattr(fireworks, "post_json", lambda *_args, **_kwargs: _MalformedResponse())
    with pytest.raises(fireworks.FireworksError) as fireworks_error:
        fireworks.chat("system", SECRET, config=REMOTE)
    _assert_private_error(fireworks_error.value)

    config = DewatermarkConfig(llm_model=SECRET, max_remote_calls=16)
    monkeypatch.setattr(
        paraphraser,
        "chat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(paraphraser.LLMError(SECRET)),
    )
    _, stages = paraphraser.recursive_paraphrase("source", 1, config)
    assert SECRET not in json.dumps(stages)
    assert "model_sha256" in stages[0]


def test_safe_error_never_trusts_custom_budget_messages():
    assert SECRET not in safe_error("operation", ResourceBudgetExceeded(SECRET))
    assert SECRET not in safe_error(SECRET, RuntimeError(SECRET))


def test_cli_and_mcp_hide_custom_exception_messages(monkeypatch, capsys):
    monkeypatch.setattr(
        "dewatermark.cli._remove_one",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    assert main(["remove", "source"]) == EXIT_PROCESSING
    assert SECRET not in capsys.readouterr().err

    monkeypatch.setattr(
        mcp_server,
        "analyze",
        lambda _text: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    with pytest.raises(RuntimeError) as caught:
        mcp_server.analyze_text("source")
    _assert_private_error(caught.value)


def test_http_handler_and_scanner_hide_failure_details(monkeypatch, tmp_path):
    handler = object.__new__(server.DewatermarkHandler)
    handler.path = "/analyze"
    handler.headers = {"Content-Type": "application/json", "Content-Length": "18"}
    handler.rfile = io.BytesIO(b'{"text": "source"}')
    handler._guard = lambda: True
    responses = []
    handler._send = lambda status, value: responses.append((status, value))
    monkeypatch.setattr(
        server,
        "process_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(SECRET)),
    )
    handler.do_POST()
    assert responses == [(400, {"error": "invalid request"})]

    private_filename = "private-source-bearer-secret-private-model.txt"
    target = tmp_path / private_filename
    target.write_text("text", encoding="utf-8")
    monkeypatch.setattr(
        scanner.Path,
        "read_bytes",
        lambda _path: (_ for _ in ()).throw(OSError(SECRET)),
    )
    report = scanner.scan_paths([target])
    rendered = json.dumps(report.to_dict())
    assert SECRET not in rendered
    assert private_filename not in rendered
    assert report.errors[0].startswith("file_sha256:")


def test_extension_and_registry_failures_discard_private_details(monkeypatch):
    class BadMetadata:
        capability = CapabilityManifest(
            identifier="privacy-fixture",
            kind="scorer",
            metadata={SECRET: float("nan")},
        )

    with pytest.raises(ConfigurationError) as metadata_error:
        extension_safety.static_capability(BadMetadata, "scorer")
    _assert_private_error(metadata_error.value)

    class EntryPoint:
        def load(self):
            raise RuntimeError(SECRET)

    monkeypatch.setattr(providers, "_provider_entry_points", {"privacy-fixture": EntryPoint()})
    try:
        with pytest.raises(ConfigurationError) as provider_error:
            providers.get_provider("privacy-fixture")
        _assert_private_error(provider_error.value)
        assert providers.provider_errors()["privacy-fixture"] == "entry_point_load_failed"
    finally:
        providers._provider_errors.pop("privacy-fixture", None)


def test_scorer_and_sira_failures_and_cache_metadata_are_private(monkeypatch):
    class LeakyScorer:
        capability = CapabilityManifest(identifier="leaky-scorer", kind="scorer")

        def __init__(self, _config):
            pass

        def self_information(self, _text):
            raise RuntimeError(SECRET)

    register_provider("leaky-scorer", LeakyScorer)
    config = replace(DewatermarkConfig(local_lm_enabled=False), scorer_provider="leaky-scorer")
    try:
        with pytest.raises(scoring.ScorerUnavailable) as scorer_error:
            scoring.self_information("source", config)
        _assert_private_error(scorer_error.value)
        assert SECRET not in json.dumps(scoring.surrogate_score("source", config))
    finally:
        unregister_provider("leaky-scorer")

    scoring.clear_cache()
    try:
        scoring._state["private-cache-key"] = {
            "name": SECRET,
            "device": "cpu",
            "dtype": "float32",
        }
        assert SECRET not in json.dumps(scoring.cache_info())
        assert scoring.cache_info()["models"][0]["name"].startswith("sha256:")
    finally:
        scoring.clear_cache()

    monkeypatch.setattr(
        scoring,
        "self_information",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    _, detail = sira.sira_rewrite("source text", config=DewatermarkConfig())
    assert SECRET not in json.dumps(detail)


def test_detector_consent_and_unsupported_reasons_are_static(monkeypatch):
    class Detector:
        capability = CapabilityManifest(
            identifier="privacy-detector",
            kind="detector",
            schemes=("fixture",),
        )

        def available(self):
            return True

        def detect(self, _text):
            return 1.0

    monkeypatch.setattr(
        detectors,
        "require_extension",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError(SECRET)),
    )
    evidence = detectors.run_detector(Detector(), "source", config=DewatermarkConfig())
    assert evidence.status == "configuration_mismatch"
    assert evidence.reason == "detector extension requirements are not explicitly permitted"
    assert SECRET not in json.dumps(evidence.to_dict())

    unsupported = detectors.UnsupportedDetector("fixture", reason=SECRET).detect("source")
    assert unsupported.reason == "No public, independently usable detector is available."
    assert SECRET not in json.dumps(unsupported.to_dict())
