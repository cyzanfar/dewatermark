import hashlib
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import dewatermark.server as server_module
from dewatermark.assurance_api import (
    ConsentRequiredError,
    PlanMismatchError,
    apply_plan,
    create_plan,
    inspect_text,
    verify_text,
)
from dewatermark.config import DewatermarkConfig, configure, reset_config
from dewatermark.models import CapabilityManifest
from dewatermark.providers import (
    register_detector,
    register_provider,
    unregister_detector,
    unregister_provider,
)
from dewatermark.server import (
    DewatermarkHandler,
    _is_json_content_type,
    _validate_origins,
    openapi_schema,
    process_request,
    serve,
)


def test_openapi_has_routes():
    schema = openapi_schema()
    paths = schema["paths"]
    assert {
        "/inspect",
        "/plan",
        "/apply",
        "/verify",
        "/localize",
        "/mitigate",
        "/sanitize",
    } <= set(paths)
    assert paths["/apply"]["post"]["operationId"] == "applyTransformation"
    assert schema["security"] == [{"bearerAuth": []}, {}]


def test_http_detector_guided_localization_and_mitigation_are_bounded_and_consent_gated():
    source = "alpha blue beta blue gamma blue delta epsilon zeta eta theta"

    def detector_capability(identifier):
        return CapabilityManifest(
            identifier=identifier,
            kind="detector",
            schemes=("http-search-fixture",),
            calibrated=True,
            independent=True,
            metadata={
                "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
                "resource_accounting": "none",
                "score_direction": "higher",
                "threshold": 2.0,
                "threshold_operator": ">=",
                "watermark_target_sha256": "e" * 64,
            },
        )

    class Primary:
        capability = detector_capability("http-search-primary")

        def __init__(self, _config=None):
            pass

        def available(self):
            return True

        def detect(self, text):
            score = float(text.count("blue"))
            start = text.find("blue")
            return {
                "scheme": "http-search-fixture",
                "status": "detected" if score >= 2 else "not_detected",
                "score": score,
                "threshold": 2.0,
                "score_direction": "higher",
                "p_value": 0.001 if score >= 2 else 0.8,
                "localization": ([{"start": start, "end": start + 4}] if start >= 0 else []),
            }

    class Verifier(Primary):
        capability = detector_capability("http-search-verifier")

        def detect(self, text):
            score = float(sum(token == "blue" for token in text.split()))
            start = text.find("blue")
            return {
                "scheme": "http-search-fixture",
                "status": "detected" if score >= 2 else "not_detected",
                "score": score,
                "threshold": 2.0,
                "score_direction": "higher",
                "p_value": 0.001 if score >= 2 else 0.8,
                "localization": ([{"start": start, "end": start + 4}] if start >= 0 else []),
            }

    class Strategy:
        capability = CapabilityManifest(
            identifier="http-search-strategy",
            kind="transformer",
            metadata={"resource_accounting": "none"},
        )
        constructed = 0

        def __init__(self, _config):
            type(self).constructed += 1

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text.replace("blue", "teal", 2), {}

    register_detector("http-search-primary", Primary)
    register_detector("http-search-verifier", Verifier)
    register_provider("http-search-strategy", Strategy)
    try:
        localized = process_request(
            "/localize", {"text": source, "detector": "http-search-primary"}
        )
        assert localized["status"] == "localized_exploratory"
        assert localized["spans"] == [{"start": 6, "end": 10, "contributing_windows": 1}]
        assert source not in str(localized)

        request = {
            "text": source,
            "detector": "http-search-primary",
            "verifiers": ["http-search-verifier"],
            "strategies": ["http-search-strategy"],
            "consent": {"transformation": False},
        }
        with pytest.raises(ConsentRequiredError):
            process_request("/mitigate", request)
        assert Strategy.constructed == 0

        request["consent"] = {"transformation": True}
        mitigated = process_request("/mitigate", request)
        assert mitigated["status"] == "verified"
        assert mitigated["cleaned_text"] == source.replace("blue", "teal", 2)
        assert source not in str(mitigated["receipt"])
    finally:
        unregister_detector("http-search-primary")
        unregister_detector("http-search-verifier")
        unregister_provider("http-search-strategy")


def test_checked_in_openapi_snapshot_is_current():
    root = Path(__file__).parents[1]
    completed = subprocess.run(
        [sys.executable, "scripts/export_openapi.py"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_process_sanitize_without_network():
    result = process_request("/sanitize", {"text": "he\u200bllo"})
    assert result == {"cleaned_text": "hello", "changed": True}


def test_external_bind_requires_key(monkeypatch):
    monkeypatch.delenv("DEWATERMARK_SERVER_API_KEY", raising=False)
    with pytest.raises(ValueError, match="requires"):
        serve("0.0.0.0", 8765)


def test_plan_apply_and_verify_are_content_bound():
    planned = process_request("/plan", {"text": "he\u200bllo", "mode": "sanitize"})
    assert planned["consent_required"] is True
    with pytest.raises(ConsentRequiredError):
        process_request(
            "/apply",
            {
                "text": "he\u200bllo",
                "mode": "sanitize",
                "plan_digest": planned["plan_digest"],
                "consent": {"transformation": False},
            },
        )
    with pytest.raises(PlanMismatchError):
        process_request(
            "/apply",
            {
                "text": "different",
                "mode": "sanitize",
                "plan_digest": planned["plan_digest"],
                "consent": {"transformation": True},
            },
        )
    applied = process_request(
        "/apply",
        {
            "text": "he\u200bllo",
            "mode": "sanitize",
            "plan_digest": planned["plan_digest"],
            "consent": {"transformation": True},
        },
    )
    assert applied["result"]["cleaned_text"] == "hello"
    verified = process_request("/verify", {"source_text": "he\u200bllo", "candidate_text": "hello"})
    assert verified["verification_status"] == "verified_cleared"
    unsupported = process_request(
        "/verify",
        {
            "source_text": "source",
            "candidate_text": "candidate",
            "detector": "anthropic-claude",
        },
    )
    assert unsupported["verification_status"] == "not_verifiable"
    assert unsupported["detection_status"] == "unsupported"

    anthropic_plan = process_request(
        "/plan",
        {"text": "plain source", "mode": "sanitize", "detector": "anthropic-claude"},
    )
    anthropic_apply = process_request(
        "/apply",
        {
            "text": "plain source",
            "mode": "sanitize",
            "detector": "anthropic-claude",
            "plan_digest": anthropic_plan["plan_digest"],
            "consent": {"transformation": True},
        },
    )
    report = anthropic_apply["result"]["report"]
    assert report["detection_status"] == "unsupported"
    assert report["verification_status"] == "not_verifiable"


@pytest.mark.parametrize(
    "options",
    [
        {"passes": 0},
        {"passes": True},
        {"passes": 1.5},
        {"epsilon": 99},
        {"epsilon": "0.3"},
        {"beta": -1},
        {"best_of": 7},
        {"best_of": False},
    ],
)
def test_plan_rejects_options_that_apply_cannot_execute(options):
    with pytest.raises(ValueError):
        process_request("/plan", {"text": "private source", "mode": "sanitize", "options": options})


def test_plan_normalizes_defaults_and_equivalent_numeric_options():
    implicit = process_request("/plan", {"text": "private source", "mode": "sanitize"})
    explicit = process_request(
        "/plan",
        {
            "text": "private source",
            "mode": "sanitize",
            "options": {"passes": 2, "epsilon": 0.3, "beta": 6, "best_of": 3},
        },
    )

    assert implicit["options"] == {
        "passes": 2,
        "epsilon": 0.3,
        "beta": 6.0,
        "best_of": 3,
    }
    assert explicit["options"] == implicit["options"]
    assert explicit["plan_digest"] == implicit["plan_digest"]


def test_http_contract_rejects_unknown_top_level_and_nested_fields():
    with pytest.raises(ValueError, match="unsupported fields"):
        process_request("/plan", {"text": "private source", "unexpected": True})
    with pytest.raises(ValueError, match="unsupported removal option"):
        process_request(
            "/plan",
            {"text": "private source", "options": {"passes": 2, "unexpected": True}},
        )

    planned = process_request("/plan", {"text": "private source", "mode": "sanitize"})
    with pytest.raises(ValueError, match="unsupported fields"):
        process_request(
            "/apply",
            {
                "text": "private source",
                "mode": "sanitize",
                "plan_digest": planned["plan_digest"],
                "consent": {"transformation": True, "unexpected": True},
            },
        )


def test_plan_binds_verification_policy_and_redacted_config():
    first_config = DewatermarkConfig(
        random_seed=7,
        local_lm="/private/models/local",
        llm_api_key="do-not-serialize",
    )
    planned = create_plan(
        "a\u200bb",
        "sanitize",
        require_verified=True,
        config=first_config,
    )
    assert planned["policy"]["config"]["require_verified"] is True
    assert planned["policy"]["config"]["local_model"].startswith("sha256:")
    assert "do-not-serialize" not in str(planned)
    with pytest.raises(PlanMismatchError, match="policy"):
        apply_plan(
            "a\u200bb",
            planned["plan_digest"],
            "sanitize",
            consent=True,
            require_verified=True,
            config=DewatermarkConfig(random_seed=8, local_lm="/private/models/local"),
        )


def test_agent_operations_enforce_configured_input_limit():
    config = DewatermarkConfig(max_input_chars=3)
    with pytest.raises(ValueError, match="max_input_chars"):
        inspect_text("four", config=config)
    with pytest.raises(ValueError, match="max_input_chars"):
        create_plan("four", "sanitize", config=config)
    with pytest.raises(ValueError, match="max_input_chars"):
        verify_text("four", "ok", config=config)


def test_legacy_http_remove_forces_local_only_policy(monkeypatch):
    observed = {}

    def fake_remove(_text, **kwargs):
        observed.update(kwargs)
        return SimpleNamespace(to_dict=lambda: {"ok": True})

    monkeypatch.setattr(server_module, "remove", fake_remove)
    configure(fireworks_api_key="secret-one", llm_api_key="secret-two")
    try:
        assert process_request("/remove", {"text": "data"}) == {"ok": True}
    finally:
        reset_config()
    config = observed["config"]
    assert config.allow_remote_processing is False
    assert config.allow_model_download is False
    assert config.fireworks_api_key is None
    assert config.llm_api_key is None
    assert config.rewriter_provider is None


def test_http_transport_rejects_cross_origin_and_non_json():
    assert not _is_json_content_type("")
    assert not _is_json_content_type("text/plain")
    assert _is_json_content_type("application/json; charset=utf-8")
    assert _validate_origins(["https://trusted.example/"], "origins") == (
        "https://trusted.example",
    )
    with pytest.raises(ValueError, match="without paths or credentials"):
        _validate_origins(["https://user:secret@trusted.example/path"], "origins")

    handler = object.__new__(DewatermarkHandler)
    handler.allowed_origins = frozenset({"https://trusted.example"})
    handler.api_key = None
    handler.bound_port = 8765
    handler.headers = {"Origin": "https://evil.example", "Host": "127.0.0.1:8765"}
    assert handler._origin_allowed() is False
    assert handler._host_allowed() is True
    handler.headers = {"Origin": "https://trusted.example", "Host": "127.0.0.1:8765"}
    assert handler._origin_allowed() is True
    handler.headers = {"Origin": "http://127.0.0.1:8765", "Host": "127.0.0.1:8765"}
    assert handler._origin_allowed() is True
    handler.headers = {"Origin": "http://evil.example:8765", "Host": "evil.example:8765"}
    assert handler._origin_allowed() is True
    assert handler._host_allowed() is False
