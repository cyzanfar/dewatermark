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
from dewatermark.server import (
    DewatermarkHandler,
    _is_json_content_type,
    _validate_origins,
    openapi_schema,
    process_request,
    serve,
)


def test_openapi_has_routes():
    paths = openapi_schema()["paths"]
    assert {"/inspect", "/plan", "/apply", "/verify", "/sanitize"} <= set(paths)
    assert paths["/apply"]["post"]["operationId"] == "applyTransformation"


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
