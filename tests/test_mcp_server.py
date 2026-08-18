import asyncio
import hashlib

import pytest

from dewatermark.mcp_server import (
    analyze_text,
    apply_transformation,
    create_mcp_server,
    get_capabilities,
    localize_for_agent,
    mitigate_for_agent,
    plan_removal,
    plan_transformation,
    sanitize_text,
)
from dewatermark.models import CapabilityManifest
from dewatermark.providers import (
    register_detector,
    register_provider,
    unregister_detector,
    unregister_provider,
)
from dewatermark.schemas import localization_result_schema, mitigation_result_schema
from dewatermark.server import process_request

_SOURCE = "alpha blue beta blue gamma delta epsilon zeta eta theta"


def _detector_capability(identifier):
    return CapabilityManifest(
        identifier=identifier,
        kind="detector",
        schemes=("mcp-search-fixture",),
        calibrated=True,
        independent=True,
        metadata={
            "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
            "resource_accounting": "none",
            "score_direction": "higher",
            "threshold": 2.0,
            "threshold_operator": ">=",
            "watermark_target_sha256": "d" * 64,
        },
    )


class _PrimaryDetector:
    capability = _detector_capability("mcp-search-primary")

    def __init__(self, _config=None):
        pass

    def available(self):
        return True

    def detect(self, text):
        score = float(text.count("blue"))
        start = text.find("blue")
        return {
            "scheme": "mcp-search-fixture",
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "p_value": 0.001 if score >= 2 else 0.8,
            "localization": ([{"start": start, "end": start + 4}] if start >= 0 else []),
        }


class _VerifierDetector(_PrimaryDetector):
    capability = _detector_capability("mcp-search-verifier")

    def detect(self, text):
        score = float(sum(token == "blue" for token in text.split()))
        start = text.find("blue")
        return {
            "scheme": "mcp-search-fixture",
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "p_value": 0.001 if score >= 2 else 0.8,
            "localization": ([{"start": start, "end": start + 4}] if start >= 0 else []),
        }


class _Strategy:
    capability = CapabilityManifest(
        identifier="mcp-search-strategy",
        kind="transformer",
        metadata={"resource_accounting": "none"},
    )
    constructed = 0

    def __init__(self, _config):
        type(self).constructed += 1

    def available(self):
        return True

    def rewrite(self, text, **_options):
        return text.replace("blue", "teal", 2), {"status": "candidate"}


def _register_search_fixtures():
    register_detector("mcp-search-primary", _PrimaryDetector)
    register_detector("mcp-search-verifier", _VerifierDetector)
    register_provider("mcp-search-strategy", _Strategy)


def _unregister_search_fixtures():
    unregister_detector("mcp-search-primary")
    unregister_detector("mcp-search-verifier")
    unregister_provider("mcp-search-strategy")


def test_pure_mcp_tools():
    assert sanitize_text("he\u200bllo")["cleaned_text"] == "hello"
    assert analyze_text("plain")["unicode"]["total_flags"] == 0
    assert plan_removal("sanitize")["available"] is True
    assert "modes" in get_capabilities()


def test_mcp_and_http_plan_defaults_are_digest_compatible():
    text = "a\u200bb"
    http_plan = process_request("/plan", {"text": text, "mode": "sanitize"})
    mcp_plan = plan_transformation(text, mode="sanitize")

    assert mcp_plan == http_plan
    applied = apply_transformation(
        text,
        http_plan["plan_digest"],
        mode="sanitize",
        consent=True,
    )
    assert applied["plan_digest"] == http_plan["plan_digest"]
    assert applied["result"]["cleaned_text"] == "ab"


def test_mcp_rejects_invalid_plan_options_as_input_errors():
    with pytest.raises(ValueError, match="planning request is invalid"):
        plan_transformation("private source", mode="sanitize", passes=0)


def test_mcp_localization_and_mitigation_are_bounded_and_consent_aware():
    _Strategy.constructed = 0
    _register_search_fixtures()
    try:
        localized = localize_for_agent(_SOURCE, "mcp-search-primary")
        assert localized["status"] == "localized_exploratory"
        assert localized["spans"][0]["start"] == 6
        assert _SOURCE not in str(localized)

        with pytest.raises(PermissionError, match="consent"):
            mitigate_for_agent(
                _SOURCE,
                "mcp-search-primary",
                ["mcp-search-verifier"],
                ["mcp-search-strategy"],
            )
        assert _Strategy.constructed == 0

        result = mitigate_for_agent(
            _SOURCE,
            "mcp-search-primary",
            ["mcp-search-verifier"],
            ["mcp-search-strategy"],
            consent=True,
        )
        assert result["status"] == "verified"
        assert result["cleaned_text"] == _SOURCE.replace("blue", "teal", 2)
        assert _SOURCE not in str(result["receipt"])
    finally:
        _unregister_search_fixtures()


def test_mcp_detector_tools_reject_non_boolean_permission_values():
    with pytest.raises(ValueError, match="allow_network must be true or false"):
        localize_for_agent(
            "private source",
            "unicode",
            allow_network="false",  # type: ignore[arg-type]
        )


def test_official_mcp_transport_inspect_plan_apply_verify():
    try:
        from mcp.shared.memory import create_connected_server_and_client_session
    except ImportError:
        return

    async def exercise():
        async with create_connected_server_and_client_session(create_mcp_server()) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            assert {"inspect", "plan", "apply", "verify", "localize", "mitigate"} <= names
            plan_tool = next(tool for tool in listed.tools if tool.name == "plan")
            assert plan_tool.inputSchema["properties"]["require_verified"]["default"] is False
            assert plan_tool.annotations is not None
            assert plan_tool.annotations.readOnlyHint is True
            apply_tool = next(tool for tool in listed.tools if tool.name == "apply")
            assert apply_tool.annotations is not None
            assert apply_tool.annotations.openWorldHint is True
            localize_tool = next(tool for tool in listed.tools if tool.name == "localize")
            assert localize_tool.annotations is not None
            assert localize_tool.annotations.readOnlyHint is False
            assert localize_tool.annotations.openWorldHint is True
            assert localize_tool.inputSchema["additionalProperties"] is False
            assert localize_tool.inputSchema["properties"]["window_characters"]["minimum"] == 32
            assert (
                localize_tool.inputSchema["properties"]["max_detector_queries"]["anyOf"][0][
                    "maximum"
                ]
                == 100000
            )
            assert localize_tool.outputSchema == localization_result_schema()
            mitigate_tool = next(tool for tool in listed.tools if tool.name == "mitigate")
            assert mitigate_tool.inputSchema["additionalProperties"] is False
            assert mitigate_tool.inputSchema["properties"]["verifiers"]["minItems"] == 1
            assert mitigate_tool.inputSchema["properties"]["strategies"]["maxItems"] == 32
            assert mitigate_tool.inputSchema["properties"]["max_rounds"]["maximum"] == 32
            assert mitigate_tool.outputSchema == mitigation_result_schema()

            inspected = await session.call_tool("inspect", {"text": "a\u200bb"})
            assert not inspected.isError
            assert inspected.structuredContent is not None
            inspect_payload = inspected.structuredContent
            assert inspect_payload["unicode"]["total_flags"] == 1

            options = {
                "text": "a\u200bb",
                "mode": "sanitize",
                "passes": 2,
                "epsilon": 0.3,
                "beta": 6.0,
                "best_of": 3,
            }
            planned = await session.call_tool("plan", options)
            plan_payload = planned.structuredContent
            applied = await session.call_tool(
                "apply",
                {**options, "plan_digest": plan_payload["plan_digest"], "consent": True},
            )
            apply_payload = applied.structuredContent
            assert apply_payload["result"]["cleaned_text"] == "ab"
            verified = await session.call_tool(
                "verify", {"source_text": "a\u200bb", "candidate_text": "ab"}
            )
            verify_payload = verified.structuredContent
            assert verify_payload["verification_status"] == "verified_cleared"

    asyncio.run(exercise())
