import asyncio

import pytest

from dewatermark.mcp_server import (
    analyze_text,
    apply_transformation,
    create_mcp_server,
    get_capabilities,
    plan_removal,
    plan_transformation,
    sanitize_text,
)
from dewatermark.server import process_request


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
            assert {"inspect", "plan", "apply", "verify"} <= names
            plan_tool = next(tool for tool in listed.tools if tool.name == "plan")
            assert plan_tool.inputSchema["properties"]["require_verified"]["default"] is False
            assert plan_tool.annotations is not None
            assert plan_tool.annotations.readOnlyHint is True
            apply_tool = next(tool for tool in listed.tools if tool.name == "apply")
            assert apply_tool.annotations is not None
            assert apply_tool.annotations.openWorldHint is True

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
