"""MCP tools for local, consent-aware text watermark processing."""

from __future__ import annotations

from importlib import import_module

from . import analyze, capabilities, plan, remove, sanitize


def analyze_text(text: str) -> dict:
    return analyze(text)


def sanitize_text(text: str, profile: str = "safe") -> dict:
    cleaned = sanitize(text, profile=profile)  # type: ignore[arg-type]
    return {"cleaned_text": cleaned, "changed": cleaned != text, "profile": profile}


def plan_removal(mode: str = "auto") -> dict:
    return plan(mode).to_dict()  # type: ignore[arg-type]


def get_capabilities() -> dict:
    """Describe installed backends and limits without loading a model or using a network."""
    return capabilities()


def remove_watermark(text: str, mode: str = "sanitize") -> dict:
    """Remove with a local/offline-safe default; remote use requires env consent."""
    return remove(text, mode=mode).to_dict()  # type: ignore[arg-type]


def main() -> None:
    try:
        MCPServer = import_module("mcp.server").MCPServer
    except ImportError as exc:
        raise SystemExit(
            'Install the agent extra first: pip install "dewatermark[agents]"'
        ) from exc
    mcp = MCPServer("dewatermark")
    for tool in (analyze_text, sanitize_text, plan_removal, get_capabilities, remove_watermark):
        mcp.tool()(tool)
    mcp.run()


if __name__ == "__main__":
    main()
