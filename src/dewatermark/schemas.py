"""Packaged, machine-readable public JSON schemas."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

_SCHEMA_FILES = {
    "removal-result": "removal-result-v1.json",
    "evidence-receipt": "evidence-receipt-v1.json",
    "detector-capability": "detector-capability-v1.json",
    "command-detector": "command-detector-protocol-v1.json",
}


def public_schema(name: str) -> dict[str, Any]:
    """Return one checked-in schema from source or an installed distribution."""
    try:
        filename = _SCHEMA_FILES[name]
    except KeyError:
        choices = ", ".join(sorted(_SCHEMA_FILES))
        raise ValueError(f"unknown schema {name!r}; choose one of: {choices}") from None
    packaged = files("dewatermark").joinpath("data").joinpath("schemas").joinpath(filename)
    try:
        payload = packaged.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Direct source checkouts use the canonical repository directory. The
        # build maps that same directory into dewatermark/data/schemas.
        source = Path(__file__).resolve().parents[2] / "schemas" / filename
        payload = source.read_text(encoding="utf-8")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise RuntimeError(f"packaged schema {filename} is not a JSON object")
    return value


def removal_result_schema() -> dict[str, Any]:
    return public_schema("removal-result")


def evidence_receipt_schema() -> dict[str, Any]:
    return public_schema("evidence-receipt")


def detector_capability_schema() -> dict[str, Any]:
    return public_schema("detector-capability")


def command_detector_schema() -> dict[str, Any]:
    return public_schema("command-detector")
