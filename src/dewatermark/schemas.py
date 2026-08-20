"""Packaged, machine-readable public JSON schemas."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

_SCHEMA_FILES = {
    "removal-result": "removal-result-v1.json",
    "evidence-receipt": "evidence-receipt-v1.json",
    "localization-result": "localization-result-v1.json",
    "mitigation-result": "mitigation-result-v1.json",
    "mitigation-profile": "mitigation-profile-v1.json",
    "detector-capability": "detector-capability-v1.json",
    "command-detector": "command-detector-protocol-v1.json",
    "command-strategy": "command-strategy-protocol-v1.json",
    "benchmark-evidence-bundle": "benchmark-evidence-bundle-v1.json",
    "benchmark-comparator-registry": "benchmark-comparator-registry-v1.json",
    "benchmark-protocol-manifest": "benchmark-protocol-manifest-v1.json",
    "benchmark-run-config": "benchmark-run-config-v1.json",
    "benchmark-input-corpus": "benchmark-input-corpus-v1.json",
    "benchmark-observation-set": "benchmark-observation-set-v1.json",
    "benchmark-replication-record": "benchmark-replication-record-v1.json",
    "benchmark-sample-registry": "benchmark-sample-registry-v1.json",
    "openapi": "openapi-v1.json",
}


def public_schema(name: str) -> dict[str, Any]:
    """Return one checked-in schema from source or an installed distribution."""
    try:
        filename = _SCHEMA_FILES[name]
    except KeyError:
        choices = ", ".join(sorted(_SCHEMA_FILES))
        raise ValueError(f"unknown schema; choose one of: {choices}") from None
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


def localization_result_schema() -> dict[str, Any]:
    return public_schema("localization-result")


def mitigation_result_schema() -> dict[str, Any]:
    return public_schema("mitigation-result")


def mitigation_profile_schema() -> dict[str, Any]:
    return public_schema("mitigation-profile")


def detector_capability_schema() -> dict[str, Any]:
    return public_schema("detector-capability")


def command_detector_schema() -> dict[str, Any]:
    return public_schema("command-detector")


def command_strategy_schema() -> dict[str, Any]:
    return public_schema("command-strategy")


def benchmark_evidence_bundle_schema() -> dict[str, Any]:
    return public_schema("benchmark-evidence-bundle")


def benchmark_comparator_registry_schema() -> dict[str, Any]:
    return public_schema("benchmark-comparator-registry")


def benchmark_protocol_manifest_schema() -> dict[str, Any]:
    return public_schema("benchmark-protocol-manifest")


def benchmark_run_config_schema() -> dict[str, Any]:
    return public_schema("benchmark-run-config")


def benchmark_input_corpus_schema() -> dict[str, Any]:
    return public_schema("benchmark-input-corpus")


def benchmark_observation_set_schema() -> dict[str, Any]:
    return public_schema("benchmark-observation-set")


def benchmark_replication_record_schema() -> dict[str, Any]:
    return public_schema("benchmark-replication-record")


def benchmark_sample_registry_schema() -> dict[str, Any]:
    return public_schema("benchmark-sample-registry")


def openapi_document() -> dict[str, Any]:
    """Return the checked-in OpenAPI 3.1 transport contract."""
    return public_schema("openapi")
