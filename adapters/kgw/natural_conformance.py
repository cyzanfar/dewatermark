#!/usr/bin/env python3
"""Run content-redacting conformance for the KGW natural reference profile."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
from typing import Any

NUMERIC_RELATIVE_TOLERANCE = 1e-12
NUMERIC_ABSOLUTE_TOLERANCE = 1e-15
P_VALUE_LOG_ABSOLUTE_TOLERANCE = 1e-10


def _numeric_matches(field: str, actual: Any, expected: float) -> bool:
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return False
    number = float(actual)
    if not math.isfinite(number):
        return False
    if field == "p_value":
        if number == 0.0 or expected == 0.0:
            return number == expected
        if number < 0.0 or expected < 0.0:
            return False
        return abs(math.log(number) - math.log(expected)) <= P_VALUE_LOG_ABSOLUTE_TOLERANCE
    return math.isclose(
        number,
        expected,
        rel_tol=NUMERIC_RELATIVE_TOLERANCE,
        abs_tol=NUMERIC_ABSOLUTE_TOLERANCE,
    )


def run(directory: Path) -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location(
        "_dewatermark_kgw_natural_conformance", directory / "natural_adapter.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("adapter unavailable")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    configuration = adapter._load_configuration(directory / "natural-adapter-config.json")
    vector_bytes = adapter._read_bounded(
        directory / "natural-fixture-cases.json", adapter.MAX_ARTIFACT_BYTES
    )
    vectors = json.loads(vector_bytes.decode("utf-8"))
    record_bytes = adapter._read_bounded(
        directory / "natural-conformance-record.json", adapter.MAX_ARTIFACT_BYTES
    )
    capability_bytes = adapter._read_bounded(
        directory / "natural-capability.json", adapter.MAX_ARTIFACT_BYTES
    )
    record = json.loads(record_bytes.decode("utf-8"))
    capability = json.loads(capability_bytes.decode("utf-8"))
    vector_sha256 = hashlib.sha256(vector_bytes).hexdigest()
    record_sha256 = hashlib.sha256(record_bytes).hexdigest()
    raw_metadata = capability.get("metadata", {}) if isinstance(capability, dict) else {}
    metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
    cross = metadata.get("cross_implementation_conformance", {})
    if (
        not isinstance(record, dict)
        or not isinstance(capability, dict)
        or set(record)
        != {
            "cases",
            "configuration_sha256",
            "independent_scorer",
            "numeric_absolute_tolerance",
            "numeric_relative_tolerance",
            "p_value_log_absolute_tolerance",
            "passed",
            "protocol_version",
            "upstream_implementation",
            "vectors_sha256",
        }
        or record.get("passed") is not True
        or record.get("protocol_version") != "1.1"
        or record.get("independent_scorer") != "natural_adapter.py transition-table scorer"
        or record.get("numeric_absolute_tolerance") != NUMERIC_ABSOLUTE_TOLERANCE
        or record.get("numeric_relative_tolerance") != NUMERIC_RELATIVE_TOLERANCE
        or record.get("p_value_log_absolute_tolerance") != P_VALUE_LOG_ABSOLUTE_TOLERANCE
        or record.get("upstream_implementation")
        != "https://github.com/jwkirchenbauer/lm-watermarking@82922516930c02f8aa322765defdb5863d07a00e"
        or record.get("configuration_sha256") != configuration["configuration_sha256"]
        or record.get("vectors_sha256") != vector_sha256
        or capability.get("identifier") != configuration["identifier"]
        or capability.get("schemes") != [configuration["scheme"]]
        or capability.get("calibrated") is not False
        or capability.get("independent") is not True
        or metadata.get("production_detection") is not False
        or metadata.get("calibration") != "analytical_only_not_empirically_calibrated"
        or metadata.get("status") != "exact_public_natural_reference_configuration"
        or metadata.get("evidence_level") != "independent_detector"
        or metadata.get("vendor_equivalent") is not False
        or metadata.get("upstream_equivalent_for_reference_configuration") is not True
        or metadata.get("score_direction") != configuration["score_direction"]
        or metadata.get("threshold_operator") != configuration["threshold_operator"]
        or metadata.get("threshold") != configuration["threshold"]
        or metadata.get("key_id") != configuration["key_id"]
        or metadata.get("profile_manifest_sha256") != configuration["profile_manifest_sha256"]
        or metadata.get("threshold_evidence_sha256") != configuration["threshold_evidence_sha256"]
        or metadata.get("tokenizer_sha256") != configuration["tokenizer_sha256"]
        or metadata.get("source_file_sha256") != configuration["upstream_file_sha256"]
        or metadata.get("source_revision") != configuration["upstream_revision"]
        or cross.get("passed") is not True
        or cross.get("record_sha256") != record_sha256
        or cross.get("vectors_sha256") != vector_sha256
        or metadata.get("configuration_sha256") != configuration["configuration_sha256"]
    ):
        raise ValueError("checked conformance binding mismatch")
    cases = []
    for vector in vectors["vectors"]:
        response = adapter.handle(
            {
                "action": "detect",
                "configuration_sha256": configuration["configuration_sha256"],
                "detector": configuration["identifier"],
                "policy": {"allow_model_download": False, "allow_network": False},
                "protocol_version": "1.1",
                "text": vector["text"],
            },
            configuration=configuration,
            tokenizer_path=directory / "natural-tokenizer.json",
            transitions_path=directory / "green-transitions-v1.json",
        )
        mismatches = []
        for field in ("status", "effective_tokens", "score", "p_value", "z_score"):
            expected = vector.get(f"expected_{field}")
            actual = response.get(field)
            if isinstance(expected, float):
                if not _numeric_matches(field, actual, expected):
                    mismatches.append(field)
            elif actual != expected:
                mismatches.append(field)
        cases.append(
            {"mismatches": sorted(mismatches), "name": vector["name"], "passed": not mismatches}
        )
    checked_cases = record.get("cases")
    if checked_cases != cases:
        raise ValueError("checked conformance cases mismatch")
    return {
        "cases": cases,
        "configuration_sha256": configuration["configuration_sha256"],
        "numeric_absolute_tolerance": NUMERIC_ABSOLUTE_TOLERANCE,
        "numeric_relative_tolerance": NUMERIC_RELATIVE_TOLERANCE,
        "p_value_log_absolute_tolerance": P_VALUE_LOG_ABSOLUTE_TOLERANCE,
        "passed": bool(cases) and all(case["passed"] for case in cases),
        "protocol_version": "1.1",
        "record_sha256": record_sha256,
        "vectors_sha256": vector_sha256,
    }


def main() -> int:
    try:
        report = run(Path(__file__).resolve().parent)
    except Exception:
        print(json.dumps({"error": "conformance execution failed", "passed": False}))
        return 1
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
