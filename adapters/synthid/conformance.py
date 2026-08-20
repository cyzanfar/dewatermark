#!/usr/bin/env python3
"""Replay the bounded public SynthID Text token-ID conformance corpus."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any

EXPECTED_VECTORS_SHA256 = "98e13668748976a8bc8885d9551202987ef6b3f336782a17dc7d2515825fe920"


def _load_runtime(directory: Path) -> Any:
    spec = importlib.util.spec_from_file_location(
        "_dewatermark_synthid_operator_runtime", directory / "operator_adapter.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("operator runtime is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def run(directory: Path | None = None) -> dict[str, Any]:
    root = directory or Path(__file__).resolve().parent
    runtime = _load_runtime(root)
    raw = runtime._read_regular(root / "fixture-cases.json", 1024 * 1024, "fixtures_unavailable")
    if hashlib.sha256(raw).hexdigest() != EXPECTED_VECTORS_SHA256:
        raise ValueError("fixtures_invalid")
    try:
        fixture = json.loads(raw.decode("ascii"), object_pairs_hook=runtime._reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("fixtures_invalid") from None
    if (
        not isinstance(fixture, dict)
        or set(fixture)
        != {
            "attribution_case",
            "cases",
            "description",
            "reference_validation",
            "schema_version",
            "upstream_revision",
        }
        or fixture.get("schema_version") != "1.0"
        or fixture.get("upstream_revision") != runtime.UPSTREAM_REVISION
        or sys.byteorder != "little"
        or not isinstance(fixture.get("cases"), list)
        or not 1 <= len(fixture["cases"]) <= 64
        or fixture.get("reference_validation")
        != {
            "byteorder": "little",
            "scope": "g_values_and_repetition_eos_masks",
            "status": "reproducible_pinned_upstream_record",
            "torch_version": "2.4.0",
            "transformers_version": "4.43.3",
        }
    ):
        raise ValueError("fixtures_invalid")
    ids: list[str] = []
    results: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for case in fixture["cases"]:
        if not isinstance(case, dict) or set(case) != {
            "context_history_size",
            "detector_type",
            "eos_token_id",
            "expected_effective_tokens",
            "expected_g_values",
            "expected_mask",
            "expected_score",
            "fixture_id",
            "keys",
            "ngram_len",
            "token_ids",
            "weights",
        }:
            raise ValueError("fixtures_invalid")
        result = runtime.score_token_ids(
            case["token_ids"],
            keys=case["keys"],
            ngram_len=case["ngram_len"],
            context_history_size=case["context_history_size"],
            eos_token_id=case["eos_token_id"],
            detector_type=case["detector_type"],
            weights=case["weights"],
        )
        if (
            not runtime._valid_public_identifier(case.get("fixture_id"))
            or result["effective_tokens"] != case["expected_effective_tokens"]
            or result["g_values"] != case["expected_g_values"]
            or result["mask"] != case["expected_mask"]
            or type(result["score"]) not in (int, float)
            or type(case["expected_score"]) not in (int, float)
            or not math.isclose(
                float(result["score"]), float(case["expected_score"]), rel_tol=0.0, abs_tol=1e-15
            )
        ):
            raise ValueError("conformance_failed")
        ids.append(case["fixture_id"])
        results[case["fixture_id"]] = (case, result)
    attribution = fixture["attribution_case"]
    if not isinstance(attribution, dict) or set(attribution) != {
        "expected_attributions",
        "fixture_id",
        "maximum_attributions",
        "offset_mapping",
        "source_fixture_id",
        "text",
    }:
        raise ValueError("fixtures_invalid")
    source = results.get(attribution.get("source_fixture_id"))
    if (
        source is None
        or not runtime._valid_public_identifier(attribution.get("fixture_id"))
        or not isinstance(attribution.get("text"), str)
        or runtime._unsafe_public_string(attribution["text"])
    ):
        raise ValueError("fixtures_invalid")
    source_case, source_result = source
    actual_attributions = runtime._attributions(
        attribution["text"],
        attribution["offset_mapping"],
        source_result,
        ngram_len=source_case["ngram_len"],
        detector_type=source_case["detector_type"],
        weights=source_case["weights"],
        maximum_attributions=attribution["maximum_attributions"],
    )
    if actual_attributions != attribution.get("expected_attributions"):
        raise ValueError("conformance_failed")
    ids.append(attribution["fixture_id"])
    if len(ids) != len(set(ids)):
        raise ValueError("fixtures_invalid")
    report = {
        "case_count": len(ids),
        "fixture_ids_sha256": hashlib.sha256(_canonical(ids)).hexdigest(),
        "implementation_sha256": hashlib.sha256(
            (root / "operator_adapter.py").read_bytes()
        ).hexdigest(),
        "passed": True,
        "schema_version": "1.0",
        "scorer_semantics": runtime.SCORER_SEMANTICS,
        "source_files_sha256": runtime.UPSTREAM_SOURCE_SHA256,
        "upstream_revision": runtime.UPSTREAM_REVISION,
        "vectors_sha256": EXPECTED_VECTORS_SHA256,
    }
    report["report_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report


def main() -> int:
    try:
        report = run()
    except Exception:
        print("SynthID conformance failed; details were redacted")
        return 1
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
