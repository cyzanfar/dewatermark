#!/usr/bin/env python3
"""Run content-redacting golden conformance against the pinned KGW checkout."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
from typing import Any


def _load_adapter(directory: Path) -> Any:
    spec = importlib.util.spec_from_file_location(
        "_dewatermark_kgw_adapter", directory / "adapter.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("adapter module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(upstream_dir: Path, pack_dir: Path) -> dict[str, Any]:
    adapter = _load_adapter(pack_dir)
    configuration = adapter._load_configuration(pack_dir / "adapter-config.json")
    vector_bytes = (pack_dir / "fixture-cases.json").read_bytes()
    bundle = json.loads(vector_bytes.decode("utf-8"))
    cases = []
    for vector in bundle["vectors"]:
        response = adapter.handle(
            {
                "protocol_version": "1.0",
                "action": "detect",
                "detector": configuration["identifier"],
                "configuration_sha256": configuration["configuration_sha256"],
                "policy": {"allow_network": False, "allow_model_download": False},
                "text": vector["text"],
            },
            configuration=configuration,
            upstream_dir=upstream_dir,
        )
        mismatches = []
        if response.get("status") != vector["expected_status"]:
            mismatches.append("status")
        if response.get("effective_tokens") != vector["expected_effective_tokens"]:
            mismatches.append("effective_tokens")
        for field in ("score", "p_value"):
            expected = vector[f"expected_{field}"]
            actual = response.get(field)
            if expected is None:
                if actual is not None:
                    mismatches.append(field)
            elif not isinstance(actual, (int, float)) or not math.isclose(
                float(actual), float(expected), rel_tol=0.0, abs_tol=1e-12
            ):
                mismatches.append(field)
        cases.append(
            {
                "name": vector["name"],
                "passed": not mismatches,
                "mismatches": sorted(mismatches),
            }
        )
    return {
        "protocol_version": "1.0",
        "configuration_sha256": configuration["configuration_sha256"],
        "vectors_sha256": hashlib.sha256(vector_bytes).hexdigest(),
        "passed": bool(cases) and all(case["passed"] for case in cases),
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path, required=True)
    args = parser.parse_args()
    pack_dir = Path(__file__).resolve().parent
    try:
        report = run(args.upstream_dir, pack_dir)
    except Exception:
        print(json.dumps({"passed": False, "error": "conformance execution failed"}))
        return 1
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
