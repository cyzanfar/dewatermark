#!/usr/bin/env python3
"""Replay public fixtures against the exact pinned DeepMind implementation offline."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any

TORCH_VERSION = "2.4.0"
TRANSFORMERS_VERSION = "4.43.3"
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("upstream conformance dependency is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_verified_upstream(runtime: Any, upstream_dir: Path) -> Any:
    runtime._verify_sources(upstream_dir)
    root = upstream_dir / "src" / "synthid_text"
    hashing = _load_module(root / "hashing_function.py", "_synthid_verified_hashing")
    package = types.ModuleType("synthid_text")
    package.hashing_function = hashing
    previous_package = sys.modules.get("synthid_text")
    previous_hashing = sys.modules.get("synthid_text.hashing_function")
    sys.modules["synthid_text"] = package
    sys.modules["synthid_text.hashing_function"] = hashing
    try:
        return _load_module(root / "logits_processing.py", "_synthid_verified_logits")
    finally:
        if previous_package is None:
            sys.modules.pop("synthid_text", None)
        else:
            sys.modules["synthid_text"] = previous_package
        if previous_hashing is None:
            sys.modules.pop("synthid_text.hashing_function", None)
        else:
            sys.modules["synthid_text.hashing_function"] = previous_hashing


def _read_json(runtime: Any, path: Path, limit: int, reason: str) -> Any:
    raw = runtime._read_regular(path, limit, reason)
    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=runtime._reject_duplicate_keys,
            parse_constant=runtime._reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError(reason) from None


def run(upstream_dir: Path, directory: Path | None = None) -> dict[str, Any]:
    root = directory or Path(__file__).resolve().parent
    runtime = _load_module(root / "operator_adapter.py", "_synthid_upstream_runtime")
    conformance = _load_module(root / "conformance.py", "_synthid_portable_conformance")
    portable = conformance.run(root)
    if sys.byteorder != "little":
        raise ValueError("upstream conformance requires little-endian signed-int64 semantics")
    try:
        import torch
        import transformers
    except ImportError:
        raise ValueError("pinned upstream runtime is unavailable") from None
    if (
        str(torch.__version__) != TORCH_VERSION
        or str(transformers.__version__) != TRANSFORMERS_VERSION
    ):
        raise ValueError("pinned upstream runtime does not match")
    official = _load_verified_upstream(runtime, upstream_dir.absolute())
    fixture = _read_json(
        runtime, root / "fixture-cases.json", MAX_FIXTURE_BYTES, "fixtures_invalid"
    )
    cases = fixture.get("cases") if isinstance(fixture, dict) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("fixtures_invalid")
    fixture_ids: list[str] = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("fixtures_invalid")
        processor = official.SynthIDLogitsProcessor(
            ngram_len=case["ngram_len"],
            keys=case["keys"],
            context_history_size=case["context_history_size"],
            temperature=1.0,
            top_k=2,
            device=torch.device("cpu"),
        )
        token_ids = torch.tensor([case["token_ids"]], dtype=torch.long, device="cpu")
        g_values = processor.compute_g_values(token_ids).tolist()[0]
        repetition = processor.compute_context_repetition_mask(token_ids)
        eos = processor.compute_eos_token_mask(token_ids, case["eos_token_id"])
        eos = eos[:, case["ngram_len"] - 1 :]
        mask = torch.logical_and(repetition, eos.to(dtype=torch.bool)).to(dtype=torch.long)
        if g_values != case["expected_g_values"] or mask.tolist()[0] != case["expected_mask"]:
            raise ValueError("upstream_conformance_failed")
        fixture_id = case.get("fixture_id")
        if not runtime._valid_public_identifier(fixture_id):
            raise ValueError("fixtures_invalid")
        fixture_ids.append(fixture_id)
    report = {
        "byteorder": "little",
        "case_count": len(fixture_ids),
        "fixture_ids_sha256": runtime._sha256(runtime._canonical(fixture_ids)),
        "passed": True,
        "portable_report_sha256": portable["report_sha256"],
        "schema_version": "1.0",
        "scope": "g_values_and_repetition_eos_masks",
        "source_files_sha256": runtime.UPSTREAM_SOURCE_SHA256,
        "torch_version": TORCH_VERSION,
        "transformers_version": TRANSFORMERS_VERSION,
        "upstream_revision": runtime.UPSTREAM_REVISION,
        "vectors_sha256": conformance.EXPECTED_VECTORS_SHA256,
    }
    report["report_sha256"] = runtime._sha256(runtime._canonical(report))
    expected = _read_json(
        runtime,
        root / "upstream-conformance-record.json",
        MAX_RECORD_BYTES,
        "upstream_record_invalid",
    )
    if report != expected:
        raise ValueError("upstream_record_mismatch")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.upstream_dir)
    except Exception:
        print("SynthID upstream conformance failed; details were redacted", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
