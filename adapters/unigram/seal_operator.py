#!/usr/bin/env python3
"""Create public Unigram operator configuration without publishing its private key."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import sys
import tempfile
from pathlib import Path
from statistics import NormalDist
from typing import Any

_OPAQUE_ID = re.compile(r"[0-9a-f]{32}")


def _load_runtime(directory: Path) -> Any:
    spec = importlib.util.spec_from_file_location(
        "_dewatermark_unigram_operator_runtime", directory / "operator_adapter.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("operator runtime is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_new(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="ascii", newline="\n") as handle:
        handle.write(payload)


def _publish_pair(output: Path, configuration: Any, capability: Any, limit: int) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("operator output directory already exists")
    for value in (configuration, capability):
        encoded = (
            json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n"
        ).encode("ascii")
        if len(encoded) > limit:
            raise ValueError("operator output exceeds its runtime size limit")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".dewatermark-operator-", dir=parent))
    try:
        _write_new(staging / "operator-config.json", configuration)
        _write_new(staging / "operator-capability.json", capability)
        os.rename(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_threshold_evidence(value: Any, args: argparse.Namespace) -> None:
    threshold = NormalDist().inv_cdf(1.0 - args.alpha)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "alpha",
            "empirical_calibration",
            "evidence_id",
            "fraction",
            "minimum_effective_tokens",
            "schema_version",
            "score",
            "threshold",
            "threshold_operator",
        }
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("evidence_id"), str)
        or _OPAQUE_ID.fullmatch(value["evidence_id"]) is None
        or type(value.get("empirical_calibration")) is not bool
        or value.get("score") != "finite_population_adjusted_z_score"
        or value.get("threshold_operator") != ">"
        or value.get("threshold") != threshold
        or value.get("alpha") != args.alpha
        or value.get("fraction") != args.fraction
        or value.get("minimum_effective_tokens") != args.minimum_effective_tokens
    ):
        raise ValueError("threshold evidence is invalid")


def seal(args: argparse.Namespace) -> None:
    if (
        not args.identifier
        or not args.scheme
        or not args.tokenizer_revision
        or isinstance(args.vocab_size, bool)
        or args.vocab_size < 2
        or isinstance(args.minimum_effective_tokens, bool)
        or args.minimum_effective_tokens < 1
        or not all(math.isfinite(item) for item in (args.alpha, args.fraction, args.strength))
        or not 0.0 < args.alpha < 0.5
        or not 0.0 < args.fraction < 1.0
        or args.strength < 0.0
        or not 1 <= int(args.fraction * args.vocab_size) < args.vocab_size
        or args.minimum_effective_tokens > args.vocab_size
    ):
        raise ValueError("operator configuration is invalid")
    directory = Path(__file__).resolve().parent
    runtime = _load_runtime(directory)
    if not all(
        runtime._valid_public_identifier(item)
        for item in (args.identifier, args.scheme, args.tokenizer_revision)
    ):
        raise ValueError("operator public identifiers are invalid")
    output = args.output_dir.absolute()
    source = args.upstream_dir.absolute() / "gptwm.py"
    source_digest = runtime._sha256(
        runtime._read_regular(source, 4 * 1024 * 1024, "upstream_source_mismatch")
    )
    if source_digest != runtime.UPSTREAM_FILE_SHA256:
        raise ValueError("upstream source mismatch")
    tokenizer_files = runtime._tokenizer_snapshot(args.tokenizer_dir.absolute())
    _key, key_id = runtime._read_key_record(args.key_file)
    evidence = runtime._read_regular(
        args.threshold_evidence, 1024 * 1024, "threshold_evidence_unavailable"
    )
    try:
        evidence_value = json.loads(
            evidence.decode("utf-8"), object_pairs_hook=runtime._reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("threshold evidence is invalid") from None
    _validate_threshold_evidence(evidence_value, args)
    try:
        import numpy
        import scipy
        import tokenizers
        import torch
        import transformers
    except ImportError:
        raise ValueError("pinned runtime dependencies are unavailable") from None
    configuration = {
        "alpha": args.alpha,
        "dynamic_threshold_method": "finite_population_unique_tokens",
        "fraction": args.fraction,
        "identifier": args.identifier.strip(),
        "key_id": key_id,
        "minimum_effective_tokens": args.minimum_effective_tokens,
        "p_value_method": "one_sided_standard_normal_survival",
        "reported_z_score": "finite_population_adjusted",
        "schema_version": "1.0",
        "scheme": args.scheme.strip(),
        "score_direction": "higher",
        "strength": args.strength,
        "threshold": NormalDist().inv_cdf(1.0 - args.alpha),
        "threshold_operator": ">",
        "threshold_evidence_sha256": runtime._sha256(evidence),
        "tokenizer_files": tokenizer_files,
        "tokenizer_revision": args.tokenizer_revision.strip(),
        "tokenizer_snapshot_sha256": runtime._sha256(runtime._canonical(tokenizer_files)),
        "tokenizer_type": "transformers_local_files_v1",
        "tokenizers_version": str(tokenizers.__version__),
        "numpy_version": str(numpy.__version__),
        "scipy_version": str(scipy.__version__),
        "torch_version": str(torch.__version__),
        "transformers_version": str(transformers.__version__),
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "byteorder": sys.byteorder,
        "upstream_file_sha256": runtime.UPSTREAM_FILE_SHA256,
        "upstream_repository": "https://github.com/XuandongZhao/Unigram-Watermark",
        "upstream_revision": runtime.UPSTREAM_REVISION,
        "vocab_size": args.vocab_size,
    }
    configuration["configuration_sha256"] = runtime._sha256(runtime._canonical(configuration))
    runtime._validate_configuration(configuration)
    capability = {
        "calibrated": False,
        "description": (
            "Operator-sealed Unigram detector with a local tokenizer and out-of-band key; "
            "pending independent conformance and empirical calibration."
        ),
        "identifier": args.identifier.strip(),
        "independent": False,
        "kind": "detector",
        "metadata": {
            "calibration": "operator_evidence_present_but_not_project_validated",
            "command_protocol_version": "1.1",
            "configuration_sha256": configuration["configuration_sha256"],
            "evidence_level": "same_implementation",
            "key_id": key_id,
            "minimum_effective_tokens": args.minimum_effective_tokens,
            "secret_binding": "operator_managed_file",
            "production_detection": False,
            "score_direction": "higher",
            "threshold_operator": ">",
            "source": "https://github.com/XuandongZhao/Unigram-Watermark",
            "source_file_sha256": runtime.UPSTREAM_FILE_SHA256,
            "source_license": "MIT",
            "source_revision": runtime.UPSTREAM_REVISION,
            "status": "sealed_pending_independent_conformance_and_empirical_calibration",
            "threshold": configuration["threshold"],
            "threshold_evidence_sha256": runtime._sha256(evidence),
            "tokenizer_revision": args.tokenizer_revision.strip(),
            "tokenizer_snapshot_sha256": configuration["tokenizer_snapshot_sha256"],
            "vendor_equivalent": False,
        },
        "minimum_characters": 0,
        "model_download_possible": False,
        "network_required": False,
        "requires_secret": True,
        "schemes": [args.scheme.strip()],
        "version": "1.0",
    }
    _publish_pair(output, configuration, capability, runtime.MAX_CONFIGURATION_BYTES)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-revision", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--threshold-evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--scheme", required=True)
    parser.add_argument("--vocab-size", type=int, required=True)
    parser.add_argument("--fraction", type=float, default=0.5)
    parser.add_argument("--strength", type=float, default=2.0)
    parser.add_argument("--alpha", type=float, default=0.01)
    parser.add_argument("--minimum-effective-tokens", type=int, default=100)
    args = parser.parse_args()
    try:
        seal(args)
    except Exception:
        print(
            "operator sealing failed; paths, runtime details, and key material were redacted",
            file=sys.stderr,
        )
        return 1
    print("operator configuration sealed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
