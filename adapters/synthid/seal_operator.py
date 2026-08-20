#!/usr/bin/env python3
"""Seal a public SynthID Text research detector without publishing its keys."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import platform
import secrets
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("pack runtime is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_new(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="ascii", newline="\n") as handle:
        handle.write(payload)


def _write_owner_only_new(path: Path, value: Any, limit: int) -> None:
    payload = (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("ascii")
    if len(payload) > limit or path.exists() or path.is_symlink():
        raise ValueError("private binding output is invalid")
    descriptor = -1
    created = False
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags, 0o600)
        created = True
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _publish_seal(
    output: Path,
    binding_output: Path,
    configuration: Any,
    capability: Any,
    binding: Any,
    public_limit: int,
    private_limit: int,
) -> None:
    output = output.absolute()
    binding_output = binding_output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("operator output directory already exists")
    if binding_output.exists() or binding_output.is_symlink():
        raise ValueError("private binding output already exists")
    if output == binding_output or output in binding_output.parents:
        raise ValueError("private binding must be outside the public output directory")
    if (
        not binding_output.parent.is_dir()
        or binding_output.parent.is_symlink()
        or os.name != "posix"
    ):
        raise ValueError("private binding parent is unavailable")
    for value in (configuration, capability):
        encoded = (
            json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n"
        ).encode("ascii")
        if len(encoded) > public_limit:
            raise ValueError("operator output exceeds its runtime size limit")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".dewatermark-synthid-seal-", dir=parent))
    binding_created = False
    try:
        _write_new(staging / "operator-config.json", configuration)
        _write_new(staging / "operator-capability.json", capability)
        _write_owner_only_new(binding_output, binding, private_limit)
        binding_created = True
        os.rename(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if binding_created:
            try:
                binding_output.unlink()
            except OSError:
                pass
        raise


def _read_public_json(runtime: Any, path: Path, limit: int, reason: str) -> Any:
    raw = runtime._read_regular(path, limit, reason)
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=runtime._reject_duplicate_keys,
            parse_constant=runtime._reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError(reason) from None


def _validate_threshold_evidence(value: Any, args: argparse.Namespace, runtime: Any) -> None:
    expected_score = "mean_g_value" if args.detector_type == "mean" else "weighted_mean_g_value"
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "detector_type",
            "empirical_calibration",
            "evidence_id",
            "maximum_effective_tokens",
            "minimum_effective_tokens",
            "schema_version",
            "score",
            "threshold",
            "threshold_operator",
        }
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("evidence_id"), str)
        or runtime._OPAQUE_ID.fullmatch(value["evidence_id"]) is None
        or type(value.get("empirical_calibration")) is not bool
        or value.get("detector_type") != args.detector_type
        or value.get("score") != expected_score
        or value.get("threshold_operator") != ">"
        or type(value.get("threshold")) not in (int, float)
        or not math.isfinite(float(value["threshold"]))
        or value.get("threshold") != args.threshold
        or type(value.get("minimum_effective_tokens")) is not int
        or value.get("minimum_effective_tokens") != args.minimum_effective_tokens
        or type(value.get("maximum_effective_tokens")) is not int
        or value.get("maximum_effective_tokens") != args.maximum_effective_tokens
    ):
        raise ValueError("threshold evidence is invalid")


def _weights(args: argparse.Namespace, runtime: Any) -> list[float]:
    if args.detector_type == "mean":
        if args.weights_json is not None:
            raise ValueError("mean detector does not accept weights")
        return []
    if args.weights_json is None:
        if args.watermarking_depth == 1:
            return [1.0]
        step = 9.0 / (args.watermarking_depth - 1)
        return [10.0 - step * index for index in range(args.watermarking_depth)]
    value = _read_public_json(runtime, args.weights_json, 64 * 1024, "weights are invalid")
    if not runtime._valid_weights(value, "weighted_mean", args.watermarking_depth):
        raise ValueError("weights are invalid")
    return [float(item) for item in value]


def seal(args: argparse.Namespace) -> None:
    directory = Path(__file__).resolve().parent
    runtime = _load_module(directory / "operator_adapter.py", "_dewatermark_synthid_operator")
    conformance = _load_module(directory / "conformance.py", "_dewatermark_synthid_conformance")
    integer_values = (
        args.vocab_size,
        args.eos_token_id,
        args.generation_num_leaves,
        args.generation_top_k,
        args.maximum_attributions,
        args.ngram_len,
        args.context_history_size,
        args.watermarking_depth,
        args.minimum_effective_tokens,
        args.maximum_effective_tokens,
        args.maximum_input_tokens,
    )
    if (
        any(type(item) is not int for item in integer_values)
        or not 2 <= args.vocab_size <= runtime._INT64_MAX
        or not 0 <= args.eos_token_id < args.vocab_size
        or not 2 <= args.generation_num_leaves <= 64
        or not 2 <= args.generation_top_k <= args.vocab_size
        or not 1 <= args.maximum_attributions <= runtime.MAX_ATTRIBUTIONS
        or type(args.generation_temperature) not in (int, float)
        or not math.isfinite(float(args.generation_temperature))
        or args.generation_temperature <= 0.0
        or not 2 <= args.ngram_len <= 64
        or not 1 <= args.context_history_size <= runtime.MAX_CONTEXT_HISTORY_SIZE
        or not 1 <= args.watermarking_depth <= runtime.MAX_KEY_DEPTH
        or not 1
        <= args.minimum_effective_tokens
        <= args.maximum_effective_tokens
        <= args.maximum_input_tokens
        <= runtime.MAX_INPUT_TOKENS
        or args.maximum_effective_tokens > args.maximum_input_tokens - args.ngram_len + 1
        or args.maximum_attributions > args.maximum_effective_tokens
        or (
            (args.maximum_input_tokens - args.ngram_len + 1) * args.watermarking_depth
            > runtime.MAX_SCORING_CELLS
        )
        or type(args.threshold) not in (int, float)
        or not math.isfinite(float(args.threshold))
        or not 0.0 <= args.threshold <= 1.0
        or args.detector_type not in {"mean", "weighted_mean"}
        or not all(
            runtime._valid_public_identifier(item)
            for item in (args.identifier, args.scheme, args.tokenizer_revision)
        )
        or args.scheme != "synthid-text/public-reference-v1"
        or runtime._RESERVED_VENDOR_CLAIM.search(args.identifier) is not None
        or (
            args.detector_type == "mean"
            and not args.identifier.startswith("operator/synthid-text-mean")
        )
        or (
            args.detector_type == "weighted_mean"
            and not args.identifier.startswith("operator/synthid-text-weighted-mean")
        )
        or sys.byteorder != "little"
    ):
        raise ValueError("operator configuration is invalid")
    weights = _weights(args, runtime)
    runtime._verify_sources(args.upstream_dir.absolute())
    tokenizer_files = runtime._tokenizer_snapshot(args.tokenizer_dir.absolute())
    keys, key_id = runtime._read_key_record(args.key_file)
    if len(keys) != args.watermarking_depth:
        raise ValueError("operator key depth is invalid")
    evidence_raw = runtime._read_regular(
        args.threshold_evidence, 1024 * 1024, "threshold evidence is unavailable"
    )
    try:
        evidence = json.loads(
            evidence_raw.decode("utf-8"),
            object_pairs_hook=runtime._reject_duplicate_keys,
            parse_constant=runtime._reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("threshold evidence is invalid") from None
    _validate_threshold_evidence(evidence, args, runtime)
    report = conformance.run(directory)
    if report.get("passed") is not True:
        raise ValueError("public conformance failed")
    try:
        import tokenizers
        import transformers
    except ImportError:
        raise ValueError("pinned runtime dependencies are unavailable") from None
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(args.tokenizer_dir.absolute()), local_files_only=True, trust_remote_code=False
    )
    tokenizer_conformance_sha256 = runtime._tokenizer_conformance(tokenizer)
    if (
        len(tokenizer) != args.vocab_size
        or tokenizer.eos_token_id != args.eos_token_id
        or tokenizer.is_fast is not True
    ):
        raise ValueError("tokenizer does not match the declared target")
    binding_id = secrets.token_hex(16)
    if runtime._OPAQUE_ID.fullmatch(binding_id) is None:
        raise ValueError("private binding identity is invalid")
    configuration = {
        "attribution_kind": "token_character_spans",
        "byteorder": sys.byteorder,
        "context_history_size": args.context_history_size,
        "context_repetition_handling": "bounded_fifo_context_hash_v1",
        "detector_type": args.detector_type,
        "detector_text_tokenization": "retokenize_add_special_tokens_false_fast_offsets_v1",
        "eos_handling": "mask_first_eos_and_after",
        "eos_token_id": args.eos_token_id,
        "generation_apply_top_k": args.generation_apply_top_k,
        "generation_num_leaves": args.generation_num_leaves,
        "generation_skip_first_ngram_calls": args.generation_skip_first_ngram_calls,
        "generation_temperature": args.generation_temperature,
        "generation_text_serialization": (
            "tokenizer_decode_skip_special_tokens_false_cleanup_false_utf8_v1"
        ),
        "generation_top_k": args.generation_top_k,
        "identifier": args.identifier.strip(),
        "key_id": key_id,
        "maximum_effective_tokens": args.maximum_effective_tokens,
        "maximum_attributions": args.maximum_attributions,
        "maximum_input_tokens": args.maximum_input_tokens,
        "minimum_effective_tokens": args.minimum_effective_tokens,
        "ngram_len": args.ngram_len,
        "offset_mapping": "huggingface_fast_offsets_v1",
        "platform_machine": platform.machine(),
        "platform_system": platform.system(),
        "python_version": platform.python_version(),
        "schema_version": "1.0",
        "scheme": args.scheme.strip(),
        "score_direction": "higher",
        "scorer_semantics": runtime.SCORER_SEMANTICS,
        "secret_binding_id": binding_id,
        "special_token_handling": "tokenizer_add_special_tokens_false",
        "source_files_sha256": runtime.UPSTREAM_SOURCE_SHA256,
        "threshold": args.threshold,
        "threshold_evidence_sha256": runtime._sha256(evidence_raw),
        "threshold_operator": ">",
        "text_scope": "candidate_text_only_no_prompt",
        "tokenizer_conformance_sha256": tokenizer_conformance_sha256,
        "tokenizer_files": tokenizer_files,
        "tokenizer_revision": args.tokenizer_revision.strip(),
        "tokenizer_snapshot_sha256": runtime._sha256(runtime._canonical(tokenizer_files)),
        "tokenizer_type": "transformers_local_files_v1",
        "tokenizers_version": str(tokenizers.__version__),
        "transformers_version": str(transformers.__version__),
        "upstream_repository": runtime.UPSTREAM_REPOSITORY,
        "upstream_revision": runtime.UPSTREAM_REVISION,
        "vocab_size": args.vocab_size,
        "watermarking_depth": args.watermarking_depth,
        "weights": weights,
    }
    configuration["watermark_target_sha256"] = runtime._sha256(
        runtime._canonical(runtime._target_material(configuration))
    )
    configuration["configuration_sha256"] = runtime._sha256(runtime._canonical(configuration))
    runtime._validate_configuration(configuration)
    implementation_sha256 = runtime._implementation_commitment(
        port_source_sha256=report["implementation_sha256"],
        tokenizers_version=str(tokenizers.__version__),
        transformers_version=str(transformers.__version__),
    )
    capability = {
        "calibrated": False,
        "description": (
            "Operator-sealed local detector for the pinned public SynthID Text mean-score "
            "research algorithm; not a vendor production detector."
        ),
        "identifier": args.identifier.strip(),
        "independent": False,
        "kind": "detector",
        "metadata": {
            "calibration": "operator_evidence_present_but_not_project_validated",
            "attribution_kind": "token_character_spans",
            "command_protocol_version": "1.2",
            "configuration_sha256": configuration["configuration_sha256"],
            "evidence_level": "same_implementation_public_fixture",
            "golden_conformance": {
                "case_count": report["case_count"],
                "passed": True,
                "report_sha256": report["report_sha256"],
                "vectors_sha256": report["vectors_sha256"],
            },
            "implementation_sha256": implementation_sha256,
            "key_id": key_id,
            "maximum_effective_tokens": args.maximum_effective_tokens,
            "maximum_attributions": args.maximum_attributions,
            "minimum_effective_tokens": args.minimum_effective_tokens,
            "production_detection": False,
            "port_source_sha256": report["implementation_sha256"],
            "score_direction": "higher",
            "scorer_semantics": runtime.SCORER_SEMANTICS,
            "secret_binding": "operator_managed_file",
            "source": runtime.UPSTREAM_REPOSITORY,
            "source_files_sha256": runtime.UPSTREAM_SOURCE_SHA256,
            "source_license": "Apache-2.0",
            "source_revision": runtime.UPSTREAM_REVISION,
            "status": "sealed_operator_research_configuration",
            "threshold": args.threshold,
            "threshold_evidence_sha256": runtime._sha256(evidence_raw),
            "threshold_operator": ">",
            "tokenizer_revision": args.tokenizer_revision.strip(),
            "tokenizer_snapshot_sha256": configuration["tokenizer_snapshot_sha256"],
            "vendor_equivalent": False,
            "watermark_target_sha256": configuration["watermark_target_sha256"],
        },
        "minimum_characters": 0,
        "model_download_possible": False,
        "network_required": False,
        "requires_secret": True,
        "schemes": [args.scheme.strip()],
        "version": "1.0",
    }
    binding = {
        "binding_id": binding_id,
        "configuration_sha256": configuration["configuration_sha256"],
        "key_id": key_id,
        "key_material_sha256": runtime._sha256(runtime._canonical({"keys": list(keys)})),
        "schema_version": "1.0",
    }
    _publish_seal(
        args.output_dir,
        args.secret_binding_output,
        configuration,
        capability,
        binding,
        runtime.MAX_CONFIGURATION_BYTES,
        runtime.MAX_BINDING_BYTES,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-revision", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--secret-binding-output", type=Path, required=True)
    parser.add_argument("--threshold-evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--scheme", required=True)
    parser.add_argument("--vocab-size", type=int, required=True)
    parser.add_argument("--eos-token-id", type=int, required=True)
    parser.add_argument("--generation-temperature", type=float, required=True)
    parser.add_argument("--generation-top-k", type=int, required=True)
    parser.add_argument("--generation-num-leaves", type=int, default=2)
    parser.add_argument(
        "--generation-apply-top-k", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument(
        "--generation-skip-first-ngram-calls",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    parser.add_argument("--ngram-len", type=int, required=True)
    parser.add_argument("--context-history-size", type=int, required=True)
    parser.add_argument("--watermarking-depth", type=int, required=True)
    parser.add_argument("--detector-type", choices=("mean", "weighted_mean"), required=True)
    parser.add_argument("--weights-json", type=Path)
    parser.add_argument("--threshold", type=float, required=True)
    parser.add_argument("--minimum-effective-tokens", type=int, required=True)
    parser.add_argument("--maximum-effective-tokens", type=int, required=True)
    parser.add_argument("--maximum-attributions", type=int, default=256)
    parser.add_argument("--maximum-input-tokens", type=int, default=32768)
    args = parser.parse_args()
    try:
        seal(args)
    except Exception:
        print(
            "SynthID operator sealing failed; paths, runtime details, and key material were redacted",
            file=sys.stderr,
        )
        return 1
    print("SynthID operator configuration sealed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
