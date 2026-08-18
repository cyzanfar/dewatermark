#!/usr/bin/env python3
"""Offline JSON-command wrapper for one pinned upstream KGW detector.

No detector algorithm is copied here. The wrapper verifies the exact upstream
source file, loads ``WatermarkDetector`` from that local checkout, and exposes a
public token-ID fixture (``t0 t17 ...``). Natural-language use requires a
separate, tokenizer-pinned operator configuration and conformance record; this
fixture must never be presented as production KGW detection.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import sys
import types
from pathlib import Path
from typing import Any, Mapping

PROTOCOL_VERSION = "1.1"
MAX_CONFIGURATION_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
_TOKEN = re.compile(r"^t([0-9]{1,6})$")
_EXPECTED_CONFIGURATION_KEYS = {
    "configuration_sha256",
    "delta",
    "gamma",
    "hash_key",
    "identifier",
    "ignore_repeated_bigrams",
    "minimum_effective_tokens",
    "normalizers",
    "rng_device",
    "schema_version",
    "scheme",
    "seeding_scheme",
    "select_green_tokens",
    "threshold",
    "threshold_operator",
    "torch_version",
    "upstream_file_sha256",
    "upstream_repository",
    "upstream_revision",
    "vocab_size",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_configuration(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_CONFIGURATION_BYTES:
        raise ValueError("configuration_unavailable")
    with path.open("rb") as handle:
        raw = handle.read(MAX_CONFIGURATION_BYTES + 1)
    if len(raw) > MAX_CONFIGURATION_BYTES:
        raise ValueError("configuration_unavailable")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or set(value) != _EXPECTED_CONFIGURATION_KEYS:
        raise ValueError("configuration_invalid")
    declared = value.get("configuration_sha256")
    public = {key: item for key, item in value.items() if key != "configuration_sha256"}
    actual = hashlib.sha256(_canonical(public)).hexdigest()
    if not isinstance(declared, str) or declared != actual:
        raise ValueError("configuration_digest_mismatch")
    if (
        value.get("schema_version") != "1.0"
        or value.get("normalizers") != []
        or value.get("threshold_operator") != ">"
    ):
        raise ValueError("configuration_unsupported")
    if value.get("upstream_revision") != "82922516930c02f8aa322765defdb5863d07a00e":
        raise ValueError("upstream_revision_mismatch")
    if value.get("rng_device") != "cpu" or value.get("torch_version") != "2.4.1":
        raise ValueError("runtime_revision_mismatch")
    return value


def _load_upstream(upstream_dir: Path, configuration: Mapping[str, Any]) -> Any:
    source = upstream_dir.resolve() / "watermark_processor.py"
    if not source.is_file() or _sha256(source) != configuration["upstream_file_sha256"]:
        raise ValueError("upstream_source_mismatch")

    # The pinned file imports a normalizer lookup even when normalizers=[].
    # Supply a no-op module so unrelated mutable checkout files cannot enter
    # this adapter's executable identity.
    normalizers = types.ModuleType("normalizers")

    def normalization_strategy_lookup(_name: str) -> Any:
        raise ValueError("normalizers_disabled")

    normalizers.normalization_strategy_lookup = normalization_strategy_lookup
    prior = sys.modules.get("normalizers")
    sys.modules["normalizers"] = normalizers
    try:
        spec = importlib.util.spec_from_file_location("_dewatermark_pinned_kgw", source)
        if spec is None or spec.loader is None:
            raise ValueError("upstream_load_failed")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if prior is None:
            sys.modules.pop("normalizers", None)
        else:
            sys.modules["normalizers"] = prior
    if not hasattr(module, "WatermarkDetector"):
        raise ValueError("upstream_contract_mismatch")
    return module


class _FixtureTokenizer:
    bos_token_id = None


def _parse_fixture_tokens(text: str, vocab_size: int) -> list[int]:
    result: list[int] = []
    for item in text.split():
        match = _TOKEN.fullmatch(item)
        if match is None:
            raise ValueError("fixture_token_invalid")
        token = int(match.group(1))
        if token >= vocab_size:
            raise ValueError("fixture_token_out_of_range")
        result.append(token)
    return result


def _base(configuration: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "action": "detect.result",
        "detector": configuration["identifier"],
        "scheme": configuration["scheme"],
        "threshold": configuration["threshold"],
        "score_direction": "higher",
        "threshold_operator": configuration["threshold_operator"],
        "configuration_sha256": configuration["configuration_sha256"],
    }


def _failure(configuration: Mapping[str, Any], reason_code: str) -> dict[str, Any]:
    return {
        **_base(configuration),
        "status": "detector_error",
        "score": None,
        "effective_tokens": 0,
        "reason_code": reason_code,
    }


def handle(
    request: Mapping[str, Any],
    *,
    configuration: Mapping[str, Any],
    upstream_dir: Path,
) -> dict[str, Any]:
    if request.get("protocol_version") != PROTOCOL_VERSION:
        return _failure(configuration, "incompatible_protocol")
    if request.get("action") != "detect":
        return _failure(configuration, "unsupported_action")
    if request.get("detector") != configuration["identifier"]:
        return _failure(configuration, "detector_mismatch")
    if request.get("configuration_sha256") != configuration["configuration_sha256"]:
        return _failure(configuration, "configuration_mismatch")
    policy = request.get("policy")
    if not isinstance(policy, Mapping):
        return _failure(configuration, "policy_missing")
    # This adapter never downloads or opens a socket, regardless of consent.
    text = request.get("text")
    if not isinstance(text, str):
        return _failure(configuration, "invalid_text")
    try:
        tokens = _parse_fixture_tokens(text, int(configuration["vocab_size"]))
    except (TypeError, ValueError):
        return {
            **_base(configuration),
            "status": "unsupported",
            "score": None,
            "effective_tokens": 0,
            "reason_code": "token_fixture_only",
        }
    if len(tokens) < 2:
        return {
            **_base(configuration),
            "status": "insufficient_evidence",
            "score": None,
            "effective_tokens": 0,
            "reason_code": "too_few_tokens",
        }
    try:
        module = _load_upstream(upstream_dir, configuration)
        if str(module.torch.__version__).split("+", 1)[0] != configuration["torch_version"]:
            raise ValueError("torch_revision_mismatch")
        detector = module.WatermarkDetector(
            vocab=list(range(int(configuration["vocab_size"]))),
            gamma=float(configuration["gamma"]),
            delta=float(configuration["delta"]),
            seeding_scheme=str(configuration["seeding_scheme"]),
            hash_key=int(configuration["hash_key"]),
            select_green_tokens=bool(configuration["select_green_tokens"]),
            device=module.torch.device("cpu"),
            tokenizer=_FixtureTokenizer(),
            z_threshold=float(configuration["threshold"]),
            normalizers=[],
            ignore_repeated_bigrams=bool(configuration["ignore_repeated_bigrams"]),
        )
        token_tensor = module.torch.tensor(tokens, dtype=module.torch.long)
        scores = detector.detect(tokenized_text=token_tensor, return_prediction=False)
        z_score = float(scores["z_score"])
        p_value = float(scores["p_value"])
        effective_tokens = int(scores["num_tokens_scored"])
    except Exception:
        return _failure(configuration, "upstream_execution_failed")
    if not math.isfinite(z_score) or not math.isfinite(p_value) or not 0 <= p_value <= 1:
        return _failure(configuration, "upstream_result_invalid")
    if effective_tokens < int(configuration["minimum_effective_tokens"]):
        status = "insufficient_evidence"
        reason_code = "too_few_effective_tokens"
    else:
        status = "detected" if z_score > float(configuration["threshold"]) else "not_detected"
        reason_code = None
    response = {
        **_base(configuration),
        "status": status,
        "score": z_score,
        "z_score": z_score,
        "p_value": p_value,
        "effective_tokens": effective_tokens,
    }
    if reason_code is not None:
        response["reason_code"] = reason_code
    return response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument(
        "--configuration",
        type=Path,
        default=Path(__file__).with_name("adapter-config.json"),
    )
    args = parser.parse_args(argv)
    try:
        configuration = _load_configuration(args.configuration)
    except Exception:
        # The static command manifest should prevent this path. Keep stderr and
        # exception details empty because configuration paths may be private.
        return 2
    try:
        request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(request_bytes) > MAX_REQUEST_BYTES:
            raise ValueError("request_too_large")
        request = json.loads(request_bytes.decode("utf-8"))
        if not isinstance(request, Mapping):
            response = _failure(configuration, "invalid_request")
        else:
            response = handle(request, configuration=configuration, upstream_dir=args.upstream_dir)
    except Exception:
        response = _failure(configuration, "invalid_request")
    json.dump(response, sys.stdout, ensure_ascii=True, sort_keys=True, allow_nan=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
