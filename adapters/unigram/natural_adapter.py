#!/usr/bin/env python3
"""Dependency-free detector for one exact natural-text Unigram reference profile.

The fixed green mask was produced by the pinned author implementation.  This
independent scorer uses the published unique-token finite-population correction
and returns an analytical p-value as its decision score.  It supports only the
content-addressed public tokenizer/mask configuration shipped beside this file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from statistics import NormalDist
from typing import Any, Mapping

PROTOCOL_VERSION = "1.1"
MAX_CONFIGURATION_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
UPSTREAM_REVISION = "b96cdb4d52771e3cbd543a9d9aeeaec8d0790ca2"
UPSTREAM_FILE_SHA256 = "2059bf7057cd66784899379ca93492dfd217ae8fb4684e4d6cb02bca4c00d3b1"
_TOKEN_PATTERN = re.compile(r"[^\W_]+(?:['’][^\W_]+)*", re.UNICODE)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[0-9a-f]{32}")
_Z_THRESHOLD = NormalDist().inv_cdf(0.99)
_EXPECTED_CONFIGURATION_KEYS = {
    "alpha",
    "configuration_sha256",
    "dynamic_threshold_method",
    "fraction",
    "identifier",
    "key_id",
    "mask_recorded_numpy_version",
    "minimum_effective_tokens",
    "normalization",
    "p_value_method",
    "profile_manifest_sha256",
    "reported_z_score",
    "schema_version",
    "scheme",
    "score_direction",
    "threshold_operator",
    "threshold",
    "threshold_evidence_sha256",
    "token_pattern",
    "tokenizer_sha256",
    "unique_tokens",
    "upstream_file_sha256",
    "upstream_repository",
    "upstream_revision",
    "vocab_size",
    "green_mask_sha256",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _population_count(value: int) -> int:
    return bin(value).count("1")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, limit: int) -> bytes:
    descriptor = -1
    try:
        if path.is_symlink():
            raise ValueError("artifact_unavailable")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("artifact_unavailable")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(limit + 1)
    except ValueError:
        raise
    except OSError:
        raise ValueError("artifact_unavailable") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(raw) > limit:
        raise ValueError("artifact_unavailable")
    return raw


def _load_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, limit)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("artifact_invalid") from None
    if not isinstance(value, dict):
        raise ValueError("artifact_invalid")
    return value, raw


def _load_configuration(path: Path) -> dict[str, Any]:
    value, _raw = _load_json(path, MAX_CONFIGURATION_BYTES)
    if set(value) != _EXPECTED_CONFIGURATION_KEYS:
        raise ValueError("configuration_invalid")
    declared = value.get("configuration_sha256")
    public = {key: item for key, item in value.items() if key != "configuration_sha256"}
    if not isinstance(declared, str) or declared != _sha256(_canonical(public)):
        raise ValueError("configuration_digest_mismatch")
    for field in (
        "green_mask_sha256",
        "profile_manifest_sha256",
        "threshold_evidence_sha256",
        "tokenizer_sha256",
        "upstream_file_sha256",
    ):
        if not isinstance(value.get(field), str) or _SHA256.fullmatch(value[field]) is None:
            raise ValueError("configuration_invalid")
    fraction = value.get("fraction")
    alpha = value.get("alpha")
    threshold = value.get("threshold")
    minimum = value.get("minimum_effective_tokens")
    vocab_size = value.get("vocab_size")
    if (
        value.get("schema_version") != "1.0"
        or value.get("identifier") != "reference-upstream/unigram-natural-profile-v1"
        or value.get("scheme") != "unigram/unique-natural-reference-v1"
        or value.get("normalization") != "NFC+casefold"
        or value.get("token_pattern") != _TOKEN_PATTERN.pattern
        or value.get("unique_tokens") is not True
        or value.get("dynamic_threshold_method") != "finite_population_unique_tokens"
        or value.get("reported_z_score") != "finite_population_adjusted"
        or value.get("p_value_method") != "one_sided_standard_normal_survival"
        or value.get("score_direction") != "higher"
        or value.get("threshold_operator") != ">"
        or isinstance(fraction, bool)
        or not isinstance(fraction, (int, float))
        or float(fraction) != 0.5
        or isinstance(alpha, bool)
        or not isinstance(alpha, (int, float))
        or float(alpha) != 0.01
        or isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isclose(float(threshold), _Z_THRESHOLD, rel_tol=0.0, abs_tol=1e-12)
        or isinstance(minimum, bool)
        or not isinstance(minimum, int)
        or minimum != 32
        or isinstance(vocab_size, bool)
        or not isinstance(vocab_size, int)
        or vocab_size != 256
        or not isinstance(value.get("key_id"), str)
        or _KEY_ID.fullmatch(value["key_id"]) is None
        or not isinstance(value.get("mask_recorded_numpy_version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["mask_recorded_numpy_version"]) is None
        or value.get("upstream_repository") != "https://github.com/XuandongZhao/Unigram-Watermark"
        or value.get("upstream_revision") != UPSTREAM_REVISION
        or value.get("upstream_file_sha256") != UPSTREAM_FILE_SHA256
    ):
        raise ValueError("configuration_unsupported")
    return value


def _load_tokenizer(path: Path, configuration: Mapping[str, Any]) -> dict[str, int]:
    value, raw = _load_json(path, MAX_ARTIFACT_BYTES)
    if _sha256(raw) != configuration["tokenizer_sha256"]:
        raise ValueError("tokenizer_digest_mismatch")
    if set(value) != {
        "casefold",
        "kind",
        "normalization",
        "schema_version",
        "token_pattern",
        "unknown_policy",
        "vocab_size",
        "vocabulary",
    }:
        raise ValueError("tokenizer_invalid")
    if (
        value.get("schema_version") != "1.0"
        or value.get("kind") != "dewatermark-natural-lexicon-v1"
        or value.get("normalization") != "NFC"
        or value.get("casefold") is not True
        or value.get("unknown_policy") != "abstain"
        or value.get("token_pattern") != _TOKEN_PATTERN.pattern
        or value.get("vocab_size") != configuration["vocab_size"]
    ):
        raise ValueError("tokenizer_unsupported")
    raw_vocabulary = value.get("vocabulary")
    if not isinstance(raw_vocabulary, dict) or not raw_vocabulary:
        raise ValueError("tokenizer_invalid")
    result: dict[str, int] = {}
    for token, token_id in raw_vocabulary.items():
        if (
            not isinstance(token, str)
            or not token
            or unicodedata.normalize("NFC", token).casefold() != token
            or _TOKEN_PATTERN.fullmatch(token) is None
            or isinstance(token_id, bool)
            or not isinstance(token_id, int)
            or not 0 <= token_id < int(configuration["vocab_size"])
        ):
            raise ValueError("tokenizer_invalid")
        result[token] = token_id
    return result


def _load_mask(path: Path, configuration: Mapping[str, Any]) -> int:
    value, raw = _load_json(path, MAX_ARTIFACT_BYTES)
    if _sha256(raw) != configuration["green_mask_sha256"]:
        raise ValueError("mask_digest_mismatch")
    if set(value) != {"fraction", "green_mask", "kind", "schema_version", "vocab_size"}:
        raise ValueError("mask_invalid")
    encoded = value.get("green_mask")
    vocab_size = int(configuration["vocab_size"])
    if (
        value.get("schema_version") != "1.0"
        or value.get("kind") != "unigram-fixed-green-mask-bitset-v1"
        or value.get("fraction") != configuration["fraction"]
        or value.get("vocab_size") != vocab_size
        or not isinstance(encoded, str)
        or len(encoded) != (vocab_size + 3) // 4
        or re.fullmatch(r"[0-9a-f]+", encoded) is None
    ):
        raise ValueError("mask_invalid")
    bits = int(encoded, 16)
    if _population_count(bits) != int(vocab_size * float(configuration["fraction"])):
        raise ValueError("mask_invalid")
    return bits


def _verify_profile_material(configuration: Mapping[str, Any]) -> None:
    directory = Path(__file__).resolve().parent
    threshold, threshold_raw = _load_json(
        directory / "natural-threshold-evidence.json", MAX_ARTIFACT_BYTES
    )
    if (
        set(threshold)
        != {
            "alpha",
            "claim_limit",
            "empirical_calibration",
            "finite_population_factor",
            "minimum_unique_tokens",
            "null_approximation",
            "schema_version",
            "score",
            "threshold",
            "threshold_operator",
        }
        or threshold.get("schema_version") != "1.0"
        or _sha256(threshold_raw) != configuration["threshold_evidence_sha256"]
        or threshold.get("empirical_calibration") is not False
        or threshold.get("alpha") != configuration["alpha"]
        or threshold.get("minimum_unique_tokens") != configuration["minimum_effective_tokens"]
        or threshold.get("threshold") != configuration["threshold"]
        or threshold.get("threshold_operator") != configuration["threshold_operator"]
        or threshold.get("score") != "finite_population_adjusted_z_score"
    ):
        raise ValueError("threshold_evidence_mismatch")
    material, material_raw = _load_json(
        directory / "natural-profile-material.json", MAX_ARTIFACT_BYTES
    )
    files = material.get("files")
    expected = {
        "green-mask-v1.json": configuration["green_mask_sha256"],
        "natural-threshold-evidence.json": configuration["threshold_evidence_sha256"],
        "natural-tokenizer.json": configuration["tokenizer_sha256"],
        "natural_adapter.py": _sha256(_read_regular(Path(__file__), MAX_ARTIFACT_BYTES)),
        "upstream/gptwm.py": configuration["upstream_file_sha256"],
    }
    if (
        _sha256(material_raw) != configuration["profile_manifest_sha256"]
        or set(material)
        != {
            "attestation",
            "files",
            "kind",
            "schema_version",
            "source_repository",
            "source_revision",
        }
        or material.get("kind") != "content-addressed-reference-profile-material-v1"
        or material.get("schema_version") != "1.0"
        or material.get("source_repository") != configuration["upstream_repository"]
        or material.get("source_revision") != configuration["upstream_revision"]
        or material.get("attestation")
        != {
            "release_artifact_provenance": (
                "GitHub OIDC attestation for the containing distribution"
            ),
            "standalone_signature": False,
        }
        or files != expected
    ):
        raise ValueError("profile_manifest_mismatch")


def _base(configuration: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "action": "detect.result",
        "configuration_sha256": configuration["configuration_sha256"],
        "detector": configuration["identifier"],
        "protocol_version": PROTOCOL_VERSION,
        "scheme": configuration["scheme"],
        "score_direction": "higher",
        "threshold_operator": ">",
        "threshold": configuration["threshold"],
    }


def _outcome(
    configuration: Mapping[str, Any],
    status: str,
    effective_tokens: int,
    *,
    score: float | None = None,
    reason_code: str | None = None,
) -> dict[str, Any]:
    result = {
        **_base(configuration),
        "effective_tokens": effective_tokens,
        "score": score,
        "status": status,
    }
    if reason_code is not None:
        result["reason_code"] = reason_code
    return result


def handle(
    request: Mapping[str, Any],
    *,
    configuration: Mapping[str, Any],
    tokenizer_path: Path,
    mask_path: Path,
) -> dict[str, Any]:
    if set(request) != {
        "action",
        "configuration_sha256",
        "detector",
        "policy",
        "protocol_version",
        "text",
    }:
        return _outcome(configuration, "detector_error", 0, reason_code="invalid_request")
    if request.get("protocol_version") != PROTOCOL_VERSION or request.get("action") != "detect":
        return _outcome(configuration, "detector_error", 0, reason_code="incompatible_protocol")
    if request.get("detector") != configuration["identifier"]:
        return _outcome(configuration, "detector_error", 0, reason_code="detector_mismatch")
    if request.get("configuration_sha256") != configuration["configuration_sha256"]:
        return _outcome(
            configuration, "configuration_mismatch", 0, reason_code="configuration_mismatch"
        )
    policy = request.get("policy")
    if (
        not isinstance(policy, Mapping)
        or set(policy) != {"allow_model_download", "allow_network"}
        or type(policy.get("allow_model_download")) is not bool
        or type(policy.get("allow_network")) is not bool
    ):
        return _outcome(configuration, "detector_error", 0, reason_code="policy_invalid")
    text = request.get("text")
    if not isinstance(text, str):
        return _outcome(configuration, "detector_error", 0, reason_code="invalid_text")
    try:
        _verify_profile_material(configuration)
        vocabulary = _load_tokenizer(tokenizer_path, configuration)
        mask = _load_mask(mask_path, configuration)
    except Exception:
        return _outcome(configuration, "detector_error", 0, reason_code="artifact_mismatch")
    normalized = unicodedata.normalize("NFC", text).casefold()
    lexemes = [match.group(0) for match in _TOKEN_PATTERN.finditer(normalized)]
    try:
        token_ids = [vocabulary[item] for item in lexemes]
    except KeyError:
        return _outcome(configuration, "unsupported", 0, reason_code="tokenizer_unknown_token")
    unique_ids = tuple(dict.fromkeys(token_ids))
    effective_tokens = len(unique_ids)
    if effective_tokens < int(configuration["minimum_effective_tokens"]):
        return _outcome(
            configuration,
            "insufficient_evidence",
            effective_tokens,
            reason_code="too_few_effective_tokens",
        )
    fraction = float(configuration["fraction"])
    hits = sum(bool(mask & (1 << token_id)) for token_id in unique_ids)
    raw_z = (hits - fraction * effective_tokens) / math.sqrt(
        fraction * (1.0 - fraction) * effective_tokens
    )
    vocab_size = int(configuration["vocab_size"])
    finite_population = math.sqrt(1.0 - (effective_tokens - 1.0) / (vocab_size - 1.0))
    if finite_population <= 0.0:
        adjusted_z = 0.0
        p_value = 1.0
    else:
        adjusted_z = raw_z / finite_population
        p_value = 0.5 * math.erfc(adjusted_z / math.sqrt(2.0))
    if not math.isfinite(adjusted_z) or not 0.0 <= p_value <= 1.0:
        return _outcome(configuration, "detector_error", 0, reason_code="score_invalid")
    threshold = float(configuration["threshold"])
    status = "detected" if adjusted_z > threshold else "not_detected"
    return {
        **_outcome(configuration, status, effective_tokens, score=adjusted_z),
        "p_value": p_value,
        "z_score": adjusted_z,
    }


def main(argv: list[str] | None = None) -> int:
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--configuration", type=Path, default=directory / "natural-adapter-config.json"
    )
    parser.add_argument("--tokenizer", type=Path, default=directory / "natural-tokenizer.json")
    parser.add_argument("--mask", type=Path, default=directory / "green-mask-v1.json")
    args = parser.parse_args(argv)
    try:
        configuration = _load_configuration(args.configuration)
    except Exception:
        return 2
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request_too_large")
        request = json.loads(raw.decode("utf-8"))
        response = (
            handle(
                request,
                configuration=configuration,
                tokenizer_path=args.tokenizer,
                mask_path=args.mask,
            )
            if isinstance(request, Mapping)
            else _outcome(configuration, "detector_error", 0, reason_code="invalid_request")
        )
    except Exception:
        response = _outcome(configuration, "detector_error", 0, reason_code="invalid_request")
    json.dump(response, sys.stdout, ensure_ascii=True, sort_keys=True, allow_nan=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
