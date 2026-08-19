#!/usr/bin/env python3
"""Dependency-free detector for one exact, natural-text KGW reference profile.

The committed transition table was produced by the pinned upstream detector.
This module independently scores the resulting decisions.  It is intentionally
limited to the tokenizer, public reference configuration, and derived table
whose digests appear in ``natural-adapter-config.json``.  It is not a generic
KGW detector and cannot detect a differently keyed or tokenized watermark.
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
from typing import Any, Mapping

PROTOCOL_VERSION = "1.1"
MAX_CONFIGURATION_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
_TOKEN_PATTERN = re.compile(r"[^\W_]+(?:['’][^\W_]+)*", re.UNICODE)
_KEY_ID = re.compile(r"[0-9a-f]{32}")
_EXPECTED_CONFIGURATION_KEYS = {
    "configuration_sha256",
    "gamma",
    "identifier",
    "ignore_repeated_bigrams",
    "key_id",
    "minimum_effective_tokens",
    "normalization",
    "p_value_method",
    "profile_manifest_sha256",
    "schema_version",
    "scheme",
    "score_direction",
    "threshold_operator",
    "seeding_scheme",
    "select_green_tokens",
    "threshold",
    "threshold_evidence_sha256",
    "token_pattern",
    "tokenizer_sha256",
    "transition_recorded_torch_version",
    "transition_table_sha256",
    "upstream_file_sha256",
    "upstream_repository",
    "upstream_revision",
    "vocab_size",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _population_count(value: int) -> int:
    return bin(value).count("1")


def _read_bounded(path: Path, limit: int) -> bytes:
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
            data = handle.read(limit + 1)
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
    if len(data) > limit:
        raise ValueError("artifact_unavailable")
    return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    raw = _read_bounded(path, limit)
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
    digest_fields = (
        "profile_manifest_sha256",
        "threshold_evidence_sha256",
        "tokenizer_sha256",
        "transition_table_sha256",
        "upstream_file_sha256",
    )
    if any(
        not isinstance(value.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
        for field in digest_fields
    ):
        raise ValueError("configuration_invalid")
    gamma = value.get("gamma")
    threshold = value.get("threshold")
    minimum = value.get("minimum_effective_tokens")
    vocab_size = value.get("vocab_size")
    if (
        value.get("schema_version") != "1.0"
        or value.get("identifier") != "reference-upstream/kgw-simple1-natural-profile-v1"
        or value.get("scheme") != "kgw/simple-1-natural-reference-v1"
        or value.get("normalization") != "NFC+casefold"
        or value.get("token_pattern") != _TOKEN_PATTERN.pattern
        or value.get("seeding_scheme") != "simple_1"
        or value.get("score_direction") != "higher"
        or value.get("threshold_operator") != ">"
        or value.get("p_value_method") != "one_sided_standard_normal_survival"
        or value.get("ignore_repeated_bigrams") is not True
        or value.get("select_green_tokens") is not True
        or isinstance(gamma, bool)
        or not isinstance(gamma, (int, float))
        or not math.isfinite(float(gamma))
        or float(gamma) != 0.25
        or isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(float(threshold))
        or float(threshold) != 4.0
        or isinstance(minimum, bool)
        or not isinstance(minimum, int)
        or minimum != 32
        or isinstance(vocab_size, bool)
        or not isinstance(vocab_size, int)
        or vocab_size != 256
        or not isinstance(value.get("key_id"), str)
        or _KEY_ID.fullmatch(value["key_id"]) is None
        or not isinstance(value.get("transition_recorded_torch_version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["transition_recorded_torch_version"])
        is None
    ):
        raise ValueError("configuration_unsupported")
    if (
        value.get("upstream_repository") != "https://github.com/jwkirchenbauer/lm-watermarking"
        or value.get("upstream_revision") != "82922516930c02f8aa322765defdb5863d07a00e"
        or value.get("upstream_file_sha256")
        != "512c40644bc9e9932a8674bbf13046c1a4e92db429cff92afc9e90d2226896fc"
    ):
        raise ValueError("upstream_revision_mismatch")
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
    vocabulary: dict[str, int] = {}
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
        vocabulary[token] = token_id
    return vocabulary


def _load_transitions(path: Path, configuration: Mapping[str, Any]) -> tuple[int, ...]:
    value, raw = _load_json(path, MAX_ARTIFACT_BYTES)
    if _sha256(raw) != configuration["transition_table_sha256"]:
        raise ValueError("transition_digest_mismatch")
    if set(value) != {
        "gamma",
        "kind",
        "rows",
        "schema_version",
        "select_green_tokens",
        "seeding_scheme",
        "vocab_size",
    }:
        raise ValueError("transition_table_invalid")
    rows = value.get("rows")
    vocab_size = int(configuration["vocab_size"])
    width = (vocab_size + 3) // 4
    expected_green = int(vocab_size * float(configuration["gamma"]))
    if (
        value.get("schema_version") != "1.0"
        or value.get("kind") != "kgw-green-transition-bitset-v1"
        or value.get("vocab_size") != vocab_size
        or value.get("gamma") != configuration["gamma"]
        or value.get("seeding_scheme") != configuration["seeding_scheme"]
        or value.get("select_green_tokens") != configuration["select_green_tokens"]
        or not isinstance(rows, list)
        or len(rows) != vocab_size
    ):
        raise ValueError("transition_table_invalid")
    parsed: list[int] = []
    for row in rows:
        if not isinstance(row, str) or len(row) != width or re.fullmatch(r"[0-9a-f]+", row) is None:
            raise ValueError("transition_table_invalid")
        bits = int(row, 16)
        if _population_count(bits) != expected_green:
            raise ValueError("transition_table_invalid")
        parsed.append(bits)
    return tuple(parsed)


def _verify_profile_material(configuration: Mapping[str, Any]) -> None:
    directory = Path(__file__).resolve().parent
    threshold, threshold_raw = _load_json(
        directory / "natural-threshold-evidence.json", MAX_ARTIFACT_BYTES
    )
    if (
        set(threshold)
        != {
            "claim_limit",
            "empirical_calibration",
            "minimum_effective_tokens",
            "null_approximation",
            "schema_version",
            "score",
            "threshold",
            "threshold_operator",
        }
        or threshold.get("schema_version") != "1.0"
        or _sha256(threshold_raw) != configuration["threshold_evidence_sha256"]
        or threshold.get("empirical_calibration") is not False
        or threshold.get("threshold") != configuration["threshold"]
        or threshold.get("minimum_effective_tokens") != configuration["minimum_effective_tokens"]
        or threshold.get("threshold_operator") != configuration["threshold_operator"]
        or threshold.get("score") != "z_score"
    ):
        raise ValueError("threshold_evidence_mismatch")
    material, material_raw = _load_json(
        directory / "natural-profile-material.json", MAX_ARTIFACT_BYTES
    )
    files = material.get("files")
    expected = {
        "green-transitions-v1.json": configuration["transition_table_sha256"],
        "natural-threshold-evidence.json": configuration["threshold_evidence_sha256"],
        "natural-tokenizer.json": configuration["tokenizer_sha256"],
        "natural_adapter.py": _sha256(_read_bounded(Path(__file__), MAX_ARTIFACT_BYTES)),
        "upstream/watermark_processor.py": configuration["upstream_file_sha256"],
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


def _tokenize(text: str, vocabulary: Mapping[str, int]) -> tuple[list[int], bool]:
    normalized = unicodedata.normalize("NFC", text).casefold()
    lexemes = [match.group(0) for match in _TOKEN_PATTERN.finditer(normalized)]
    try:
        return [vocabulary[item] for item in lexemes], False
    except KeyError:
        return [], True


def _base(configuration: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "action": "detect.result",
        "detector": configuration["identifier"],
        "scheme": configuration["scheme"],
        "threshold": configuration["threshold"],
        "score_direction": configuration["score_direction"],
        "threshold_operator": configuration["threshold_operator"],
        "configuration_sha256": configuration["configuration_sha256"],
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
        "status": status,
        "score": score,
        "effective_tokens": effective_tokens,
    }
    if reason_code is not None:
        result["reason_code"] = reason_code
    return result


def handle(
    request: Mapping[str, Any],
    *,
    configuration: Mapping[str, Any],
    tokenizer_path: Path,
    transitions_path: Path,
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
    if request.get("protocol_version") != PROTOCOL_VERSION:
        return _outcome(configuration, "detector_error", 0, reason_code="incompatible_protocol")
    if request.get("action") != "detect":
        return _outcome(configuration, "detector_error", 0, reason_code="unsupported_action")
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
        return _outcome(configuration, "detector_error", 0, reason_code="policy_missing")
    text = request.get("text")
    if not isinstance(text, str):
        return _outcome(configuration, "detector_error", 0, reason_code="invalid_text")
    try:
        _verify_profile_material(configuration)
        vocabulary = _load_tokenizer(tokenizer_path, configuration)
        transitions = _load_transitions(transitions_path, configuration)
    except Exception:
        return _outcome(configuration, "detector_error", 0, reason_code="artifact_mismatch")
    tokens, unknown = _tokenize(text, vocabulary)
    if unknown:
        return _outcome(configuration, "unsupported", 0, reason_code="tokenizer_unknown_token")
    unique_bigrams = tuple(dict.fromkeys(zip(tokens, tokens[1:])))
    effective_tokens = len(unique_bigrams)
    minimum = int(configuration["minimum_effective_tokens"])
    if effective_tokens < minimum:
        return _outcome(
            configuration,
            "insufficient_evidence",
            effective_tokens,
            reason_code="too_few_effective_tokens",
        )
    hits = sum(bool(transitions[previous] & (1 << token)) for previous, token in unique_bigrams)
    gamma = float(configuration["gamma"])
    denominator = math.sqrt(effective_tokens * gamma * (1.0 - gamma))
    z_score = (hits - gamma * effective_tokens) / denominator
    p_value = 0.5 * math.erfc(z_score / math.sqrt(2.0))
    if not math.isfinite(z_score) or not 0.0 <= p_value <= 1.0:
        return _outcome(configuration, "detector_error", 0, reason_code="score_invalid")
    threshold = float(configuration["threshold"])
    status = "detected" if z_score > threshold else "not_detected"
    return {
        **_outcome(configuration, status, effective_tokens, score=z_score),
        "z_score": z_score,
        "p_value": p_value,
    }


def main(argv: list[str] | None = None) -> int:
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--configuration", type=Path, default=directory / "natural-adapter-config.json"
    )
    parser.add_argument("--tokenizer", type=Path, default=directory / "natural-tokenizer.json")
    parser.add_argument("--transitions", type=Path, default=directory / "green-transitions-v1.json")
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
        if not isinstance(request, Mapping):
            response = _outcome(configuration, "detector_error", 0, reason_code="invalid_request")
        else:
            response = handle(
                request,
                configuration=configuration,
                tokenizer_path=args.tokenizer,
                transitions_path=args.transitions,
            )
    except Exception:
        response = _outcome(configuration, "detector_error", 0, reason_code="invalid_request")
    json.dump(response, sys.stdout, ensure_ascii=True, sort_keys=True, allow_nan=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
