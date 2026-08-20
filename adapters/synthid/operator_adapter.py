#!/usr/bin/env python3
"""Offline SynthID Text research detector for an operator-sealed target.

This command implements the public signed-int64 hashing and mean/weighted-mean
formulas of google-deepmind/synthid-text at the pinned revision below, with an
explicit Python binary64 final-score contract.  It deliberately
does not contain a key, tokenizer, threshold, or vendor configuration.  The
operator must first run ``seal_operator.py`` with an owner-only key record and
a local tokenizer snapshot.

Detection verifies every public commitment and the private key record before
tokenizing text.  It never opens a socket or asks Transformers to download or
execute remote code.  All failure responses use a closed, content-free reason
code set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import stat
import struct
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

PROTOCOL_VERSION = "1.2"
UPSTREAM_REPOSITORY = "https://github.com/google-deepmind/synthid-text"
UPSTREAM_REVISION = "addb4a158143c7c6851a1308f78b89fceed59683"
UPSTREAM_SOURCE_SHA256 = {
    "src/synthid_text/detector_mean.py": (
        "584f12aa376e9106e6e6d4dd8bf3d5572c04996c844ffddeff37e1a1a15680f9"
    ),
    "src/synthid_text/hashing_function.py": (
        "6900000b03d6275347396d495d1118c64a16537a64c05fdec0868b623d1a34ab"
    ),
    "src/synthid_text/logits_processing.py": (
        "88bd1c20e2fea72356980548fc4cfa82c2ca1a2059ecb2deb1e3efa38be76294"
    ),
}
SCORER_SEMANTICS = "synthid-text-public-mean-formula-python-binary64-v1"
MAX_CONFIGURATION_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_BINDING_BYTES = 16 * 1024
MAX_KEY_DEPTH = 256
MAX_INPUT_TOKENS = 1_000_000
MAX_CONTEXT_HISTORY_SIZE = 65_536
MAX_SCORING_CELLS = 1_000_000
MAX_TOKENIZER_FILES = 128
MAX_TOKENIZER_FILE_BYTES = 64 * 1024 * 1024
MAX_TOKENIZER_TOTAL_BYTES = 512 * 1024 * 1024
MAX_UPSTREAM_FILE_BYTES = 4 * 1024 * 1024
# Keep the worst-case JSON response below CommandDetector's default 64 KiB
# stdout capture while remaining well inside the protocol-wide 4096-span cap.
MAX_ATTRIBUTIONS = 512
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1
_INT64_MASK = (1 << 64) - 1
_HASH_MULTIPLIER = 6364136223846793005
_SHA256 = re.compile(r"[0-9a-f]{64}")
_OPAQUE_ID = re.compile(r"[0-9a-f]{32}")
_PUBLIC_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}")
_RESERVED_VENDOR_CLAIM = re.compile(r"(?i)(?:anthropic|claude|deepmind|gemini|google)")
_PUBLIC_RELATIVE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+\-=]{0,511}")
_URL_USERINFO = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s@]+@")
_PRIVATE_ABSOLUTE_PATH = re.compile(
    r"(?i)(?:^|[\s\"'(=:\[])(?:/(?!/)(?:[^/\s\"'<>]+/)+[^/\s\"'<>]+|"
    r"~[/\\][^\s\"'<>]+|[A-Za-z]:[/\\][^\s\"'<>]+|"
    r"\\\\[^\\\s]+\\[^\s\"'<>]+|file://[^\s\"'<>]+)"
)
_SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?i)\b(?:sk|rk)[-_](?:live|test|proj|ant)?[-_A-Za-z0-9]{8,}\b|"
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
        r"\bglpat-[A-Za-z0-9_-]{20,}\b|\bAKIA[0-9A-Z]{16}\b|"
        r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}\b"
    ),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)(?:^|[^A-Za-z0-9])(?:api[-_]?key|authorization|credential|password|"
        r"secret|(?:access|api|auth|bearer|refresh|session)[-_]?token)"
        r"\s*[:=]\s*[\"']?[^\s,;\"']{8,}"
    ),
)
_CREDENTIAL_JSON_KEYS = {
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "aws_secret_access_key",
    "client_secret",
    "credential",
    "credentials",
    "env",
    "environment",
    "headers",
    "key",
    "password",
    "private_key",
    "secret",
}
_CREDENTIAL_JSON_KEY_SUFFIXES = (
    "_access_token",
    "_api_key",
    "_api_token",
    "_auth_token",
    "_authorization",
    "_bearer_token",
    "_client_secret",
    "_credential",
    "_credentials",
    "_id_token",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_session_token",
)
_SENSITIVE_TOKENIZER_NAMES = {
    ".env",
    ".netrc",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
}
_SENSITIVE_TOKENIZER_SUFFIXES = (".key", ".p12", ".pem", ".pfx")
_SENSITIVE_TOKENIZER_TOKENS = {"credential", "key", "password", "private", "secret", "token"}
_EXPECTED_CONFIGURATION_KEYS = {
    "attribution_kind",
    "byteorder",
    "configuration_sha256",
    "context_history_size",
    "context_repetition_handling",
    "detector_type",
    "detector_text_tokenization",
    "eos_handling",
    "eos_token_id",
    "generation_apply_top_k",
    "generation_num_leaves",
    "generation_skip_first_ngram_calls",
    "generation_temperature",
    "generation_text_serialization",
    "generation_top_k",
    "identifier",
    "key_id",
    "maximum_effective_tokens",
    "maximum_attributions",
    "maximum_input_tokens",
    "minimum_effective_tokens",
    "ngram_len",
    "offset_mapping",
    "platform_machine",
    "platform_system",
    "python_version",
    "schema_version",
    "scheme",
    "score_direction",
    "scorer_semantics",
    "secret_binding_id",
    "special_token_handling",
    "source_files_sha256",
    "threshold",
    "threshold_evidence_sha256",
    "threshold_operator",
    "text_scope",
    "tokenizer_conformance_sha256",
    "tokenizer_files",
    "tokenizer_revision",
    "tokenizer_snapshot_sha256",
    "tokenizer_type",
    "tokenizers_version",
    "transformers_version",
    "upstream_repository",
    "upstream_revision",
    "vocab_size",
    "watermark_target_sha256",
    "watermarking_depth",
    "weights",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non_finite_json_number")


def _read_regular(path: Path, limit: int, reason: str) -> bytes:
    descriptor = -1
    try:
        # Reject FIFOs and other special files before open so a hostile path
        # cannot block the process. The descriptor check below closes the
        # replacement race, while O_NONBLOCK keeps that open non-blocking.
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError(reason)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError(reason)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(limit + 1)
    except ValueError:
        raise
    except OSError:
        raise ValueError(reason) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(raw) > limit:
        raise ValueError(reason)
    return raw


def _normal_json_key(value: str) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")


def _credential_json_key(value: str) -> bool:
    normalized = _normal_json_key(value)
    return normalized in _CREDENTIAL_JSON_KEYS or normalized.endswith(_CREDENTIAL_JSON_KEY_SUFFIXES)


def _unsafe_tokenizer_fragment(value: str) -> bool:
    return bool(
        _URL_USERINFO.search(value)
        or _PRIVATE_ABSOLUTE_PATH.search(value)
        or any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS)
    )


def _unsafe_public_string(value: str) -> bool:
    return _unsafe_tokenizer_fragment(value) or any(
        ord(character) < 32 and character not in "\t\n\r" for character in value
    )


def _valid_public_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _PUBLIC_IDENTIFIER.fullmatch(value) is not None
        and not _unsafe_public_string(value)
        and ".." not in PurePosixPath(value).parts
        and not re.match(r"(?i)^[a-z]:/", value)
    )


def _validate_tokenizer_json(value: Any) -> None:
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        item, depth, vocabulary = stack.pop()
        if depth > 128:
            raise ValueError("tokenizer_contains_unsafe_content")
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or _unsafe_public_string(key):
                    raise ValueError("tokenizer_contains_unsafe_content")
                numeric_vocabulary_entry = vocabulary and type(child) in (int, float)
                if _credential_json_key(key) and not numeric_vocabulary_entry:
                    raise ValueError("tokenizer_contains_unsafe_content")
                is_vocabulary = (
                    _normal_json_key(key) in {"vocab", "vocabulary"} and type(child) is dict
                )
                stack.append((child, depth + 1, is_vocabulary))
        elif type(item) is list:
            stack.extend((child, depth + 1, False) for child in item)
        elif type(item) is str:
            if _unsafe_public_string(item):
                raise ValueError("tokenizer_contains_unsafe_content")
        elif item is None or type(item) in (bool, int, float):
            if type(item) is float and not math.isfinite(item):
                raise ValueError("tokenizer_contains_unsafe_content")
        else:
            raise ValueError("tokenizer_contains_unsafe_content")


def _validate_tokenizer_content(relative: str, raw: bytes) -> None:
    projected = raw.decode("utf-8", "ignore")
    if _unsafe_tokenizer_fragment(projected):
        raise ValueError("tokenizer_contains_unsafe_content")
    if relative.lower().endswith(".model"):
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        if relative.lower().endswith(".json"):
            raise ValueError("tokenizer_contains_unsafe_content") from None
        return
    if not relative.lower().endswith(".json"):
        return
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        raise ValueError("tokenizer_contains_unsafe_content") from None
    _validate_tokenizer_json(value)


def _tokenizer_snapshot(directory: Path) -> dict[str, str]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("tokenizer_unavailable")
    paths = sorted(path for path in directory.rglob("*") if path.is_file() or path.is_symlink())
    if not paths or len(paths) > MAX_TOKENIZER_FILES:
        raise ValueError("tokenizer_unavailable")
    result: dict[str, str] = {}
    total_bytes = 0
    for path in paths:
        relative = path.relative_to(directory).as_posix()
        lowered_parts = tuple(part.lower() for part in Path(relative).parts)
        filename_tokens = {
            token for part in lowered_parts for token in re.sub(r"[^a-z0-9]+", " ", part).split()
        }
        if (
            any(part in _SENSITIVE_TOKENIZER_NAMES for part in lowered_parts)
            or any(part.startswith(".env.") for part in lowered_parts)
            or any(part.endswith(_SENSITIVE_TOKENIZER_SUFFIXES) for part in lowered_parts)
            or bool(filename_tokens.intersection(_SENSITIVE_TOKENIZER_TOKENS))
            or _PUBLIC_RELATIVE_PATH.fullmatch(relative) is None
        ):
            raise ValueError("tokenizer_contains_sensitive_file")
        raw = _read_regular(path, MAX_TOKENIZER_FILE_BYTES, "tokenizer_unavailable")
        total_bytes += len(raw)
        if total_bytes > MAX_TOKENIZER_TOTAL_BYTES:
            raise ValueError("tokenizer_unavailable")
        _validate_tokenizer_content(relative, raw)
        result[relative] = _sha256(raw)
    return result


def _verify_sources(directory: Path) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("upstream_source_mismatch")
    for relative, expected in UPSTREAM_SOURCE_SHA256.items():
        path = directory / relative
        actual = _sha256(_read_regular(path, MAX_UPSTREAM_FILE_BYTES, "upstream_source_mismatch"))
        if actual != expected:
            raise ValueError("upstream_source_mismatch")


def _read_owner_only_record(path: Path, limit: int) -> dict[str, Any]:
    if os.name != "posix":
        raise ValueError("key_permissions_unverifiable")
    descriptor = -1
    try:
        # Apply the same pre-open special-file rejection as the public reader.
        # Owner and mode checks are repeated on the opened descriptor below so
        # a path replacement cannot bypass the private-record policy.
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > limit
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise ValueError("key_unavailable")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > limit
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("key_unavailable")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(limit + 1)
    except ValueError:
        raise
    except OSError:
        raise ValueError("key_unavailable") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        record = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("key_unavailable") from None
    if not isinstance(record, dict):
        raise ValueError("key_unavailable")
    return record


def _read_key_record(path: Path) -> tuple[tuple[int, ...], str]:
    record = _read_owner_only_record(path, MAX_KEY_BYTES)
    if set(record) != {"key_id", "keys", "schema_version"}:
        raise ValueError("key_unavailable")
    values = record.get("keys")
    key_id = record.get("key_id")
    if (
        record.get("schema_version") != "1.0"
        or not isinstance(key_id, str)
        or _OPAQUE_ID.fullmatch(key_id) is None
        or not isinstance(values, list)
        or not 1 <= len(values) <= MAX_KEY_DEPTH
        or any(type(item) is not int or not 0 <= item <= _INT64_MAX for item in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("key_unavailable")
    return tuple(values), key_id


def _load_key(path: Path, binding_path: Path, configuration: Mapping[str, Any]) -> tuple[int, ...]:
    keys, actual_id = _read_key_record(path)
    binding = _read_owner_only_record(binding_path, MAX_BINDING_BYTES)
    expected_key_sha256 = _sha256(_canonical({"keys": list(keys)}))
    if (
        actual_id != configuration["key_id"]
        or len(keys) != configuration["watermarking_depth"]
        or set(binding)
        != {
            "binding_id",
            "configuration_sha256",
            "key_id",
            "key_material_sha256",
            "schema_version",
        }
        or binding.get("schema_version") != "1.0"
        or binding.get("binding_id") != configuration["secret_binding_id"]
        or binding.get("configuration_sha256") != configuration["configuration_sha256"]
        or binding.get("key_id") != actual_id
        or not isinstance(binding.get("key_material_sha256"), str)
        or _SHA256.fullmatch(binding["key_material_sha256"]) is None
        or binding.get("key_material_sha256") != expected_key_sha256
    ):
        raise ValueError("key_mismatch")
    return keys


def _target_material(configuration: Mapping[str, Any]) -> dict[str, Any]:
    names = (
        "byteorder",
        "context_history_size",
        "context_repetition_handling",
        "detector_text_tokenization",
        "eos_handling",
        "eos_token_id",
        "generation_apply_top_k",
        "generation_num_leaves",
        "generation_skip_first_ngram_calls",
        "generation_temperature",
        "generation_text_serialization",
        "generation_top_k",
        "key_id",
        "ngram_len",
        "scheme",
        "special_token_handling",
        "text_scope",
        "tokenizer_conformance_sha256",
        "tokenizer_revision",
        "tokenizer_snapshot_sha256",
        "upstream_revision",
        "vocab_size",
        "tokenizer_type",
        "tokenizers_version",
        "transformers_version",
        "watermarking_depth",
    )
    material = {name: configuration[name] for name in names}
    material["generation_source_files_sha256"] = {
        name: configuration["source_files_sha256"][name]
        for name in (
            "src/synthid_text/hashing_function.py",
            "src/synthid_text/logits_processing.py",
        )
    }
    return material


def _tokenizer_conformance(tokenizer: Any) -> str:
    """Bind public text-to-token and offset behavior without publishing probe text."""
    try:
        vocab_size = len(tokenizer)
    except Exception:
        raise ValueError("tokenizer_conformance_failed") from None
    if type(vocab_size) is not int or not 2 <= vocab_size <= _INT64_MAX:
        raise ValueError("tokenizer_conformance_failed")
    probes = (
        "public offset probe",
        "A  B\nC",
        "cafe\N{COMBINING ACUTE ACCENT} and \N{GREEK CAPITAL LETTER DELTA}",
        "emoji \N{SLIGHTLY SMILING FACE} byte fallback",
    )
    records: list[dict[str, Any]] = []
    for probe_id, text in enumerate(probes):
        encoded = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
        token_ids = encoded.get("input_ids") if isinstance(encoded, Mapping) else None
        offsets = encoded.get("offset_mapping") if isinstance(encoded, Mapping) else None
        if (
            not isinstance(token_ids, list)
            or not isinstance(offsets, list)
            or not token_ids
            or len(token_ids) > 4096
            or len(token_ids) != len(offsets)
            or any(type(item) is not int or not 0 <= item < vocab_size for item in token_ids)
            or any(
                not isinstance(item, (list, tuple))
                or len(item) != 2
                or type(item[0]) is not int
                or type(item[1]) is not int
                or not 0 <= item[0] <= item[1] <= len(text)
                for item in offsets
            )
        ):
            raise ValueError("tokenizer_conformance_failed")
        previous_end = 0
        nonempty = False
        for start, end in offsets:
            if start != end:
                if start < previous_end:
                    raise ValueError("tokenizer_conformance_failed")
                previous_end = end
                nonempty = True
        if not nonempty:
            raise ValueError("tokenizer_conformance_failed")
        try:
            decoded = tokenizer.decode(
                token_ids,
                skip_special_tokens=False,
                clean_up_tokenization_spaces=False,
            )
        except Exception:
            raise ValueError("tokenizer_conformance_failed") from None
        if not isinstance(decoded, str) or len(decoded) > 65_536:
            raise ValueError("tokenizer_conformance_failed")
        reencoded = tokenizer(decoded, add_special_tokens=False, return_offsets_mapping=True)
        roundtrip_ids = reencoded.get("input_ids") if isinstance(reencoded, Mapping) else None
        roundtrip_offsets = (
            reencoded.get("offset_mapping") if isinstance(reencoded, Mapping) else None
        )
        if (
            not isinstance(roundtrip_ids, list)
            or not isinstance(roundtrip_offsets, list)
            or len(roundtrip_ids) > 4096
            or len(roundtrip_ids) != len(roundtrip_offsets)
            or any(type(item) is not int or not 0 <= item < vocab_size for item in roundtrip_ids)
            or any(
                not isinstance(item, (list, tuple))
                or len(item) != 2
                or type(item[0]) is not int
                or type(item[1]) is not int
                or not 0 <= item[0] <= item[1] <= len(decoded)
                for item in roundtrip_offsets
            )
        ):
            raise ValueError("tokenizer_conformance_failed")
        records.append(
            {
                "offsets": [list(item) for item in offsets],
                "probe_id": probe_id,
                "roundtrip_offsets": [list(item) for item in roundtrip_offsets],
                "roundtrip_token_ids": roundtrip_ids,
                "token_ids": token_ids,
            }
        )
    return _sha256(_canonical(records))


def _implementation_commitment(
    *,
    port_source_sha256: str,
    tokenizers_version: str,
    transformers_version: str,
) -> str:
    material = {
        "byteorder": sys.byteorder,
        "platform_machine": platform.machine(),
        "platform_system": platform.system(),
        "port_source_sha256": port_source_sha256,
        "python_version": platform.python_version(),
        "scorer_semantics": SCORER_SEMANTICS,
        "source_files_sha256": UPSTREAM_SOURCE_SHA256,
        "tokenizer_loading": "local_files_only_trust_remote_code_false_v1",
        "tokenizers_version": tokenizers_version,
        "transformers_version": transformers_version,
    }
    return _sha256(_canonical(material))


def _valid_weights(value: Any, detector_type: Any, depth: int) -> bool:
    if detector_type == "mean":
        return value == []
    if detector_type != "weighted_mean" or not isinstance(value, list) or len(value) != depth:
        return False
    for item in value:
        if type(item) not in (int, float) or item < 0:
            return False
        try:
            if not math.isfinite(float(item)):
                return False
        except (OverflowError, TypeError, ValueError):
            return False
    return _finite_weight_total(value)


def _finite_weight_total(value: Sequence[Any]) -> bool:
    try:
        total = math.fsum(float(item) for item in value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(total) and total > 0.0


def _normalized_weights(value: Sequence[Any], detector_type: str, depth: int) -> list[float]:
    if detector_type == "mean" and not value:
        return [1.0] * depth
    weights = list(value)
    if not _valid_weights(weights, detector_type, depth):
        raise ValueError("scorer_input_invalid")
    total = math.fsum(float(item) for item in weights)
    normalized = [(float(item) / total) * depth for item in weights]
    if any(not math.isfinite(item) for item in normalized):
        raise ValueError("scorer_input_invalid")
    return normalized


def _validate_configuration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _EXPECTED_CONFIGURATION_KEYS:
        raise ValueError("configuration_invalid")
    declared = value.get("configuration_sha256")
    public = {key: item for key, item in value.items() if key != "configuration_sha256"}
    if not isinstance(declared, str) or declared != _sha256(_canonical(public)):
        raise ValueError("configuration_digest_mismatch")
    if value.get("source_files_sha256") != UPSTREAM_SOURCE_SHA256:
        raise ValueError("configuration_unsupported")
    files = value.get("tokenizer_files")
    if not isinstance(files, dict) or not files or len(files) > MAX_TOKENIZER_FILES:
        raise ValueError("configuration_invalid")
    for name, digest in files.items():
        relative = PurePosixPath(name) if isinstance(name, str) else PurePosixPath("/")
        if (
            not isinstance(name, str)
            or not name
            or _PUBLIC_RELATIVE_PATH.fullmatch(name) is None
            or relative.is_absolute()
            or ".." in relative.parts
            or "\\" in name
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise ValueError("configuration_invalid")
    integer_fields = (
        "context_history_size",
        "eos_token_id",
        "generation_num_leaves",
        "generation_top_k",
        "maximum_attributions",
        "maximum_effective_tokens",
        "maximum_input_tokens",
        "minimum_effective_tokens",
        "ngram_len",
        "vocab_size",
        "watermarking_depth",
    )
    if any(type(value.get(name)) is not int for name in integer_fields):
        raise ValueError("configuration_invalid")
    minimum = value["minimum_effective_tokens"]
    maximum = value["maximum_effective_tokens"]
    depth = value["watermarking_depth"]
    threshold = value.get("threshold")
    if (
        value.get("schema_version") != "1.0"
        or not _valid_public_identifier(value.get("identifier"))
        or not _valid_public_identifier(value.get("scheme"))
        or not isinstance(value.get("key_id"), str)
        or _OPAQUE_ID.fullmatch(value["key_id"]) is None
        or not isinstance(value.get("secret_binding_id"), str)
        or _OPAQUE_ID.fullmatch(value["secret_binding_id"]) is None
        or not str(value["identifier"]).startswith("operator/synthid-text-")
        or _RESERVED_VENDOR_CLAIM.search(str(value["identifier"])) is not None
        or value.get("scheme") != "synthid-text/public-reference-v1"
        or (
            value.get("detector_type") == "mean"
            and not str(value["identifier"]).startswith("operator/synthid-text-mean")
        )
        or (
            value.get("detector_type") == "weighted_mean"
            and not str(value["identifier"]).startswith("operator/synthid-text-weighted-mean")
        )
        or not 1 <= value["context_history_size"] <= MAX_CONTEXT_HISTORY_SIZE
        or not 2 <= value["ngram_len"] <= 64
        or not 1 <= depth <= MAX_KEY_DEPTH
        or not 2 <= value["vocab_size"] <= _INT64_MAX
        or not 0 <= value["eos_token_id"] < value["vocab_size"]
        or not 2 <= value["generation_num_leaves"] <= 64
        or not 2 <= value["generation_top_k"] <= value["vocab_size"]
        or type(value.get("generation_temperature")) not in (int, float)
        or not math.isfinite(float(value["generation_temperature"]))
        or float(value["generation_temperature"]) <= 0.0
        or type(value.get("generation_apply_top_k")) is not bool
        or type(value.get("generation_skip_first_ngram_calls")) is not bool
        or value.get("attribution_kind") != "token_character_spans"
        or not 1 <= value["maximum_attributions"] <= MAX_ATTRIBUTIONS
        or value.get("offset_mapping") != "huggingface_fast_offsets_v1"
        or not 1 <= minimum <= maximum <= value["maximum_input_tokens"] <= MAX_INPUT_TOKENS
        or maximum > value["maximum_input_tokens"] - value["ngram_len"] + 1
        or value["maximum_attributions"] > maximum
        or ((value["maximum_input_tokens"] - value["ngram_len"] + 1) * depth > MAX_SCORING_CELLS)
        or type(threshold) not in (int, float)
        or not math.isfinite(float(threshold))
        or not 0.0 <= float(threshold) <= 1.0
        or value.get("score_direction") != "higher"
        or value.get("threshold_operator") != ">"
        or value.get("scorer_semantics") != SCORER_SEMANTICS
        or value.get("context_repetition_handling") != "bounded_fifo_context_hash_v1"
        or value.get("eos_handling") != "mask_first_eos_and_after"
        or value.get("special_token_handling") != "tokenizer_add_special_tokens_false"
        or value.get("text_scope") != "candidate_text_only_no_prompt"
        or value.get("generation_text_serialization")
        != "tokenizer_decode_skip_special_tokens_false_cleanup_false_utf8_v1"
        or value.get("detector_text_tokenization")
        != "retokenize_add_special_tokens_false_fast_offsets_v1"
        or not _valid_weights(value.get("weights"), value.get("detector_type"), depth)
        or value.get("tokenizer_type") != "transformers_local_files_v1"
        or not _valid_public_identifier(value.get("tokenizer_revision"))
        or value.get("tokenizer_snapshot_sha256") != _sha256(_canonical(files))
        or value.get("upstream_repository") != UPSTREAM_REPOSITORY
        or value.get("upstream_revision") != UPSTREAM_REVISION
        or value.get("python_version") != platform.python_version()
        or value.get("platform_system") != platform.system()
        or value.get("platform_machine") != platform.machine()
        or sys.byteorder != "little"
        or value.get("byteorder") != "little"
        or not _valid_public_identifier(value.get("transformers_version"))
        or not _valid_public_identifier(value.get("tokenizers_version"))
    ):
        raise ValueError("configuration_unsupported")
    for name in (
        "threshold_evidence_sha256",
        "tokenizer_conformance_sha256",
        "watermark_target_sha256",
    ):
        if not isinstance(value.get(name), str) or _SHA256.fullmatch(value[name]) is None:
            raise ValueError("configuration_invalid")
    if value["watermark_target_sha256"] != _sha256(_canonical(_target_material(value))):
        raise ValueError("configuration_digest_mismatch")
    return value


def _load_configuration(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_CONFIGURATION_BYTES, "configuration_unavailable")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("configuration_invalid") from None
    return _validate_configuration(value)


def _to_int64(value: int) -> int:
    value &= _INT64_MASK
    return value - (1 << 64) if value > _INT64_MAX else value


def _accumulate_hash(current: int, values: Sequence[int]) -> int:
    for value in values:
        current = _to_int64(current + value)
        current = _to_int64(current * _HASH_MULTIPLIER)
        current = _to_int64(current + 1)
    return current


def _hash_iv(keys: Sequence[int]) -> int:
    raw = struct.pack(f"<{len(keys)}q", *keys)
    return int.from_bytes(hashlib.sha256(raw).digest(), byteorder="big") % _INT64_MAX


def _g_value(ngram_hash: int, key: int) -> int:
    value = _accumulate_hash(ngram_hash, (key,))
    for _ in range(12):
        value = _accumulate_hash(value, (1,)) >> 5
    return (value >> 30) % 2


def score_token_ids(
    token_ids: Sequence[int],
    *,
    keys: Sequence[int],
    ngram_len: int,
    context_history_size: int,
    eos_token_id: int,
    detector_type: str,
    weights: Sequence[float],
) -> dict[str, Any]:
    """Return content-free pinned hash/mask and Python-binary64 score intermediates."""
    if (
        not 2 <= ngram_len <= 64
        or not 1 <= len(keys) <= MAX_KEY_DEPTH
        or not 1 <= context_history_size <= MAX_CONTEXT_HISTORY_SIZE
        or len(token_ids) > MAX_INPUT_TOKENS
        or max(0, len(token_ids) - ngram_len + 1) * len(keys) > MAX_SCORING_CELLS
        or any(type(item) is not int or not 0 <= item <= _INT64_MAX for item in token_ids)
        or any(type(item) is not int or not 0 <= item <= _INT64_MAX for item in keys)
        or len(set(keys)) != len(keys)
        or type(eos_token_id) is not int
        or not 0 <= eos_token_id <= _INT64_MAX
    ):
        raise ValueError("scorer_input_invalid")
    if len(token_ids) < ngram_len:
        return {"effective_tokens": 0, "g_values": [], "mask": [], "score": None}
    iv = _hash_iv(keys)
    history = [0] * context_history_size
    first_eos = next((index for index, item in enumerate(token_ids) if item == eos_token_id), None)
    g_values: list[list[int]] = []
    mask: list[int] = []
    for start in range(len(token_ids) - ngram_len + 1):
        ngram = token_ids[start : start + ngram_len]
        ngram_hash = _accumulate_hash(iv, ngram)
        g_values.append([_g_value(ngram_hash, key) for key in keys])
        context_hash = _accumulate_hash(iv, ngram[:-1])
        repeated = context_hash in history
        history = [context_hash, *history[:-1]]
        end_index = start + ngram_len - 1
        before_eos = first_eos is None or end_index < first_eos
        mask.append(int(not repeated and before_eos))
    effective = sum(mask)
    if effective == 0:
        return {"effective_tokens": 0, "g_values": g_values, "mask": mask, "score": None}
    normalized_weights = _normalized_weights(weights, detector_type, len(keys))
    numerator = math.fsum(
        g * normalized_weights[depth]
        for row, keep in zip(g_values, mask)
        if keep
        for depth, g in enumerate(row)
    )
    score = numerator / (len(keys) * effective)
    return {"effective_tokens": effective, "g_values": g_values, "mask": mask, "score": score}


def _attributions(
    text: str,
    offsets: Sequence[Any],
    result: Mapping[str, Any],
    *,
    ngram_len: int,
    detector_type: str,
    weights: Sequence[float],
    maximum_attributions: int,
) -> list[dict[str, Any]]:
    g_values = result.get("g_values")
    mask = result.get("mask")
    if (
        not isinstance(g_values, list)
        or not isinstance(mask, list)
        or len(g_values) != len(mask)
        or (
            len(offsets) != len(g_values) + ngram_len - 1
            and not (not g_values and len(offsets) < ngram_len)
        )
        or not 1 <= maximum_attributions <= MAX_ATTRIBUTIONS
    ):
        raise ValueError("offset_mapping_invalid")
    normalized_offsets: list[tuple[int, int]] = []
    previous_end = 0
    for raw in offsets:
        if (
            not isinstance(raw, (list, tuple))
            or len(raw) != 2
            or type(raw[0]) is not int
            or type(raw[1]) is not int
        ):
            raise ValueError("offset_mapping_invalid")
        start, end = raw
        if start < 0 or end < start or end > len(text):
            raise ValueError("offset_mapping_invalid")
        if start != end:
            if start < previous_end:
                raise ValueError("offset_mapping_invalid")
            previous_end = end
        normalized_offsets.append((start, end))
    if not g_values:
        return []
    try:
        normalized_weights = _normalized_weights(weights, detector_type, len(g_values[0]))
    except ValueError:
        raise ValueError("offset_mapping_invalid") from None
    candidates: list[dict[str, Any]] = []
    for row_index, (row, keep) in enumerate(zip(g_values, mask)):
        if keep != 1:
            continue
        token_index = row_index + ngram_len - 1
        start, end = normalized_offsets[token_index]
        if start == end or not any(not character.isspace() for character in text[start:end]):
            continue
        if (
            not isinstance(row, list)
            or len(row) != len(normalized_weights)
            or any(item not in (0, 1) for item in row)
        ):
            raise ValueError("offset_mapping_invalid")
        contribution = math.fsum(
            item * normalized_weights[index] for index, item in enumerate(row)
        ) / len(row)
        if not math.isfinite(contribution):
            raise ValueError("offset_mapping_invalid")
        candidates.append({"start": start, "end": end, "score": contribution})
    selected = sorted(
        candidates,
        key=lambda item: (-float(item["score"]), int(item["start"]), int(item["end"])),
    )[:maximum_attributions]
    return sorted(selected, key=lambda item: (int(item["start"]), int(item["end"])))


def _load_runtime(tokenizer_dir: Path, configuration: Mapping[str, Any]) -> Any:
    if tokenizer_dir.is_symlink():
        raise ValueError("runtime_path_mismatch")
    if _tokenizer_snapshot(tokenizer_dir.absolute()) != configuration["tokenizer_files"]:
        raise ValueError("tokenizer_mismatch")
    try:
        import tokenizers
        import transformers
    except ImportError:
        raise ValueError("runtime_unavailable") from None
    if str(transformers.__version__) != configuration["transformers_version"]:
        raise ValueError("runtime_mismatch")
    if str(tokenizers.__version__) != configuration["tokenizers_version"]:
        raise ValueError("runtime_mismatch")
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(tokenizer_dir.absolute()), local_files_only=True, trust_remote_code=False
    )
    if tokenizer.is_fast is not True:
        raise ValueError("tokenizer_mismatch")
    if len(tokenizer) != configuration["vocab_size"]:
        raise ValueError("tokenizer_mismatch")
    if tokenizer.eos_token_id != configuration["eos_token_id"]:
        raise ValueError("tokenizer_mismatch")
    if _tokenizer_conformance(tokenizer) != configuration["tokenizer_conformance_sha256"]:
        raise ValueError("tokenizer_mismatch")
    return tokenizer


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


def _failure(
    configuration: Mapping[str, Any], reason: str, status: str = "detector_error"
) -> dict[str, Any]:
    return {
        **_base(configuration),
        "attributions": [],
        "effective_tokens": 0,
        "reason_code": reason,
        "score": None,
        "status": status,
    }


def handle(
    request: Mapping[str, Any],
    *,
    configuration: Mapping[str, Any],
    upstream_dir: Path,
    tokenizer_dir: Path,
    key_file: Path,
    secret_binding_file: Path,
) -> dict[str, Any]:
    if set(request) != {
        "action",
        "attribution",
        "configuration_sha256",
        "detector",
        "policy",
        "protocol_version",
        "text",
    }:
        return _failure(configuration, "invalid_request")
    if request.get("protocol_version") != PROTOCOL_VERSION or request.get("action") != "detect":
        return _failure(configuration, "incompatible_protocol")
    if request.get("detector") != configuration["identifier"]:
        return _failure(configuration, "detector_mismatch")
    if request.get("configuration_sha256") != configuration["configuration_sha256"]:
        return _failure(configuration, "configuration_mismatch", "configuration_mismatch")
    attribution = request.get("attribution")
    if (
        not isinstance(attribution, Mapping)
        or set(attribution) != {"kind", "maximum_attributions"}
        or attribution.get("kind") != configuration["attribution_kind"]
        or attribution.get("maximum_attributions") != configuration["maximum_attributions"]
    ):
        return _failure(configuration, "attribution_contract_mismatch", "configuration_mismatch")
    policy = request.get("policy")
    if (
        not isinstance(policy, Mapping)
        or set(policy) != {"allow_model_download", "allow_network"}
        or policy.get("allow_model_download") is not False
        or policy.get("allow_network") is not False
    ):
        return _failure(configuration, "offline_policy_required", "unsupported")
    text = request.get("text")
    if not isinstance(text, str):
        return _failure(configuration, "invalid_text")
    try:
        keys = _load_key(key_file, secret_binding_file, configuration)
        _verify_sources(upstream_dir.absolute())
        tokenizer = _load_runtime(tokenizer_dir.absolute(), configuration)
        encoded = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
        token_ids = encoded.get("input_ids") if isinstance(encoded, Mapping) else None
        offsets = encoded.get("offset_mapping") if isinstance(encoded, Mapping) else None
        if (
            not isinstance(token_ids, list)
            or not isinstance(offsets, list)
            or len(token_ids) > int(configuration["maximum_input_tokens"])
            or any(type(item) is not int for item in token_ids)
            or any(not 0 <= item < int(configuration["vocab_size"]) for item in token_ids)
        ):
            raise ValueError("tokenizer_result_invalid")
        result = score_token_ids(
            token_ids,
            keys=keys,
            ngram_len=int(configuration["ngram_len"]),
            context_history_size=int(configuration["context_history_size"]),
            eos_token_id=int(configuration["eos_token_id"]),
            detector_type=str(configuration["detector_type"]),
            weights=configuration["weights"],
        )
        effective = int(result["effective_tokens"])
        if effective < int(configuration["minimum_effective_tokens"]):
            response = _failure(configuration, "too_few_effective_tokens", "insufficient_evidence")
            response["effective_tokens"] = effective
            return response
        if effective > int(configuration["maximum_effective_tokens"]):
            response = _failure(configuration, "too_many_effective_tokens", "unsupported")
            response["effective_tokens"] = effective
            return response
        attributions = _attributions(
            text,
            offsets,
            result,
            ngram_len=int(configuration["ngram_len"]),
            detector_type=str(configuration["detector_type"]),
            weights=configuration["weights"],
            maximum_attributions=int(configuration["maximum_attributions"]),
        )
    except Exception:
        return _failure(configuration, "operator_runtime_failed")
    score = result["score"]
    if type(score) not in (int, float) or not math.isfinite(float(score)):
        return _failure(configuration, "operator_result_invalid")
    return {
        **_base(configuration),
        "attributions": attributions,
        "effective_tokens": effective,
        "score": float(score),
        "status": "detected"
        if float(score) > float(configuration["threshold"])
        else "not_detected",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-dir", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--secret-file", dest="secret_binding_file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        configuration = _load_configuration(args.configuration)
    except Exception:
        return 2
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request_too_large")
        request = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        response = (
            handle(
                request,
                configuration=configuration,
                upstream_dir=args.upstream_dir,
                tokenizer_dir=args.tokenizer_dir,
                key_file=args.key_file,
                secret_binding_file=args.secret_binding_file,
            )
            if isinstance(request, Mapping)
            else _failure(configuration, "invalid_request")
        )
    except Exception:
        response = _failure(configuration, "invalid_request")
    json.dump(response, sys.stdout, ensure_ascii=True, sort_keys=True, allow_nan=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
