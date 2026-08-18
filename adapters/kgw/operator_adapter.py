#!/usr/bin/env python3
"""Offline KGW adapter for an operator-sealed local tokenizer and private key.

Run ``seal_operator.py`` explicitly before registering this command.  Static
capability discovery reads only the generated public manifest.  Detection then
verifies the local tokenizer snapshot, pinned upstream source, runtime versions,
and an owner-only key file before any text is tokenized.  No code path downloads
a model/tokenizer, opens a socket, accepts key material in argv/environment, or
returns the key in output.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import stat
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

PROTOCOL_VERSION = "1.1"
MAX_CONFIGURATION_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_KEY_BYTES = 128
MAX_TOKENIZER_FILES = 128
MAX_TOKENIZER_FILE_BYTES = 64 * 1024 * 1024
MAX_TOKENIZER_TOTAL_BYTES = 512 * 1024 * 1024
UPSTREAM_REVISION = "82922516930c02f8aa322765defdb5863d07a00e"
UPSTREAM_FILE_SHA256 = "512c40644bc9e9932a8674bbf13046c1a4e92db429cff92afc9e90d2226896fc"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[0-9a-f]{32}")
_PUBLIC_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}")
_PUBLIC_RELATIVE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+\-=]{0,511}")
_URL_USERINFO = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s@]+@")
_CREDENTIAL_VALUE = re.compile(
    r"(?i)(?:\b(?:sk|rk)[-_](?:live|test|proj|ant)?[-_A-Za-z0-9]{8,}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\b(?:bearer|basic)\s+)"
)
_TOKENIZER_CREDENTIAL_VALUE = re.compile(
    r"(?i)(?:\b(?:sk|rk)[-_](?:live|test|proj|ant)?[-_A-Za-z0-9]{8,}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}\b)"
)
_CREDENTIAL_JSON_FRAGMENT = re.compile(
    r"(?i)[\"'](?:x[-_]?api[-_]?key|api[-_]?key|aws[-_]?secret[-_]?access[-_]?key|"
    r"authorization|client[-_]?secret|credential|credentials|password|private[-_]?key|"
    r"(?:access|api|auth|bearer|refresh|session)[-_]?token)[\"']\s*:"
)
_SECRET_VALUE_PATTERNS = (
    _TOKENIZER_CREDENTIAL_VALUE,
    re.compile(
        r"(?i)\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+"
        r"[A-Za-z0-9._~+/=-]{8,}\b"
    ),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)(?:^|[^A-Za-z0-9])(?:x[-_]?api[-_]?key|api[-_]?key|"
        r"aws[-_]?secret[-_]?access[-_]?key|authorization|credential|password|secret|"
        r"(?:access|api|auth|bearer|refresh|session)[-_]?token)"
        r"\s*[:=]\s*[\"']?[^\s,;\"']{8,}"
    ),
)
_PRIVATE_ABSOLUTE_PATH = re.compile(
    r"(?i)(?:^|[\s\"'(=:\[])(?:/(?!/)(?:[^/\s\"'<>]+/)+[^/\s\"'<>]+|"
    r"~[/\\][^\s\"'<>]+|[A-Za-z]:[/\\][^\s\"'<>]+|"
    r"\\\\[^\\\s]+\\[^\s\"'<>]+|file://[^\s\"'<>]+)"
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
_SENSITIVE_MARKER = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:api[-_]?key|credential|password|private|secret|token)"
    r"(?![A-Za-z0-9])"
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
    "bos_handling",
    "configuration_sha256",
    "delta",
    "gamma",
    "identifier",
    "ignore_repeated_bigrams",
    "key_id",
    "minimum_effective_tokens",
    "normalizers",
    "nltk_version",
    "p_value_method",
    "schema_version",
    "scheme",
    "score_direction",
    "threshold_operator",
    "seeding_scheme",
    "select_green_tokens",
    "threshold",
    "threshold_evidence_sha256",
    "tokenizer_files",
    "tokenizer_revision",
    "tokenizer_snapshot_sha256",
    "tokenizer_type",
    "tokenizers_version",
    "torch_version",
    "transformers_version",
    "python_version",
    "platform_machine",
    "platform_system",
    "byteorder",
    "scipy_version",
    "upstream_file_sha256",
    "upstream_repository",
    "upstream_revision",
    "vocab_size",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _read_regular(path: Path, limit: int, reason: str) -> bytes:
    descriptor = -1
    try:
        if path.is_symlink():
            raise ValueError(reason)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
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


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_configuration(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, MAX_CONFIGURATION_BYTES, "configuration_unavailable")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("configuration_invalid") from None
    return _validate_configuration(value)


def _valid_public_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _PUBLIC_IDENTIFIER.fullmatch(value) is not None
        and _URL_USERINFO.search(value) is None
        and _CREDENTIAL_VALUE.search(value) is None
        and len(_SENSITIVE_MARKER.findall(value)) < 2
        and ".." not in PurePosixPath(value).parts
        and not re.match(r"(?i)^[a-z]:/", value)
    )


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


def _unsafe_tokenizer_string(value: str) -> bool:
    return _unsafe_tokenizer_fragment(value) or any(
        ord(character) < 32 and character not in "\t\n\r" for character in value
    )


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non_finite_json_number")


def _validate_tokenizer_json(value: Any) -> None:
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        item, depth, vocabulary = stack.pop()
        if depth > 128:
            raise ValueError("tokenizer_contains_unsafe_content")
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or _unsafe_tokenizer_string(key):
                    raise ValueError("tokenizer_contains_unsafe_content")
                numeric_vocabulary_entry = vocabulary and type(child) in (int, float)
                if _credential_json_key(key) and not numeric_vocabulary_entry:
                    raise ValueError("tokenizer_contains_unsafe_content")
                child_is_vocabulary = (
                    _normal_json_key(key) in {"vocab", "vocabulary"} and type(child) is dict
                )
                stack.append((child, depth + 1, child_is_vocabulary))
        elif type(item) is list:
            stack.extend((child, depth + 1, False) for child in item)
        elif type(item) is str:
            if _unsafe_tokenizer_string(item):
                raise ValueError("tokenizer_contains_unsafe_content")
        elif item is None or type(item) in (bool, int, float):
            if type(item) is float and not math.isfinite(item):
                raise ValueError("tokenizer_contains_unsafe_content")
        else:
            raise ValueError("tokenizer_contains_unsafe_content")


def _validate_tokenizer_content(relative: str, raw: bytes) -> None:
    projected = raw.decode("utf-8", "ignore")
    lowered = relative.lower()
    if _unsafe_tokenizer_fragment(projected) or (
        not lowered.endswith(".json") and _CREDENTIAL_JSON_FRAGMENT.search(projected)
    ):
        raise ValueError("tokenizer_contains_unsafe_content")
    if lowered.endswith(".model"):
        # SentencePiece model artifacts are protobuf binaries. Only their
        # printable fragments can be screened without interpreting a format
        # that the pinned tokenizer runtime itself owns.
        return
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        # Explicit tokenizer snapshots may contain bounded binary model files.
        # Their printable fragments were checked above before the digest is made.
        if lowered.endswith(".json"):
            raise ValueError("tokenizer_contains_unsafe_content") from None
        return
    if _unsafe_tokenizer_string(text):
        raise ValueError("tokenizer_contains_unsafe_content")
    if not lowered.endswith(".json"):
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


def _validate_configuration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _EXPECTED_CONFIGURATION_KEYS:
        raise ValueError("configuration_invalid")
    declared = value.get("configuration_sha256")
    public = {key: item for key, item in value.items() if key != "configuration_sha256"}
    if not isinstance(declared, str) or declared != _sha256(_canonical(public)):
        raise ValueError("configuration_digest_mismatch")
    digests = (
        "threshold_evidence_sha256",
        "tokenizer_snapshot_sha256",
        "upstream_file_sha256",
    )
    if any(
        not isinstance(value.get(item), str) or not _SHA256.fullmatch(value[item])
        for item in digests
    ):
        raise ValueError("configuration_invalid")
    numeric = ("delta", "gamma", "threshold")
    if any(
        isinstance(value.get(item), bool)
        or not isinstance(value.get(item), (int, float))
        or not math.isfinite(float(value[item]))
        for item in numeric
    ):
        raise ValueError("configuration_invalid")
    minimum = value.get("minimum_effective_tokens")
    vocab_size = value.get("vocab_size")
    files = value.get("tokenizer_files")
    if (
        isinstance(minimum, bool)
        or not isinstance(minimum, int)
        or minimum < 1
        or isinstance(vocab_size, bool)
        or not isinstance(vocab_size, int)
        or vocab_size < 2
    ):
        raise ValueError("configuration_invalid")
    if (
        value.get("schema_version") != "1.0"
        or not _valid_public_identifier(value.get("identifier"))
        or not _valid_public_identifier(value.get("scheme"))
        or not isinstance(value.get("key_id"), str)
        or _KEY_ID.fullmatch(value["key_id"]) is None
        or not 0.0 < float(value["gamma"]) < 1.0
        or not 1 <= int(float(value["gamma"]) * int(vocab_size)) < int(vocab_size)
        or float(value["delta"]) < 0.0
        or float(value["threshold"]) <= 0.0
        or value.get("score_direction") != "higher"
        or value.get("threshold_operator") != ">"
        or value.get("p_value_method") != "one_sided_standard_normal_survival"
        or value.get("bos_handling") != "strip_if_present"
        or value.get("normalizers") != []
        or value.get("seeding_scheme") != "simple_1"
        or value.get("select_green_tokens") is not True
        or value.get("ignore_repeated_bigrams") is not True
        or value.get("tokenizer_type") != "transformers_local_files_v1"
        or not _valid_public_identifier(value.get("tokenizer_revision"))
        or minimum > vocab_size * vocab_size
        or not isinstance(files, dict)
        or not files
        or len(files) > MAX_TOKENIZER_FILES
        or value.get("upstream_repository") != "https://github.com/jwkirchenbauer/lm-watermarking"
        or value.get("upstream_revision") != UPSTREAM_REVISION
        or value.get("upstream_file_sha256") != UPSTREAM_FILE_SHA256
        or not all(
            _valid_public_identifier(value.get(item))
            for item in (
                "torch_version",
                "transformers_version",
                "tokenizers_version",
                "scipy_version",
                "nltk_version",
            )
        )
        or value.get("python_version") != platform.python_version()
        or value.get("platform_system") != platform.system()
        or value.get("platform_machine") != platform.machine()
        or value.get("byteorder") != sys.byteorder
    ):
        raise ValueError("configuration_unsupported")
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
            or not _SHA256.fullmatch(digest)
        ):
            raise ValueError("configuration_invalid")
    expected_snapshot = _sha256(_canonical(files))
    if value["tokenizer_snapshot_sha256"] != expected_snapshot:
        raise ValueError("configuration_digest_mismatch")
    return value


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
        ):
            raise ValueError("tokenizer_contains_sensitive_file")
        if _PUBLIC_RELATIVE_PATH.fullmatch(relative) is None:
            raise ValueError("tokenizer_contains_unsafe_filename")
        raw = _read_regular(path, MAX_TOKENIZER_FILE_BYTES, "tokenizer_unavailable")
        total_bytes += len(raw)
        if total_bytes > MAX_TOKENIZER_TOTAL_BYTES:
            raise ValueError("tokenizer_unavailable")
        _validate_tokenizer_content(relative, raw)
        result[relative] = _sha256(raw)
    return result


def _read_key_record(path: Path) -> tuple[int, str]:
    if os.name != "posix":
        # This reference adapter can prove owner and mode isolation only with
        # POSIX metadata. A purpose-built Windows adapter must validate the
        # file's ACL before it is allowed to read private key material.
        raise ValueError("key_permissions_unverifiable")
    descriptor = -1
    try:
        if path.is_symlink():
            raise ValueError("key_unavailable")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_KEY_BYTES
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("key_unavailable")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(MAX_KEY_BYTES + 1).strip()
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
    if not isinstance(record, dict) or set(record) != {"key", "key_id", "schema_version"}:
        raise ValueError("key_unavailable")
    key = record.get("key")
    key_id = record.get("key_id")
    if (
        record.get("schema_version") != "1.0"
        or isinstance(key, bool)
        or not isinstance(key, int)
        or not 0 <= key < (1 << 63)
        or not isinstance(key_id, str)
        or _KEY_ID.fullmatch(key_id) is None
    ):
        raise ValueError("key_unavailable")
    return key, key_id


def _load_key(path: Path, key_id: str, vocab_size: int) -> int:
    key, actual_id = _read_key_record(path)
    if actual_id != key_id:
        raise ValueError("key_mismatch")
    if key * (vocab_size - 1) > (1 << 63) - 1:
        raise ValueError("key_unavailable")
    return key


def _load_runtime(
    upstream_dir: Path, tokenizer_dir: Path, configuration: Mapping[str, Any]
) -> tuple[Any, Any]:
    if upstream_dir.is_symlink() or tokenizer_dir.is_symlink():
        raise ValueError("runtime_path_mismatch")
    source = upstream_dir.absolute() / "watermark_processor.py"
    if (
        _sha256(_read_regular(source, 4 * 1024 * 1024, "upstream_source_mismatch"))
        != UPSTREAM_FILE_SHA256
    ):
        raise ValueError("upstream_source_mismatch")
    if _tokenizer_snapshot(tokenizer_dir.absolute()) != configuration["tokenizer_files"]:
        raise ValueError("tokenizer_mismatch")
    import nltk
    import scipy
    import tokenizers
    import torch
    import transformers

    if str(torch.__version__) != configuration["torch_version"]:
        raise ValueError("runtime_mismatch")
    if str(transformers.__version__) != configuration["transformers_version"]:
        raise ValueError("runtime_mismatch")
    if str(tokenizers.__version__) != configuration["tokenizers_version"]:
        raise ValueError("runtime_mismatch")
    if str(scipy.__version__) != configuration["scipy_version"]:
        raise ValueError("runtime_mismatch")
    if str(nltk.__version__) != configuration["nltk_version"]:
        raise ValueError("runtime_mismatch")
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(tokenizer_dir.absolute()), local_files_only=True, trust_remote_code=False
    )
    if len(tokenizer) != configuration["vocab_size"]:
        raise ValueError("tokenizer_mismatch")
    normalizers = types.ModuleType("normalizers")
    normalizers.normalization_strategy_lookup = lambda _name: None
    prior = sys.modules.get("normalizers")
    sys.modules["normalizers"] = normalizers
    try:
        spec = importlib.util.spec_from_file_location("_dewatermark_operator_kgw", source)
        if spec is None or spec.loader is None:
            raise ValueError("upstream_load_failed")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if prior is None:
            sys.modules.pop("normalizers", None)
        else:
            sys.modules["normalizers"] = prior
    return module, tokenizer


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
) -> dict[str, Any]:
    if set(request) != {
        "action",
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
    policy = request.get("policy")
    if (
        not isinstance(policy, Mapping)
        or set(policy) != {"allow_model_download", "allow_network"}
        or type(policy.get("allow_model_download")) is not bool
        or type(policy.get("allow_network")) is not bool
    ):
        return _failure(configuration, "policy_invalid")
    text = request.get("text")
    if not isinstance(text, str):
        return _failure(configuration, "invalid_text")
    try:
        key = _load_key(
            key_file,
            str(configuration["key_id"]),
            int(configuration["vocab_size"]),
        )
        module, tokenizer = _load_runtime(upstream_dir, tokenizer_dir, configuration)
        encoded = tokenizer(text, add_special_tokens=False)
        token_ids = encoded.get("input_ids") if isinstance(encoded, Mapping) else None
        if (
            not isinstance(token_ids, list)
            or any(isinstance(item, bool) or not isinstance(item, int) for item in token_ids)
            or any(not 0 <= item < int(configuration["vocab_size"]) for item in token_ids)
        ):
            raise ValueError("tokenizer_result_invalid")
        if token_ids and token_ids[0] == tokenizer.bos_token_id:
            token_ids = token_ids[1:]
        if len(token_ids) < 2:
            return _failure(configuration, "too_few_effective_tokens", "insufficient_evidence")
        detector = module.WatermarkDetector(
            vocab=list(range(int(configuration["vocab_size"]))),
            gamma=float(configuration["gamma"]),
            delta=float(configuration["delta"]),
            seeding_scheme=str(configuration["seeding_scheme"]),
            hash_key=key,
            select_green_tokens=True,
            device=module.torch.device("cpu"),
            tokenizer=tokenizer,
            z_threshold=float(configuration["threshold"]),
            normalizers=[],
            ignore_repeated_bigrams=True,
        )
        scores = detector.detect(
            tokenized_text=module.torch.tensor(token_ids, dtype=module.torch.long),
            return_prediction=False,
        )
        z_score = float(scores["z_score"])
        p_value = float(scores["p_value"])
        effective_tokens = int(scores["num_tokens_scored"])
    except Exception:
        return _failure(configuration, "operator_runtime_failed")
    if not math.isfinite(z_score) or not math.isfinite(p_value) or not 0.0 <= p_value <= 1.0:
        return _failure(configuration, "operator_result_invalid")
    if effective_tokens < int(configuration["minimum_effective_tokens"]):
        return {
            **_failure(configuration, "too_few_effective_tokens", "insufficient_evidence"),
            "effective_tokens": effective_tokens,
        }
    status = "detected" if z_score > float(configuration["threshold"]) else "not_detected"
    return {
        **_base(configuration),
        "effective_tokens": effective_tokens,
        "p_value": p_value,
        "score": z_score,
        "status": status,
        "z_score": z_score,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--tokenizer-dir", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
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
                upstream_dir=args.upstream_dir,
                tokenizer_dir=args.tokenizer_dir,
                key_file=args.key_file,
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
