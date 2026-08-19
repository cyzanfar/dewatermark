#!/usr/bin/env python3
"""Rebuild the exact public Unigram natural-text reference profile offline."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
import tempfile
import types
from pathlib import Path
from statistics import NormalDist
from typing import Any

UPSTREAM_REVISION = "b96cdb4d52771e3cbd543a9d9aeeaec8d0790ca2"
UPSTREAM_FILE_SHA256 = "2059bf7057cd66784899379ca93492dfd217ae8fb4684e4d6cb02bca4c00d3b1"
SOURCE_URL = "https://github.com/XuandongZhao/Unigram-Watermark"
TOKEN_PATTERN = r"[^\W_]+(?:['’][^\W_]+)*"
POSITIVE_TEXT = """Careful researchers studying language provenance design transparent experiments
that separate calibration, development, validation, plus final evaluation cohorts. Every generated
passage uses documented prompts, models, tokenizers, configurations, keys, sampling parameters,
seeds, lengths, domains, and languages. Reviewers preserve facts, entities, numbers, quotations,
citations, hyperlinks, formatting, structure while measuring detector scores, false positives,
confidence intervals, editing distance, latency, memory, calls, cost. Reproducible evidence records
revisions, digests, thresholds, effective tokens, failures, abstentions, controls. Independent audits
compare original candidates through semantic, factual, grammatical, task checks before accepting
minimal changes. Honest reports limit conclusions to named schemes, exact settings, heldout samples.
This workflow."""
CONTROL_TEXT = """Modern software teams benefit when libraries offer predictable interfaces,
concise guides, stable releases, further helpful diagnostics. A newcomer should install one package,
run small example, understand its result, then explore advanced options gradually. Contributors need
focused modules, deterministic tests, clear ownership boundaries, reviewable modifications alongside
respectful discussion. Maintainers can automate styling, typing, builds, security scans, dependency
updates, artifact signing with changelog preparation. Users appreciate private defaults, bounded
resources, explicit consent, useful errors, portable commands, structured output, sensible extension
points. Strong projects earn trust by documenting limitations, publishing benchmarks, welcoming
replication, fixing mistakes quickly yet avoiding exaggerated promises."""
VARIANT_TEXT = """Independent researchers can compare detector output through reproducible tests.
Transparent evidence uses exact configurations, sampling seeds, tokenizers, revisions, effective
tokens, thresholds, confidence intervals, false positives, failures, abstentions, latency, and cost.
Careful reviewers preserve facts, entities, numbers, quotations, citations, hyperlinks, formatting,
plus structure before accepting minimal changes."""
POSITIVE_WORDS = [item.casefold() for item in re.findall(TOKEN_PATTERN, POSITIVE_TEXT)]
CONTROL_WORDS = [item.casefold() for item in re.findall(TOKEN_PATTERN, CONTROL_TEXT)]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _pretty(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_digest(path: Path) -> str:
    return _digest(path.read_bytes())


def _numeric_matches(field: str, actual: Any, expected: float) -> bool:
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return False
    number = float(actual)
    if not math.isfinite(number) or not math.isfinite(expected):
        return False
    if field == "p_value":
        if not 0.0 <= number <= 1.0 or not 0.0 <= expected <= 1.0:
            return False
        return (
            number == expected
            if number == 0.0 or expected == 0.0
            else math.isclose(math.log(number), math.log(expected), rel_tol=0.0, abs_tol=1e-10)
        )
    return math.isclose(number, expected, rel_tol=1e-12, abs_tol=1e-15)


def _read_key(path: Path) -> tuple[int, str]:
    if os.name != "posix":
        raise ValueError("key file permissions cannot be verified")
    descriptor = -1
    try:
        if path.is_symlink():
            raise ValueError("key file is unavailable")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > 128
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("key file is unavailable")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(129).strip()
    except ValueError:
        raise
    except OSError:
        raise ValueError("key file is unavailable") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        record = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("key file format is invalid") from None
    if not isinstance(record, dict) or set(record) != {"key", "key_id", "schema_version"}:
        raise ValueError("key file format is invalid")
    value = record.get("key")
    key_id = record.get("key_id")
    if (
        record.get("schema_version") != "1.0"
        or isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= (1 << 32) - 1
        or not isinstance(key_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", key_id) is None
    ):
        raise ValueError("key value is out of range")
    return value, key_id


def _load_upstream(source: Path) -> Any:
    if not source.is_file() or _file_digest(source) != UPSTREAM_FILE_SHA256:
        raise ValueError("upstream source mismatch")
    transformers = types.ModuleType("transformers")
    transformers.LogitsWarper = type("LogitsWarper", (), {})
    prior = sys.modules.get("transformers")
    sys.modules["transformers"] = transformers
    try:
        spec = importlib.util.spec_from_file_location("_dewatermark_unigram_profile_source", source)
        if spec is None or spec.loader is None:
            raise ValueError("upstream source cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if prior is None:
            sys.modules.pop("transformers", None)
        else:
            sys.modules["transformers"] = prior
    return module


def _write(path: Path, value: Any) -> None:
    path.write_bytes(_pretty(value))


def _read_public_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if len(raw) > 256 * 1024:
        raise ValueError("public profile artifact is too large")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("public profile artifact is invalid") from None
    if not isinstance(value, dict):
        raise ValueError("public profile artifact is invalid")
    return value, raw


def _conformance_record(
    configuration_sha256: str, cases: list[dict[str, Any]], vectors_sha256: str
) -> dict[str, Any]:
    return {
        "cases": cases,
        "configuration_sha256": configuration_sha256,
        "independent_scorer": "natural_adapter.py fixed-mask scorer",
        "numeric_absolute_tolerance": 1e-15,
        "numeric_relative_tolerance": 1e-12,
        "p_value_log_absolute_tolerance": 1e-10,
        "passed": True,
        "protocol_version": "1.1",
        "upstream_implementation": f"{SOURCE_URL}@{UPSTREAM_REVISION}",
        "vectors_sha256": vectors_sha256,
    }


def _capability(
    configuration: dict[str, Any],
    profile_manifest_sha256: str,
    record_sha256: str,
    vectors_sha256: str,
) -> dict[str, Any]:
    return {
        "calibrated": False,
        "description": (
            "Readable closed-vocabulary Unigram conformance fixture cross-conformed with the "
            "pinned author implementation; analytical threshold only, not production detection."
        ),
        "identifier": configuration["identifier"],
        "independent": True,
        "kind": "detector",
        "metadata": {
            "calibration": "analytical_only_not_empirically_calibrated",
            "command_protocol_version": "1.1",
            "configuration_sha256": configuration["configuration_sha256"],
            "cross_implementation_conformance": {
                "passed": True,
                "record_sha256": record_sha256,
                "vectors_sha256": vectors_sha256,
            },
            "evidence_level": "independent_detector",
            "key_id": configuration["key_id"],
            "minimum_effective_tokens": 32,
            "production_detection": False,
            "profile_manifest_sha256": profile_manifest_sha256,
            "score_direction": "higher",
            "threshold_operator": ">",
            "source": SOURCE_URL,
            "source_file_sha256": UPSTREAM_FILE_SHA256,
            "source_license": "MIT",
            "source_revision": UPSTREAM_REVISION,
            "status": "exact_public_natural_reference_configuration",
            "threshold": configuration["threshold"],
            "threshold_evidence_sha256": configuration["threshold_evidence_sha256"],
            "threat_models": ["T2"],
            "tokenizer_sha256": configuration["tokenizer_sha256"],
            "upstream_equivalent_for_reference_configuration": True,
            "vendor_equivalent": False,
        },
        "minimum_characters": 0,
        "model_download_possible": False,
        "network_required": False,
        "requires_secret": False,
        "schemes": [configuration["scheme"]],
        "version": "1.0",
    }


def _portable_cases(
    adapter: Any,
    configuration: dict[str, Any],
    vectors: dict[str, Any],
    directory: Path,
) -> list[dict[str, Any]]:
    cases = []
    for vector in vectors["vectors"]:
        response = adapter.handle(
            {
                "action": "detect",
                "configuration_sha256": configuration["configuration_sha256"],
                "detector": configuration["identifier"],
                "policy": {"allow_model_download": False, "allow_network": False},
                "protocol_version": "1.1",
                "text": vector["text"],
            },
            configuration=configuration,
            tokenizer_path=directory / "natural-tokenizer.json",
            mask_path=directory / "green-mask-v1.json",
        )
        mismatches = []
        for field in ("status", "effective_tokens", "score", "p_value", "z_score"):
            actual = response.get(field)
            expected = vector.get(f"expected_{field}")
            if isinstance(expected, float):
                if not _numeric_matches(field, actual, expected):
                    mismatches.append(field)
            elif actual != expected:
                mismatches.append(field)
        cases.append(
            {"mismatches": sorted(mismatches), "name": vector["name"], "passed": not mismatches}
        )
    return cases


def _validate_vectors(vectors: dict[str, Any]) -> list[dict[str, Any]]:
    expected_names_and_text = (
        ("natural-reference-positive", POSITIVE_TEXT),
        ("natural-length-control", CONTROL_TEXT),
        ("readable-positive-variant", VARIANT_TEXT),
        ("natural-short-abstention", POSITIVE_WORDS[0]),
    )
    items = vectors.get("vectors")
    if (
        set(vectors) != {"description", "schema_version", "vectors"}
        or vectors.get("schema_version") != "1.0"
        or vectors.get("description")
        != "Natural-language vectors for one exact public Unigram reference configuration."
        or not isinstance(items, list)
        or len(items) != len(expected_names_and_text)
    ):
        raise ValueError("public fixture vectors are invalid")
    expected_keys = {
        "expected_effective_tokens",
        "expected_p_value",
        "expected_score",
        "expected_status",
        "expected_z_score",
        "name",
        "text",
    }
    for item, (name, text) in zip(items, expected_names_and_text):
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise ValueError("public fixture vectors are invalid")
        if item.get("name") != name or item.get("text") != text:
            raise ValueError("public fixture vectors are invalid")
    return [
        {"mismatches": [], "name": name, "passed": True} for name, _text in expected_names_and_text
    ]


def _validate_existing_bindings(output_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    material, material_raw = _read_public_json(output_dir / "natural-profile-material.json")
    files = material.get("files")
    expected_file_names = {
        "green-mask-v1.json",
        "natural-threshold-evidence.json",
        "natural-tokenizer.json",
        "natural_adapter.py",
        "upstream/gptwm.py",
    }
    if (
        set(material)
        != {
            "attestation",
            "files",
            "kind",
            "schema_version",
            "source_repository",
            "source_revision",
        }
        or material.get("attestation")
        != {
            "release_artifact_provenance": (
                "GitHub OIDC attestation for the containing distribution"
            ),
            "standalone_signature": False,
        }
        or material.get("kind") != "content-addressed-reference-profile-material-v1"
        or material.get("schema_version") != "1.0"
        or material.get("source_repository") != SOURCE_URL
        or material.get("source_revision") != UPSTREAM_REVISION
        or not isinstance(files, dict)
        or set(files) != expected_file_names
        or files.get("upstream/gptwm.py") != UPSTREAM_FILE_SHA256
    ):
        raise ValueError("public profile material is invalid")
    for filename in expected_file_names - {"natural_adapter.py", "upstream/gptwm.py"}:
        if files.get(filename) != _file_digest(output_dir / filename):
            raise ValueError("public profile material is invalid")

    configuration, _configuration_raw = _read_public_json(
        output_dir / "natural-adapter-config.json"
    )
    public_configuration = dict(configuration)
    declared_configuration_sha256 = public_configuration.pop("configuration_sha256", None)
    expected_configuration_keys = {
        "alpha",
        "configuration_sha256",
        "dynamic_threshold_method",
        "fraction",
        "green_mask_sha256",
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
        "threshold",
        "threshold_evidence_sha256",
        "threshold_operator",
        "token_pattern",
        "tokenizer_sha256",
        "unique_tokens",
        "upstream_file_sha256",
        "upstream_repository",
        "upstream_revision",
        "vocab_size",
    }
    threshold = NormalDist().inv_cdf(0.99)
    if (
        set(configuration) != expected_configuration_keys
        or declared_configuration_sha256 != _digest(_canonical(public_configuration))
        or configuration.get("alpha") != 0.01
        or configuration.get("dynamic_threshold_method") != "finite_population_unique_tokens"
        or configuration.get("fraction") != 0.5
        or configuration.get("green_mask_sha256") != _file_digest(output_dir / "green-mask-v1.json")
        or configuration.get("identifier") != "reference-upstream/unigram-natural-profile-v1"
        or not isinstance(configuration.get("key_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", configuration["key_id"]) is None
        or not isinstance(configuration.get("mask_recorded_numpy_version"), str)
        or not configuration["mask_recorded_numpy_version"]
        or configuration.get("minimum_effective_tokens") != 32
        or configuration.get("normalization") != "NFC+casefold"
        or configuration.get("p_value_method") != "one_sided_standard_normal_survival"
        or configuration.get("profile_manifest_sha256") != _digest(material_raw)
        or configuration.get("reported_z_score") != "finite_population_adjusted"
        or configuration.get("schema_version") != "1.0"
        or configuration.get("scheme") != "unigram/unique-natural-reference-v1"
        or configuration.get("score_direction") != "higher"
        or configuration.get("threshold") != threshold
        or configuration.get("threshold_evidence_sha256")
        != _file_digest(output_dir / "natural-threshold-evidence.json")
        or configuration.get("threshold_operator") != ">"
        or configuration.get("token_pattern") != TOKEN_PATTERN
        or configuration.get("tokenizer_sha256")
        != _file_digest(output_dir / "natural-tokenizer.json")
        or configuration.get("unique_tokens") is not True
        or configuration.get("upstream_file_sha256") != UPSTREAM_FILE_SHA256
        or configuration.get("upstream_repository") != SOURCE_URL
        or configuration.get("upstream_revision") != UPSTREAM_REVISION
        or configuration.get("vocab_size") != 256
    ):
        raise ValueError("public profile configuration is invalid")

    vectors, vectors_raw = _read_public_json(output_dir / "natural-fixture-cases.json")
    clean_cases = _validate_vectors(vectors)
    vectors_sha256 = _digest(vectors_raw)
    conformance, conformance_raw = _read_public_json(output_dir / "natural-conformance-record.json")
    if conformance != _conformance_record(
        configuration["configuration_sha256"], clean_cases, vectors_sha256
    ):
        raise ValueError("public conformance record is invalid")
    capability, _capability_raw = _read_public_json(output_dir / "natural-capability.json")
    if capability != _capability(
        configuration,
        configuration["profile_manifest_sha256"],
        _digest(conformance_raw),
        vectors_sha256,
    ):
        raise ValueError("public capability is invalid")
    return configuration, vectors


def _publish_staged_bindings(output_dir: Path, staging: Path) -> None:
    filenames = (
        "natural-profile-material.json",
        "natural-adapter-config.json",
        "natural-conformance-record.json",
        "natural-capability.json",
    )
    originals = {filename: (output_dir / filename).read_bytes() for filename in filenames}
    published: list[str] = []
    try:
        for filename in filenames:
            os.replace(staging / filename, output_dir / filename)
            published.append(filename)
    except OSError:
        for filename in published:
            restore = staging / f"restore-{filename}"
            restore.write_bytes(originals[filename])
            os.replace(restore, output_dir / filename)
        raise


def refresh_bindings(output_dir: Path) -> None:
    output_dir = output_dir.absolute()
    existing_configuration, vectors = _validate_existing_bindings(output_dir)
    static_filenames = (
        "green-mask-v1.json",
        "natural-fixture-cases.json",
        "natural-threshold-evidence.json",
        "natural-tokenizer.json",
        "natural_adapter.py",
        "natural_conformance.py",
    )
    with tempfile.TemporaryDirectory(prefix=".natural-profile-refresh-", dir=output_dir) as raw:
        staging = Path(raw)
        for filename in static_filenames:
            (staging / filename).write_bytes((output_dir / filename).read_bytes())

        material = {
            "attestation": {
                "release_artifact_provenance": (
                    "GitHub OIDC attestation for the containing distribution"
                ),
                "standalone_signature": False,
            },
            "files": {
                "green-mask-v1.json": _file_digest(staging / "green-mask-v1.json"),
                "natural-threshold-evidence.json": _file_digest(
                    staging / "natural-threshold-evidence.json"
                ),
                "natural-tokenizer.json": _file_digest(staging / "natural-tokenizer.json"),
                "natural_adapter.py": _file_digest(staging / "natural_adapter.py"),
                "upstream/gptwm.py": UPSTREAM_FILE_SHA256,
            },
            "kind": "content-addressed-reference-profile-material-v1",
            "schema_version": "1.0",
            "source_repository": SOURCE_URL,
            "source_revision": UPSTREAM_REVISION,
        }
        _write(staging / "natural-profile-material.json", material)
        configuration = dict(existing_configuration)
        configuration["profile_manifest_sha256"] = _file_digest(
            staging / "natural-profile-material.json"
        )
        public_configuration = {
            key: value for key, value in configuration.items() if key != "configuration_sha256"
        }
        configuration["configuration_sha256"] = _digest(_canonical(public_configuration))
        _write(staging / "natural-adapter-config.json", configuration)

        adapter_spec = importlib.util.spec_from_file_location(
            "_dewatermark_unigram_refreshed_natural_adapter", staging / "natural_adapter.py"
        )
        if adapter_spec is None or adapter_spec.loader is None:
            raise ValueError("natural adapter cannot be loaded")
        adapter = importlib.util.module_from_spec(adapter_spec)
        adapter_spec.loader.exec_module(adapter)
        staged_configuration = adapter._load_configuration(staging / "natural-adapter-config.json")
        cases = _portable_cases(adapter, staged_configuration, vectors, staging)
        if cases != _validate_vectors(vectors):
            raise ValueError("adapter semantic fixture outputs changed")
        vectors_sha256 = _file_digest(staging / "natural-fixture-cases.json")
        conformance = _conformance_record(
            configuration["configuration_sha256"], cases, vectors_sha256
        )
        _write(staging / "natural-conformance-record.json", conformance)
        capability = _capability(
            configuration,
            configuration["profile_manifest_sha256"],
            _file_digest(staging / "natural-conformance-record.json"),
            vectors_sha256,
        )
        _write(staging / "natural-capability.json", capability)

        runner_spec = importlib.util.spec_from_file_location(
            "_dewatermark_unigram_refreshed_natural_conformance",
            staging / "natural_conformance.py",
        )
        if runner_spec is None or runner_spec.loader is None:
            raise ValueError("natural conformance runner cannot be loaded")
        runner = importlib.util.module_from_spec(runner_spec)
        runner_spec.loader.exec_module(runner)
        report = runner.run(staging)
        if report.get("passed") is not True:
            raise ValueError("refreshed natural conformance failed")
        _publish_staged_bindings(output_dir, staging)


def build(upstream_dir: Path, key_file: Path, output_dir: Path) -> None:
    if len(POSITIVE_WORDS) != 97 or len(CONTROL_WORDS) != 97:
        raise RuntimeError("natural-language fixture length changed")
    if len(set(POSITIVE_WORDS + CONTROL_WORDS)) != 194:
        raise RuntimeError("natural-language fixture tokens must be disjoint and unique")
    output_dir.mkdir(parents=True, exist_ok=True)
    module = _load_upstream(upstream_dir / "gptwm.py")
    key, key_id = _read_key(key_file)
    vocab_size = 256
    fraction = 0.5
    alpha = 0.01
    threshold = NormalDist().inv_cdf(1.0 - alpha)
    detector = module.GPTWatermarkDetector(
        fraction=fraction, strength=2.0, vocab_size=vocab_size, watermark_key=key
    )
    green_ids = [index for index, item in enumerate(detector.green_list_mask.tolist()) if item]
    red_ids = [index for index, item in enumerate(detector.green_list_mask.tolist()) if not item]
    if len(green_ids) != 128 or len(red_ids) != 128:
        raise ValueError("upstream mask has an unexpected partition")
    positive_ids = green_ids[:97]
    control_ids = red_ids[:97]
    vocabulary = dict(zip(POSITIVE_WORDS, positive_ids))
    vocabulary.update(zip(CONTROL_WORDS, control_ids))
    tokenizer = {
        "casefold": True,
        "kind": "dewatermark-natural-lexicon-v1",
        "normalization": "NFC",
        "schema_version": "1.0",
        "token_pattern": TOKEN_PATTERN,
        "unknown_policy": "abstain",
        "vocab_size": vocab_size,
        "vocabulary": vocabulary,
    }
    tokenizer_path = output_dir / "natural-tokenizer.json"
    _write(tokenizer_path, tokenizer)
    mask_bits = sum(1 << index for index in green_ids)
    mask = {
        "fraction": fraction,
        "green_mask": f"{mask_bits:064x}",
        "kind": "unigram-fixed-green-mask-bitset-v1",
        "schema_version": "1.0",
        "vocab_size": vocab_size,
    }
    mask_path = output_dir / "green-mask-v1.json"
    _write(mask_path, mask)
    threshold_evidence = {
        "alpha": alpha,
        "claim_limit": "analytical dynamic threshold; no empirical false-positive claim",
        "empirical_calibration": False,
        "finite_population_factor": "sqrt(1 - (m - 1) / (N - 1))",
        "minimum_unique_tokens": 32,
        "null_approximation": "one-sided standard-normal survival after finite-population correction",
        "schema_version": "1.0",
        "threshold_operator": ">",
        "score": "finite_population_adjusted_z_score",
        "threshold": threshold,
    }
    threshold_path = output_dir / "natural-threshold-evidence.json"
    _write(threshold_path, threshold_evidence)
    material = {
        "attestation": {
            "release_artifact_provenance": "GitHub OIDC attestation for the containing distribution",
            "standalone_signature": False,
        },
        "files": {
            "green-mask-v1.json": _file_digest(mask_path),
            "natural_adapter.py": _file_digest(output_dir / "natural_adapter.py"),
            "natural-threshold-evidence.json": _file_digest(threshold_path),
            "natural-tokenizer.json": _file_digest(tokenizer_path),
            "upstream/gptwm.py": UPSTREAM_FILE_SHA256,
        },
        "kind": "content-addressed-reference-profile-material-v1",
        "schema_version": "1.0",
        "source_repository": SOURCE_URL,
        "source_revision": UPSTREAM_REVISION,
    }
    material_path = output_dir / "natural-profile-material.json"
    _write(material_path, material)
    configuration = {
        "alpha": alpha,
        "dynamic_threshold_method": "finite_population_unique_tokens",
        "fraction": fraction,
        "green_mask_sha256": _file_digest(mask_path),
        "identifier": "reference-upstream/unigram-natural-profile-v1",
        "key_id": key_id,
        "mask_recorded_numpy_version": str(module.np.__version__),
        "minimum_effective_tokens": 32,
        "normalization": "NFC+casefold",
        "p_value_method": "one_sided_standard_normal_survival",
        "profile_manifest_sha256": _file_digest(material_path),
        "reported_z_score": "finite_population_adjusted",
        "schema_version": "1.0",
        "scheme": "unigram/unique-natural-reference-v1",
        "score_direction": "higher",
        "threshold": threshold,
        "threshold_operator": ">",
        "threshold_evidence_sha256": _file_digest(threshold_path),
        "token_pattern": TOKEN_PATTERN,
        "tokenizer_sha256": _file_digest(tokenizer_path),
        "unique_tokens": True,
        "upstream_file_sha256": UPSTREAM_FILE_SHA256,
        "upstream_repository": SOURCE_URL,
        "upstream_revision": UPSTREAM_REVISION,
        "vocab_size": vocab_size,
    }
    configuration["configuration_sha256"] = _digest(_canonical(configuration))
    config_path = output_dir / "natural-adapter-config.json"
    _write(config_path, configuration)

    def upstream_score(token_ids: list[int]) -> dict[str, Any]:
        unique = list(set(token_ids))
        raw_z = float(detector.unidetect(unique))
        factor = math.sqrt(1.0 - (len(unique) - 1.0) / (vocab_size - 1.0))
        adjusted = raw_z / factor if factor > 0 else 0.0
        p_value = 0.5 * math.erfc(adjusted / math.sqrt(2.0)) if factor > 0 else 1.0
        return {
            "effective_tokens": len(unique),
            "p_value": p_value,
            "score": adjusted,
            "status": "detected" if adjusted > threshold else "not_detected",
            "z_score": adjusted,
        }

    variant_ids = [vocabulary[item.casefold()] for item in re.findall(TOKEN_PATTERN, VARIANT_TEXT)]
    vectors = {
        "description": "Natural-language vectors for one exact public Unigram reference configuration.",
        "schema_version": "1.0",
        "vectors": [
            {
                **{
                    f"expected_{name}": value
                    for name, value in upstream_score(positive_ids).items()
                },
                "name": "natural-reference-positive",
                "text": POSITIVE_TEXT,
            },
            {
                **{
                    f"expected_{name}": value for name, value in upstream_score(control_ids).items()
                },
                "name": "natural-length-control",
                "text": CONTROL_TEXT,
            },
            {
                **{
                    f"expected_{name}": value for name, value in upstream_score(variant_ids).items()
                },
                "name": "readable-positive-variant",
                "text": VARIANT_TEXT,
            },
            {
                "expected_effective_tokens": 1,
                "expected_p_value": None,
                "expected_score": None,
                "expected_status": "insufficient_evidence",
                "expected_z_score": None,
                "name": "natural-short-abstention",
                "text": POSITIVE_WORDS[0],
            },
        ],
    }
    vectors_path = output_dir / "natural-fixture-cases.json"
    _write(vectors_path, vectors)
    adapter_spec = importlib.util.spec_from_file_location(
        "_dewatermark_unigram_natural_adapter", output_dir / "natural_adapter.py"
    )
    if adapter_spec is None or adapter_spec.loader is None:
        raise ValueError("natural adapter cannot be loaded")
    adapter = importlib.util.module_from_spec(adapter_spec)
    adapter_spec.loader.exec_module(adapter)
    portable_configuration = adapter._load_configuration(config_path)
    conformance_cases = []
    for vector in vectors["vectors"]:
        response = adapter.handle(
            {
                "action": "detect",
                "configuration_sha256": configuration["configuration_sha256"],
                "detector": configuration["identifier"],
                "policy": {"allow_model_download": False, "allow_network": False},
                "protocol_version": "1.1",
                "text": vector["text"],
            },
            configuration=portable_configuration,
            tokenizer_path=tokenizer_path,
            mask_path=mask_path,
        )
        mismatches = []
        for field in ("status", "effective_tokens", "score", "p_value", "z_score"):
            actual = response.get(field)
            expected = vector.get(f"expected_{field}")
            if isinstance(expected, float):
                if not _numeric_matches(field, actual, expected):
                    mismatches.append(field)
            elif actual != expected:
                mismatches.append(field)
        conformance_cases.append(
            {"mismatches": sorted(mismatches), "name": vector["name"], "passed": not mismatches}
        )
    if not all(item["passed"] for item in conformance_cases):
        raise ValueError("portable/upstream cross-conformance failed")
    conformance = {
        "cases": conformance_cases,
        "configuration_sha256": configuration["configuration_sha256"],
        "independent_scorer": "natural_adapter.py fixed-mask scorer",
        "numeric_absolute_tolerance": 1e-15,
        "numeric_relative_tolerance": 1e-12,
        "p_value_log_absolute_tolerance": 1e-10,
        "passed": True,
        "protocol_version": "1.1",
        "upstream_implementation": f"{SOURCE_URL}@{UPSTREAM_REVISION}",
        "vectors_sha256": _file_digest(vectors_path),
    }
    conformance_path = output_dir / "natural-conformance-record.json"
    _write(conformance_path, conformance)
    capability = {
        "calibrated": False,
        "description": (
            "Readable closed-vocabulary Unigram conformance fixture cross-conformed with the pinned "
            "author implementation; analytical threshold only, not production detection."
        ),
        "identifier": configuration["identifier"],
        "independent": True,
        "kind": "detector",
        "metadata": {
            "calibration": "analytical_only_not_empirically_calibrated",
            "command_protocol_version": "1.1",
            "configuration_sha256": configuration["configuration_sha256"],
            "cross_implementation_conformance": {
                "passed": True,
                "record_sha256": _file_digest(conformance_path),
                "vectors_sha256": _file_digest(vectors_path),
            },
            "evidence_level": "independent_detector",
            "key_id": key_id,
            "minimum_effective_tokens": 32,
            "production_detection": False,
            "profile_manifest_sha256": _file_digest(material_path),
            "score_direction": "higher",
            "threshold_operator": ">",
            "source": SOURCE_URL,
            "source_file_sha256": UPSTREAM_FILE_SHA256,
            "source_license": "MIT",
            "source_revision": UPSTREAM_REVISION,
            "status": "exact_public_natural_reference_configuration",
            "threshold": threshold,
            "threshold_evidence_sha256": _file_digest(threshold_path),
            "threat_models": ["T2"],
            "tokenizer_sha256": _file_digest(tokenizer_path),
            "upstream_equivalent_for_reference_configuration": True,
            "vendor_equivalent": False,
        },
        "minimum_characters": 0,
        "model_download_possible": False,
        "network_required": False,
        "requires_secret": False,
        "schemes": [configuration["scheme"]],
        "version": "1.0",
    }
    _write(output_dir / "natural-capability.json", capability)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument(
        "--refresh-bindings",
        action="store_true",
        help="transactionally rebind a behavior-preserving adapter change to public artifacts",
    )
    args = parser.parse_args()
    if args.refresh_bindings:
        if args.upstream_dir is not None or args.key_file is not None:
            parser.error("--refresh-bindings cannot be combined with upstream or key inputs")
    elif args.upstream_dir is None or args.key_file is None:
        parser.error("--upstream-dir and --key-file are required for a full rebuild")
    try:
        if args.refresh_bindings:
            refresh_bindings(args.output_dir)
        else:
            build(args.upstream_dir.absolute(), args.key_file, args.output_dir.absolute())
    except Exception:
        print("profile build failed; details and key material were redacted", file=sys.stderr)
        return 1
    print("profile bindings refreshed" if args.refresh_bindings else "profile build completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
