#!/usr/bin/env python3
"""Rebuild the exact public KGW natural-text reference profile.

This maintenance command requires an already-installed, pinned upstream checkout
and a local key file.  It never opens a socket or downloads a tokenizer/model.
The key is used only to derive the public transition table; its unrelated opaque
identifier is copied into public artifacts for operator-side binding.
Raw key material is never written to a generated artifact or command output.
"""

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
import types
from pathlib import Path
from typing import Any

UPSTREAM_REVISION = "82922516930c02f8aa322765defdb5863d07a00e"
UPSTREAM_FILE_SHA256 = "512c40644bc9e9932a8674bbf13046c1a4e92db429cff92afc9e90d2226896fc"
SOURCE_URL = "https://github.com/jwkirchenbauer/lm-watermarking"
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


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        or not 0 <= value < (1 << 63)
        or not isinstance(key_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", key_id) is None
    ):
        raise ValueError("key file value is out of range")
    return value, key_id


def _load_upstream(source: Path) -> Any:
    if not source.is_file() or _file_digest(source) != UPSTREAM_FILE_SHA256:
        raise ValueError("upstream source mismatch")
    normalizers = types.ModuleType("normalizers")
    normalizers.normalization_strategy_lookup = lambda _name: None
    nltk = types.ModuleType("nltk")
    nltk_util = types.ModuleType("nltk.util")
    nltk_util.ngrams = lambda sequence, size: zip(*(sequence[index:] for index in range(size)))
    prior = {name: sys.modules.get(name) for name in ("normalizers", "nltk", "nltk.util")}
    sys.modules.update({"normalizers": normalizers, "nltk": nltk, "nltk.util": nltk_util})
    try:
        spec = importlib.util.spec_from_file_location("_dewatermark_kgw_profile_source", source)
        if spec is None or spec.loader is None:
            raise ValueError("upstream source cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name, old in prior.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
    return module


def _write(path: Path, value: Any) -> None:
    path.write_bytes(_pretty(value))


def build(upstream_dir: Path, key_file: Path, output_dir: Path) -> None:
    if len(POSITIVE_WORDS) != 97 or len(CONTROL_WORDS) != 97:
        raise RuntimeError("natural-language fixture length changed")
    if len(set(POSITIVE_WORDS + CONTROL_WORDS)) != 194:
        raise RuntimeError("natural-language fixture tokens must be disjoint and unique")
    output_dir.mkdir(parents=True, exist_ok=True)
    module = _load_upstream(upstream_dir / "watermark_processor.py")
    key, key_id = _read_key(key_file)
    vocab_size = 256
    gamma = 0.25
    detector = module.WatermarkDetector(
        vocab=list(range(vocab_size)),
        gamma=gamma,
        delta=2.0,
        seeding_scheme="simple_1",
        hash_key=key,
        select_green_tokens=True,
        device=module.torch.device("cpu"),
        tokenizer=type("FixtureTokenizer", (), {"bos_token_id": None})(),
        z_threshold=4.0,
        normalizers=[],
        ignore_repeated_bigrams=True,
    )
    source_vectors = json.loads((output_dir / "fixture-cases.json").read_text("utf-8"))
    positive_ids = [int(item[1:]) for item in source_vectors["vectors"][0]["text"].split()]
    control_ids = list(range(1, 98))
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

    rows: list[str] = []
    for previous in range(vocab_size):
        green = detector._get_greenlist_ids(
            module.torch.tensor([previous], dtype=module.torch.long)
        ).tolist()
        bits = sum(1 << int(token) for token in green)
        rows.append(f"{bits:064x}")
    transitions = {
        "gamma": gamma,
        "kind": "kgw-green-transition-bitset-v1",
        "rows": rows,
        "schema_version": "1.0",
        "seeding_scheme": "simple_1",
        "select_green_tokens": True,
        "vocab_size": vocab_size,
    }
    transitions_path = output_dir / "green-transitions-v1.json"
    _write(transitions_path, transitions)

    threshold_evidence = {
        "claim_limit": "analytical reference threshold; no empirical false-positive claim",
        "empirical_calibration": False,
        "minimum_effective_tokens": 32,
        "null_approximation": "Binomial(T, gamma) with a one-sided standard-normal survival value",
        "threshold_operator": ">",
        "schema_version": "1.0",
        "score": "z_score",
        "threshold": 4.0,
    }
    threshold_path = output_dir / "natural-threshold-evidence.json"
    _write(threshold_path, threshold_evidence)

    material_files = {
        "green-transitions-v1.json": _file_digest(transitions_path),
        "natural_adapter.py": _file_digest(output_dir / "natural_adapter.py"),
        "natural-threshold-evidence.json": _file_digest(threshold_path),
        "natural-tokenizer.json": _file_digest(tokenizer_path),
        "upstream/watermark_processor.py": UPSTREAM_FILE_SHA256,
    }
    material_manifest = {
        "attestation": {
            "release_artifact_provenance": "GitHub OIDC attestation for the containing distribution",
            "standalone_signature": False,
        },
        "files": material_files,
        "kind": "content-addressed-reference-profile-material-v1",
        "schema_version": "1.0",
        "source_repository": SOURCE_URL,
        "source_revision": UPSTREAM_REVISION,
    }
    material_path = output_dir / "natural-profile-material.json"
    _write(material_path, material_manifest)

    configuration = {
        "gamma": gamma,
        "identifier": "reference-upstream/kgw-simple1-natural-profile-v1",
        "ignore_repeated_bigrams": True,
        "key_id": key_id,
        "minimum_effective_tokens": 32,
        "normalization": "NFC+casefold",
        "p_value_method": "one_sided_standard_normal_survival",
        "profile_manifest_sha256": _file_digest(material_path),
        "schema_version": "1.0",
        "scheme": "kgw/simple-1-natural-reference-v1",
        "score_direction": "higher",
        "threshold_operator": ">",
        "seeding_scheme": "simple_1",
        "select_green_tokens": True,
        "threshold": 4.0,
        "threshold_evidence_sha256": _file_digest(threshold_path),
        "token_pattern": TOKEN_PATTERN,
        "tokenizer_sha256": _file_digest(tokenizer_path),
        "transition_recorded_torch_version": str(module.torch.__version__).split("+", 1)[0],
        "transition_table_sha256": _file_digest(transitions_path),
        "upstream_file_sha256": UPSTREAM_FILE_SHA256,
        "upstream_repository": SOURCE_URL,
        "upstream_revision": UPSTREAM_REVISION,
        "vocab_size": vocab_size,
    }
    configuration["configuration_sha256"] = _digest(_canonical(configuration))
    config_path = output_dir / "natural-adapter-config.json"
    _write(config_path, configuration)

    def upstream_score(token_ids: list[int]) -> dict[str, Any]:
        tensor = module.torch.tensor(token_ids, dtype=module.torch.long)
        score = detector.detect(tokenized_text=tensor, return_prediction=False)
        z_score = float(score["z_score"])
        return {
            "effective_tokens": int(score["num_tokens_scored"]),
            "p_value": float(score["p_value"]),
            "score": z_score,
            "status": "detected" if z_score > 4.0 else "not_detected",
            "z_score": z_score,
        }

    positive = upstream_score(positive_ids)
    control = upstream_score(control_ids)
    variant_ids = [vocabulary[item.casefold()] for item in re.findall(TOKEN_PATTERN, VARIANT_TEXT)]
    variant = upstream_score(variant_ids)
    if positive["effective_tokens"] != 96 or positive["status"] != "detected":
        raise ValueError("key does not match the public positive reference vector")
    vectors = {
        "description": "Natural-language vectors for one exact public KGW reference configuration.",
        "schema_version": "1.0",
        "vectors": [
            {
                **{f"expected_{key}": value for key, value in positive.items()},
                "name": "natural-reference-positive",
                "text": POSITIVE_TEXT,
            },
            {
                **{f"expected_{key}": value for key, value in control.items()},
                "name": "natural-length-control",
                "text": CONTROL_TEXT,
            },
            {
                **{f"expected_{key}": value for key, value in variant.items()},
                "name": "readable-positive-variant",
                "text": VARIANT_TEXT,
            },
            {
                "expected_effective_tokens": 0,
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
        "_dewatermark_kgw_natural_adapter", output_dir / "natural_adapter.py"
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
            transitions_path=transitions_path,
        )
        fields = ("status", "effective_tokens", "score", "p_value", "z_score")
        mismatches = []
        for field in fields:
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
    passed = all(case["passed"] for case in conformance_cases)
    if not passed:
        raise ValueError("portable/upstream cross-conformance failed")
    conformance = {
        "cases": conformance_cases,
        "configuration_sha256": configuration["configuration_sha256"],
        "independent_scorer": "natural_adapter.py transition-table scorer",
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
            "Readable closed-vocabulary KGW conformance fixture cross-conformed with the pinned "
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
            "source_license": "Apache-2.0",
            "source_revision": UPSTREAM_REVISION,
            "status": "exact_public_natural_reference_configuration",
            "threshold": 4.0,
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
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    try:
        build(args.upstream_dir.absolute(), args.key_file, args.output_dir.absolute())
    except Exception:
        print("profile build failed; details and key material were redacted", file=sys.stderr)
        return 1
    print("profile build completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
