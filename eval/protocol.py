"""Machine-enforced benchmark registries and coverage assessment.

This module deliberately separates *harness coverage* from empirical evidence.
Passing these validators means that required metadata and strata are present;
it does not establish efficacy or human authorship.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    from .manifest import canonical_json
    from .public_codes import (
        COVERAGE_COMPLETE_REASON_CODES_BY_AREA,
        COVERAGE_REASON_CODES_BY_AREA,
        HUMAN_CONTROL_RISK_CODES,
        is_code_or_commitment,
        is_public_token,
    )
except ImportError:  # direct-script compatibility
    from manifest import canonical_json  # type: ignore
    from public_codes import (  # type: ignore
        COVERAGE_COMPLETE_REASON_CODES_BY_AREA,
        COVERAGE_REASON_CODES_BY_AREA,
        HUMAN_CONTROL_RISK_CODES,
        is_code_or_commitment,
        is_public_token,
    )

PROTOCOL_REGISTRY_PATH = Path(__file__).with_name("protocol-registry-v1.json")
MAX_REGISTRY_BYTES = 4 * 1024 * 1024
SAMPLE_REGISTRY_SCHEMA_VERSION = "1.0"
COVERAGE_STATES = {"complete", "partial", "not_run", "not_available", "not_applicable"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_FORBIDDEN_CONTENT_KEYS = {
    "body",
    "candidate_text",
    "completion",
    "content",
    "document",
    "human_text",
    "input",
    "output",
    "prompt",
    "raw",
    "response",
    "source_text",
    "text",
}
_SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}
_COVERAGE_FIELDS = {
    "state",
    "reason",
    "tuning_key_count",
    "final_test_key_count",
    "observed",
    "missing",
    "missing_final_test_matrix_cells",
    "missing_checker_kinds",
    "observed_languages",
    "missing_groups",
}


class ProtocolValidationError(ValueError):
    """A registry or evidence declaration violates the public protocol."""


def _read_bounded_json(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        if path.is_symlink():
            raise ProtocolValidationError("registry is not a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REGISTRY_BYTES:
            raise ProtocolValidationError("registry is not a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(MAX_REGISTRY_BYTES + 1)
        if len(data) > MAX_REGISTRY_BYTES:
            raise ProtocolValidationError("registry exceeds the size limit")
        value = json.loads(data.decode("utf-8"))
    except ProtocolValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ProtocolValidationError("registry is not readable bounded JSON") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not isinstance(value, dict):
        raise ProtocolValidationError("registry must contain one JSON object")
    return value


def _ids(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ProtocolValidationError(f"{label} registry must be a non-empty array")
    result: list[str] = []
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(value.get("id"), str):
            raise ProtocolValidationError(f"each {label} entry requires an id")
        identifier = str(value["id"])
        if not _PUBLIC_ID.fullmatch(identifier):
            raise ProtocolValidationError(f"invalid public {label} id; value was redacted")
        result.append(identifier)
    if len(result) != len(set(result)):
        raise ProtocolValidationError(f"duplicate {label} ids")
    return result


def validate_protocol_registry(registry: Mapping[str, Any]) -> dict[str, Any]:
    """Validate canonical task, language, cohort, split, and length definitions."""
    _require_plain_tree(registry)
    if type(registry) is not dict:
        raise ProtocolValidationError("protocol registry must be a plain object")
    if registry.get("schema_version") != "1.0":
        raise ProtocolValidationError("unsupported protocol registry schema_version")
    if not isinstance(registry.get("registry_id"), str):
        raise ProtocolValidationError("protocol registry_id is required")
    for field in ("splits", "tasks", "languages", "cohorts"):
        _ids(registry.get(field), field)
    bins = registry.get("length_bins")
    _ids(bins, "length_bins")
    expected_minimum = 0
    assert isinstance(bins, list)
    for index, item in enumerate(bins):
        minimum = item.get("minimum_inclusive")
        maximum = item.get("maximum_exclusive")
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum != expected_minimum:
            raise ProtocolValidationError("length bins must be contiguous from zero")
        if maximum is None:
            if index != len(bins) - 1:
                raise ProtocolValidationError("only the final length bin may be unbounded")
        elif not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= minimum:
            raise ProtocolValidationError("length-bin maximum must exceed its minimum")
        else:
            expected_minimum = maximum
    areas = registry.get("coverage_areas")
    if (
        not isinstance(areas, list)
        or not areas
        or any(not is_public_token(value) for value in areas)
    ):
        raise ProtocolValidationError("coverage_areas must be a non-empty string array")
    if len(areas) != len(set(areas)):
        raise ProtocolValidationError("duplicate coverage areas")
    return dict(registry)


def load_protocol_registry(path: Path | None = None) -> dict[str, Any]:
    """Load a registry as inert JSON; no plugin or model code is imported."""
    return validate_protocol_registry(_read_bounded_json(path or PROTOCOL_REGISTRY_PATH))


def registry_sha256(registry: Mapping[str, Any] | None = None) -> str:
    value = registry if registry is not None else load_protocol_registry()
    _require_plain_tree(value)
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def length_bin_for(tokens: int, registry: Mapping[str, Any] | None = None) -> str:
    """Return the canonical bin for an effective detector-token count."""
    if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0:
        raise ProtocolValidationError("effective detector tokens must be a non-negative integer")
    value = registry if registry is not None else load_protocol_registry()
    _require_plain_tree(value)
    if type(value) is not dict:
        raise ProtocolValidationError("protocol registry must be a plain object")
    for item in value["length_bins"]:
        maximum = item.get("maximum_exclusive")
        if tokens >= item["minimum_inclusive"] and (maximum is None or tokens < maximum):
            return str(item["id"])
    raise ProtocolValidationError("protocol registry has no matching length bin")


def _normal_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _require_plain_tree(value: Any, *, _active: set[int] | None = None, _depth: int = 0) -> None:
    if _depth > 128:
        raise ProtocolValidationError("public registry nesting exceeds the limit")
    value_type = type(value)
    if value_type is dict or value_type in (list, tuple):
        active = set() if _active is None else _active
        identity = id(value)
        if identity in active:
            raise ProtocolValidationError("public registries cannot contain cycles")
        active.add(identity)
        try:
            if value_type is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise ProtocolValidationError("public registry keys must be plain strings")
                    _require_plain_tree(item, _active=active, _depth=_depth + 1)
            else:
                for item in value:
                    _require_plain_tree(item, _active=active, _depth=_depth + 1)
        finally:
            active.remove(identity)
        return
    if value is None or value_type in (str, int, float, bool):
        if value_type is float and not math.isfinite(value):
            raise ProtocolValidationError("public registry numbers must be finite")
        return
    raise ProtocolValidationError("public registries must contain only plain JSON values")


def _contains_private_content(value: Any) -> bool:
    if type(value) is dict:
        for key, item in value.items():
            assert type(key) is str
            normalized = _normal_key(key)
            if normalized in _FORBIDDEN_CONTENT_KEYS:
                return True
            if normalized in _SENSITIVE_KEYS or normalized.endswith(
                ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
            ):
                return True
            if _contains_private_content(item):
                return True
    elif type(value) in (list, tuple):
        return any(_contains_private_content(item) for item in value)
    return False


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ProtocolValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _required_metadata(registry: Mapping[str, Any]) -> dict[str, set[str]]:
    return {
        str(value["id"]): {str(field) for field in value.get("required_metadata", [])}
        for value in registry["cohorts"]
    }


def _validate_key_partitions(
    entries: Any, split_ids: set[str]
) -> tuple[dict[str, str], dict[str, Any]]:
    if not isinstance(entries, list):
        raise ProtocolValidationError("key_partitions must be an array")
    partitions: dict[str, str] = {}
    for item in entries:
        if not isinstance(item, Mapping):
            raise ProtocolValidationError("key partition entries must be objects")
        if set(item) != {"key_fingerprint", "split"}:
            raise ProtocolValidationError("key partition fields do not match the v1 contract")
        fingerprint = item.get("key_fingerprint")
        split = item.get("split")
        _require_sha256(fingerprint, "key_fingerprint")
        if split not in split_ids:
            raise ProtocolValidationError("key partition references an unknown split")
        if fingerprint in partitions:
            raise ProtocolValidationError("a key fingerprint may belong to only one split")
        partitions[fingerprint] = str(split)
    final_keys = sorted(key for key, split in partitions.items() if split == "final_test")
    tuning_keys = sorted(key for key, split in partitions.items() if split != "final_test")
    return partitions, {
        "state": "complete" if final_keys and tuning_keys else "not_run",
        "reason": (
            "tuning_and_final_key_partitions_disjoint"
            if final_keys and tuning_keys
            else "tuning_and_final_key_fingerprints_required"
        ),
        "tuning_key_count": len(tuning_keys),
        "final_test_key_count": len(final_keys),
    }


def _status(state: str, reason: str, **details: Any) -> dict[str, Any]:
    if state not in COVERAGE_STATES:
        raise ProtocolValidationError(f"invalid coverage state: {state}")
    return {"state": state, "reason": reason, **details}


def validate_coverage_declaration(
    coverage: Mapping[str, Any], registry: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Require every protocol area to be explicit, including missing work."""
    _require_plain_tree(coverage)
    if type(coverage) is not dict:
        raise ProtocolValidationError("coverage declaration must be a plain object")
    protocol = registry if registry is not None else load_protocol_registry()
    _require_plain_tree(protocol)
    if type(protocol) is not dict:
        raise ProtocolValidationError("protocol registry must be a plain object")
    missing = sorted(set(protocol["coverage_areas"]) - set(coverage))
    extra = sorted(set(coverage) - set(protocol["coverage_areas"]))
    if missing:
        raise ProtocolValidationError(f"coverage declaration omits: {', '.join(missing)}")
    if extra:
        raise ProtocolValidationError(f"unknown coverage areas: {', '.join(extra)}")
    result: dict[str, Any] = {}
    for area in protocol["coverage_areas"]:
        value = coverage[area]
        if not isinstance(value, Mapping) or value.get("state") not in COVERAGE_STATES:
            raise ProtocolValidationError(f"coverage area {area} has no valid state")
        if set(value) - _COVERAGE_FIELDS:
            raise ProtocolValidationError(f"coverage area {area} has unregistered fields")
        reason = value.get("reason")
        allowed_reasons = COVERAGE_REASON_CODES_BY_AREA.get(str(area), frozenset())
        complete_reasons = COVERAGE_COMPLETE_REASON_CODES_BY_AREA.get(str(area), frozenset())
        if not is_code_or_commitment(reason, allowed_reasons) or (
            value.get("state") == "complete" and reason not in complete_reasons
        ):
            raise ProtocolValidationError(
                f"coverage area {area} requires a registered reason code or commitment"
            )
        for field in (
            "tuning_key_count",
            "final_test_key_count",
            "missing_final_test_matrix_cells",
        ):
            item = value.get(field)
            if item is not None and (type(item) is not int or item < 0):
                raise ProtocolValidationError(f"coverage area {area} has an invalid count")
        for field in ("observed", "missing", "observed_languages", "missing_groups"):
            item = value.get(field)
            if item is not None and (
                type(item) is not list or any(not is_public_token(entry) for entry in item)
            ):
                raise ProtocolValidationError(
                    f"coverage area {area} has invalid public identifiers"
                )
        missing_checkers = value.get("missing_checker_kinds")
        if missing_checkers is not None and (
            type(missing_checkers) is not dict
            or any(
                not is_public_token(task)
                or type(checkers) is not list
                or any(not is_public_token(checker) for checker in checkers)
                for task, checkers in missing_checkers.items()
            )
        ):
            raise ProtocolValidationError(f"coverage area {area} has invalid checker identifiers")
        result[area] = dict(value)
    return result


def validate_sample_registry(
    sample_registry: Mapping[str, Any],
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate pre-registered samples and report enforceable protocol coverage.

    Sample records are metadata-only. Raw prompts, generated outputs, and human
    control text are rejected so a registry can be published safely. Human
    inputs are bound by content digest, license, provenance, date, and a frozen
    selection-rule digest.
    """
    _require_plain_tree(sample_registry)
    if type(sample_registry) is not dict:
        raise ProtocolValidationError("sample registry must be a plain object")
    protocol = registry if registry is not None else load_protocol_registry()
    _require_plain_tree(protocol)
    if type(protocol) is not dict:
        raise ProtocolValidationError("protocol registry must be a plain object")
    required_registry_fields = {
        "schema_version",
        "protocol_registry_sha256",
        "frozen_before_final_test",
        "freeze_record_sha256",
        "key_partitions",
        "samples",
    }
    allowed_registry_fields = required_registry_fields | {"registry_classification"}
    if (
        not required_registry_fields <= set(sample_registry)
        or not set(sample_registry) <= allowed_registry_fields
    ):
        raise ProtocolValidationError("sample registry fields do not match the v1 contract")
    classification = sample_registry.get("registry_classification")
    if classification not in {None, "synthetic_harness_fixture_not_performance_evidence"}:
        raise ProtocolValidationError("unknown sample registry classification")
    if sample_registry.get("schema_version") != SAMPLE_REGISTRY_SCHEMA_VERSION:
        raise ProtocolValidationError("unsupported sample registry schema_version")
    if _contains_private_content(sample_registry):
        raise ProtocolValidationError("sample registries cannot contain text or credentials")
    expected_registry_digest = registry_sha256(protocol)
    if sample_registry.get("protocol_registry_sha256") != expected_registry_digest:
        raise ProtocolValidationError("sample registry is bound to a different protocol registry")
    if not isinstance(sample_registry.get("frozen_before_final_test"), bool):
        raise ProtocolValidationError("frozen_before_final_test must be a boolean")
    _require_sha256(sample_registry.get("freeze_record_sha256"), "freeze_record_sha256")
    samples = sample_registry.get("samples")
    if not isinstance(samples, list):
        raise ProtocolValidationError("samples must be an array")
    split_ids = set(_ids(protocol["splits"], "splits"))
    task_ids = set(_ids(protocol["tasks"], "tasks"))
    language_ids = set(_ids(protocol["languages"], "languages"))
    cohort_ids = set(_ids(protocol["cohorts"], "cohorts"))
    required_metadata = _required_metadata(protocol)
    key_partitions, held_out_status = _validate_key_partitions(
        sample_registry.get("key_partitions", []), split_ids
    )
    sample_ids: set[str] = set()
    samples_by_id: dict[str, Mapping[str, Any]] = {}
    cluster_splits: dict[str, set[str]] = defaultdict(set)
    observed_tasks: set[str] = set()
    observed_languages: set[str] = set()
    observed_language_groups: set[str] = set()
    observed_bins: set[str] = set()
    observed_cohorts: set[str] = set()
    observed_splits: set[str] = set()
    task_checkers: dict[str, set[str]] = defaultdict(set)
    count_by_stratum: Counter[tuple[str, str, str, str, str]] = Counter()
    language_group = {
        str(item["id"]): str(item["coverage_group"]) for item in protocol["languages"]
    }
    task_requirements = {
        str(item["id"]): {str(kind) for kind in item.get("required_checker_kinds", [])}
        for item in protocol["tasks"]
    }
    human_count = 0
    for index, item in enumerate(samples):
        if not isinstance(item, Mapping):
            raise ProtocolValidationError(f"sample {index} must be an object")
        expected_sample_fields = {
            "sample_id",
            "cluster_id",
            "split",
            "task",
            "language",
            "cohort",
            "input_sha256",
            "effective_detector_tokens",
            "length_bin",
            "key_fingerprint",
            "task_checkers",
            "metadata",
        }
        if set(item) != expected_sample_fields:
            raise ProtocolValidationError(f"sample {index} fields do not match the v1 contract")
        sample_id = item.get("sample_id")
        cluster_id = item.get("cluster_id")
        split = item.get("split")
        task = item.get("task")
        language = item.get("language")
        cohort = item.get("cohort")
        if not isinstance(sample_id, str) or not _PUBLIC_ID.fullmatch(sample_id):
            raise ProtocolValidationError(f"sample {index} has an invalid sample_id")
        if sample_id in sample_ids:
            raise ProtocolValidationError("duplicate sample_id; value was redacted")
        sample_ids.add(sample_id)
        samples_by_id[sample_id] = item
        if not isinstance(cluster_id, str) or not _PUBLIC_ID.fullmatch(cluster_id):
            raise ProtocolValidationError(f"sample {index} has an invalid cluster_id")
        if split not in split_ids or task not in task_ids or language not in language_ids:
            raise ProtocolValidationError(f"sample {index} references an unknown registry id")
        if cohort not in cohort_ids:
            raise ProtocolValidationError(f"sample {index} has an unknown cohort")
        metadata = item.get("metadata")
        if not isinstance(metadata, Mapping):
            raise ProtocolValidationError(f"sample {index} requires metadata")
        if set(metadata) != required_metadata[str(cohort)]:
            raise ProtocolValidationError(
                f"sample {index} metadata fields do not match its cohort contract"
            )
        missing_metadata = sorted(required_metadata[str(cohort)] - set(metadata))
        if missing_metadata:
            raise ProtocolValidationError(
                f"sample {index} lacks cohort metadata: {', '.join(missing_metadata)}"
            )
        _require_sha256(item.get("input_sha256"), f"sample {index} input_sha256")
        tokens = item.get("effective_detector_tokens")
        canonical_bin = length_bin_for(tokens, protocol)
        if item.get("length_bin") != canonical_bin:
            raise ProtocolValidationError(f"sample {index} has an incorrect length_bin")
        key = item.get("key_fingerprint")
        if key is not None:
            if key not in key_partitions:
                raise ProtocolValidationError(f"sample {index} uses an unregistered key")
            if key_partitions[key] != split:
                raise ProtocolValidationError(
                    f"sample {index} key is assigned to a different split"
                )
        if cohort == "human_control":
            human_count += 1
            if key is not None:
                raise ProtocolValidationError(f"human control {index} cannot carry a key")
            for digest_field in (
                "content_sha256",
                "selection_rule_sha256",
                "matching_rule_sha256",
            ):
                _require_sha256(metadata.get(digest_field), f"sample {index} {digest_field}")
            if metadata.get("generator_exposed") is not False:
                raise ProtocolValidationError(
                    f"human control {index} must never pass through the generator"
                )
            if metadata.get("rewriter_exposed") is not False:
                raise ProtocolValidationError(
                    f"human control {index} source must not pass through the rewriter"
                )
            for field in ("license_id", "domain"):
                if not is_public_token(metadata.get(field)):
                    raise ProtocolValidationError(
                        f"human control {index} requires a public {field} identifier"
                    )
            for field in ("contamination_risk", "memorization_risk"):
                if not is_code_or_commitment(metadata.get(field), HUMAN_CONTROL_RISK_CODES):
                    raise ProtocolValidationError(
                        f"human control {index} requires a registered {field} code or commitment"
                    )
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(metadata["source_date"])):
                raise ProtocolValidationError(
                    f"human control {index} source_date must use YYYY-MM-DD"
                )
        else:
            if not is_public_token(metadata.get("generator_id")):
                raise ProtocolValidationError(f"sample {index} has an invalid generator_id")
            _require_sha256(
                metadata.get("decoding_config_sha256"),
                f"sample {index} decoding_config_sha256",
            )
        checkers = item.get("task_checkers", [])
        if not isinstance(checkers, list) or any(not is_public_token(value) for value in checkers):
            raise ProtocolValidationError(
                f"sample {index} task_checkers must be public identifiers"
            )
        missing_sample_checkers = task_requirements[str(task)] - set(checkers)
        if missing_sample_checkers:
            raise ProtocolValidationError(
                f"sample {index} lacks task checker kinds: "
                f"{', '.join(sorted(missing_sample_checkers))}"
            )
        task_checkers[str(task)].update(checkers)
        cluster_splits[cluster_id].add(str(split))
        observed_tasks.add(str(task))
        observed_languages.add(str(language))
        observed_language_groups.add(language_group[str(language)])
        observed_bins.add(canonical_bin)
        observed_cohorts.add(str(cohort))
        observed_splits.add(str(split))
        count_by_stratum[(str(split), str(task), str(language), canonical_bin, str(cohort))] += 1

    for item in samples_by_id.values():
        if item.get("cohort") != "matched_generator_null":
            continue
        paired_id = item["metadata"].get("paired_sample_id")
        paired = samples_by_id.get(str(paired_id))
        if paired is None or paired.get("cohort") != "watermarked_positive":
            raise ProtocolValidationError(
                "matched null must reference a registered watermarked positive"
            )
        for field in ("split", "cluster_id", "task", "language", "length_bin"):
            if item.get(field) != paired.get(field):
                raise ProtocolValidationError(f"matched null differs from its positive on {field}")
        for field in ("generator_id", "decoding_config_sha256"):
            if item["metadata"].get(field) != paired["metadata"].get(field):
                raise ProtocolValidationError(f"matched null differs from its positive on {field}")

    leaked_clusters = sorted(
        cluster for cluster, values in cluster_splits.items() if len(values) > 1
    )
    if leaked_clusters:
        raise ProtocolValidationError("prompt/document clusters cross split boundaries")
    required_bins = set(_ids(protocol["length_bins"], "length_bins"))
    required_groups = {str(item["coverage_group"]) for item in protocol["languages"]}
    required_matrix = {
        ("final_test", task, language, length_bin, cohort)
        for task in task_ids
        for language in language_ids
        for length_bin in required_bins
        for cohort in cohort_ids
    }
    observed_matrix = set(count_by_stratum)
    missing_matrix = sorted(required_matrix - observed_matrix)
    missing_task_checkers = {
        task: sorted(task_requirements[task] - task_checkers.get(task, set()))
        for task in sorted(task_ids)
        if task_requirements[task] - task_checkers.get(task, set())
    }
    matrix_complete = not missing_matrix
    complete_tasks = observed_tasks == task_ids and not missing_task_checkers and matrix_complete
    controls_complete = {
        "matched_generator_null",
        "human_control",
    } <= observed_cohorts and matrix_complete
    split_complete = split_ids <= observed_splits and not leaked_clusters
    held_out_complete = (
        held_out_status["state"] == "complete"
        and sample_registry.get("frozen_before_final_test") is True
    )
    coverage = {
        "reproducible_identity": _status(
            "complete" if sample_registry.get("frozen_before_final_test") is True else "partial",
            "registry_inputs_and_freeze_content_addressed"
            if sample_registry.get("frozen_before_final_test") is True
            else "final_test_freeze_record_missing",
        ),
        "independent_splits": _status(
            "complete" if split_complete else "partial",
            "splits_populated_and_clusters_disjoint"
            if split_complete
            else "required_splits_incomplete",
            observed=sorted(observed_splits),
        ),
        "matched_controls": _status(
            "complete" if controls_complete else "partial",
            "matched_controls_complete" if controls_complete else "matched_controls_missing",
            observed=sorted(observed_cohorts),
            missing_final_test_matrix_cells=len(missing_matrix),
        ),
        "held_out_keys": _status(
            "complete" if held_out_complete else held_out_status["state"],
            "key_partitions_frozen_before_final_test"
            if held_out_complete
            else str(held_out_status["reason"]),
            tuning_key_count=held_out_status["tuning_key_count"],
            final_test_key_count=held_out_status["final_test_key_count"],
        ),
        "length_coverage": _status(
            "complete" if observed_bins == required_bins and matrix_complete else "partial",
            "detector_token_bins_complete"
            if observed_bins == required_bins
            else "detector_token_bins_missing",
            observed=sorted(observed_bins),
            missing=sorted(required_bins - observed_bins),
            missing_final_test_matrix_cells=len(missing_matrix),
        ),
        "task_coverage": _status(
            "complete" if complete_tasks else "partial",
            "task_checker_matrix_complete"
            if complete_tasks
            else "task_or_checker_matrix_incomplete",
            observed=sorted(observed_tasks),
            missing=sorted(task_ids - observed_tasks),
            missing_checker_kinds=missing_task_checkers,
            missing_final_test_matrix_cells=len(missing_matrix),
        ),
        "language_coverage": _status(
            "complete"
            if observed_language_groups == required_groups and matrix_complete
            else "partial",
            "language_script_groups_complete"
            if observed_language_groups == required_groups
            else "language_script_groups_missing",
            observed_languages=sorted(observed_languages),
            missing_groups=sorted(required_groups - observed_language_groups),
            missing_final_test_matrix_cells=len(missing_matrix),
        ),
        # The sample registry cannot prove execution-time areas. They must be
        # filled by the result assembler instead of being inferred optimistically.
        "detector_statistics": _status("not_run", "detector_results_not_assessed"),
        "negative_effects": _status("not_run", "transformed_control_scores_not_assessed"),
        "quality_preservation": _status("not_run", "quality_gate_outcomes_not_assessed"),
        "human_evaluation": _status("not_run", "blinded_human_review_not_assessed"),
        "resource_accounting": _status("not_run", "execution_telemetry_not_assessed"),
        "artifact_handling": _status("not_run", "evidence_bundle_not_assessed"),
        "independent_replication": _status("not_run", "independent_replication_not_attached"),
    }
    validate_coverage_declaration(coverage, protocol)
    return {
        "schema_version": "1.0",
        "valid": True,
        "protocol_registry_sha256": expected_registry_digest,
        "sample_registry_sha256": hashlib.sha256(
            canonical_json(sample_registry).encode("utf-8")
        ).hexdigest(),
        "sample_count": len(samples),
        "human_control_count": human_count,
        "counts_by_stratum": [
            {
                "split": key[0],
                "task": key[1],
                "language": key[2],
                "length_bin": key[3],
                "cohort": key[4],
                "samples": count,
            }
            for key, count in sorted(count_by_stratum.items())
        ],
        "coverage": coverage,
        "registry_complete": all(
            coverage[area]["state"] == "complete"
            for area in (
                "reproducible_identity",
                "independent_splits",
                "matched_controls",
                "held_out_keys",
                "length_coverage",
                "task_coverage",
                "language_coverage",
            )
        ),
    }


def load_sample_registry(
    path: Path, registry: Mapping[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _read_bounded_json(path)
    return value, validate_sample_registry(value, registry)


def human_control_records(
    controls: Iterable[Mapping[str, Any]],
    *,
    split: str,
    selection_rule_sha256: str,
    matching_rule_sha256: str,
    include_runtime_text: bool = False,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Turn local human inputs into publishable metadata and optional runtime text.

    Each input must provide ``text``, ``id``, ``cluster_id``, ``task``,
    ``language``, ``domain``, ``license_id``, ``source_date``, and
    ``effective_detector_tokens``. Text is returned separately only when the
    caller explicitly requests it; it is never embedded in registry metadata.
    """
    _require_sha256(selection_rule_sha256, "selection_rule_sha256")
    _require_sha256(matching_rule_sha256, "matching_rule_sha256")
    if type(controls) not in (list, tuple):
        raise ProtocolValidationError("human controls must be a plain array")
    records: list[dict[str, Any]] = []
    runtime_texts: list[str] = []
    protocol = load_protocol_registry()
    for value in controls:
        _require_plain_tree(value)
        if type(value) is not dict:
            raise ProtocolValidationError("human controls must contain plain objects")
        text = value.get("text")
        if not isinstance(text, str) or not text:
            raise ProtocolValidationError("each human control requires non-empty local text")
        identifier = value.get("id")
        if not isinstance(identifier, str):
            raise ProtocolValidationError("each human control requires a public string id")
        record = {
            "sample_id": identifier,
            "cluster_id": value.get("cluster_id"),
            "split": split,
            "task": value.get("task"),
            "language": value.get("language"),
            "cohort": "human_control",
            "input_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "effective_detector_tokens": value.get("effective_detector_tokens"),
            "length_bin": length_bin_for(value.get("effective_detector_tokens"), protocol),
            "key_fingerprint": None,
            "task_checkers": list(value.get("task_checkers", [])),
            "metadata": {
                "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "license_id": value.get("license_id"),
                "source_date": value.get("source_date"),
                "domain": value.get("domain"),
                "selection_rule_sha256": selection_rule_sha256,
                "matching_rule_sha256": matching_rule_sha256,
                "contamination_risk": value.get("contamination_risk"),
                "memorization_risk": value.get("memorization_risk"),
                "generator_exposed": False,
                "rewriter_exposed": False,
            },
        }
        records.append(record)
        if include_runtime_text:
            runtime_texts.append(text)
    return records, runtime_texts


def merge_coverage(
    registry_coverage: Mapping[str, Any],
    execution_coverage: Mapping[str, Any],
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge execution evidence without upgrading unrelated registry gaps."""
    _require_plain_tree(execution_coverage)
    if type(execution_coverage) is not dict:
        raise ProtocolValidationError("execution coverage must be a plain object")
    protocol = registry if registry is not None else load_protocol_registry()
    _require_plain_tree(protocol)
    if type(protocol) is not dict:
        raise ProtocolValidationError("protocol registry must be a plain object")
    base = validate_coverage_declaration(registry_coverage, protocol)
    unknown = sorted(set(execution_coverage) - set(protocol["coverage_areas"]))
    if unknown:
        raise ProtocolValidationError(f"unknown execution coverage areas: {', '.join(unknown)}")
    result = dict(base)
    for area, value in execution_coverage.items():
        if not isinstance(value, Mapping):
            raise ProtocolValidationError(f"execution coverage {area} must be an object")
        candidate = dict(value)
        if candidate.get("state") not in COVERAGE_STATES or not candidate.get("reason"):
            raise ProtocolValidationError(f"execution coverage {area} is incomplete")
        result[area] = candidate
    return validate_coverage_declaration(result, protocol)


def required_length_sweep(registry: Mapping[str, Any] | None = None) -> list[int]:
    """Return the smallest requested-token sweep touching every canonical bin.

    Final conformance still uses *detector-reported effective tokens*, not these
    requested values. This helper is only a deterministic planning default.
    """
    protocol = registry if registry is not None else load_protocol_registry()
    values: list[int] = []
    for item in protocol["length_bins"]:
        minimum = int(item["minimum_inclusive"])
        maximum = item.get("maximum_exclusive")
        values.append(max(1, minimum if maximum is None else (minimum + int(maximum) - 1) // 2))
    return values


def covered_length_bins(
    effective_token_counts: Sequence[int], registry: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    protocol = registry if registry is not None else load_protocol_registry()
    required = set(_ids(protocol["length_bins"], "length_bins"))
    observed = {length_bin_for(value, protocol) for value in effective_token_counts}
    return {
        "complete": observed == required,
        "observed": sorted(observed),
        "missing": sorted(required - observed),
    }
