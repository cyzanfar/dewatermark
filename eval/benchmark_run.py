"""Execute a frozen adapter benchmark into strict, content-free evidence.

Raw prompts, generated outputs, and human controls exist only in memory and in
the operator-supplied input file. The checkpoint and all public artifacts hold
only identifiers, hashes, scores, states, and resource measurements.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from dewatermark.command_safety import validate_public_json

try:
    from .adapters import AdapterContractError, CommandScheme
    from .comparisons import comparator_registry_sha256, load_comparator_registry
    from .evidence import (
        EvidenceValidationError,
        _require_public_values,
        create_bundle,
        read_bundle,
        results_identity,
        validate_bundle,
        write_bundle,
    )
    from .manifest import StrictJSONError, canonical_json, strict_json_loads
    from .observations import (
        MAX_BOOTSTRAP_REPLICATES,
        MAX_BOOTSTRAP_SEED,
        ObservationValidationError,
        _validate_human_review,
        aggregate_observation_set,
        finalize_observation_set,
    )
    from .protocol import (
        length_bin_for,
        load_protocol_registry,
        registry_sha256,
        validate_sample_registry,
    )
    from .public_codes import HUMAN_CONTROL_RISK_CODES
    from .resources import resource_snapshot
except ImportError:  # direct-script compatibility
    from comparisons import (  # type: ignore
        comparator_registry_sha256,
        load_comparator_registry,
    )
    from evidence import (  # type: ignore
        EvidenceValidationError,
        _require_public_values,
        create_bundle,
        read_bundle,
        results_identity,
        validate_bundle,
        write_bundle,
    )
    from manifest import (  # type: ignore
        StrictJSONError,
        canonical_json,
        strict_json_loads,
    )
    from observations import (  # type: ignore
        MAX_BOOTSTRAP_REPLICATES,
        MAX_BOOTSTRAP_SEED,
        ObservationValidationError,
        _validate_human_review,
        aggregate_observation_set,
        finalize_observation_set,
    )
    from protocol import (  # type: ignore
        length_bin_for,
        load_protocol_registry,
        registry_sha256,
        validate_sample_registry,
    )
    from public_codes import HUMAN_CONTROL_RISK_CODES  # type: ignore
    from resources import resource_snapshot  # type: ignore

    from adapters import AdapterContractError, CommandScheme  # type: ignore

RUN_CONFIG_SCHEMA_VERSION = "1.0"
INPUT_CORPUS_SCHEMA_VERSION = "1.0"
PROTOCOL_MANIFEST_SCHEMA_VERSION = "1.0"
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 512 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_DETECTOR_FIELDS = {
    "schema_version",
    "id",
    "family",
    "source",
    "implementation",
    "implementation_version",
    "independent_requested",
    "independent",
    "vendor_validated",
    "score_direction",
    "minimum_effective_tokens",
    "minimum_tokens",
    "configuration_sha256",
    "implementation_sha256",
    "model_sha256",
    "tokenizer_sha256",
    "source_sha256",
    "model_revision",
    "tokenizer_revision",
    "golden_conformance",
    "network_required",
    "model_download_required",
    "reproducibility_blockers",
    "sidecar_sha256",
    "command_sha256",
    "command_identity",
    "executable_digests",
    "reproducible",
    "limitations",
}


class BenchmarkRunError(RuntimeError):
    """The executable benchmark contract was not satisfied."""


def _validate_new_sample_key_bindings(
    sample_registry: Mapping[str, Any], key_ids: Mapping[str, str]
) -> None:
    """Apply the stricter runner contract without narrowing published v1."""
    samples = sample_registry.get("samples")
    if type(samples) is not list:
        raise BenchmarkRunError("generated sample registry is invalid")
    by_id = {
        item.get("sample_id"): item
        for item in samples
        if type(item) is dict and type(item.get("sample_id")) is str
    }
    for item in samples:
        if type(item) is not dict or item.get("cohort") == "human_control":
            continue
        split = item.get("split")
        if type(split) is not str or item.get("key_fingerprint") != key_ids.get(split):
            raise BenchmarkRunError("generated sample key binding is incomplete")
        if item.get("cohort") != "matched_generator_null":
            continue
        metadata = item.get("metadata")
        paired_id = metadata.get("paired_sample_id") if type(metadata) is dict else None
        paired = by_id.get(paired_id)
        if type(paired) is not dict or paired.get("key_fingerprint") != item.get("key_fingerprint"):
            raise BenchmarkRunError("generated sample pair key binding is inconsistent")


class _AdapterInvocationFailure(RuntimeError):
    def __init__(self, telemetry: Mapping[str, Any]) -> None:
        super().__init__("adapter invocation failed; details were redacted")
        self.telemetry = dict(telemetry)


def _sha256(value: bytes | str) -> str:
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(encoded).hexdigest()


def _read_json(path: Path, *, limit: int, label: str) -> tuple[dict[str, Any], bytes]:
    descriptor = -1
    try:
        if path.is_symlink():
            raise BenchmarkRunError(f"{label} must be a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise BenchmarkRunError(f"{label} must be a bounded regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise BenchmarkRunError(f"{label} exceeds the size limit")
        value = strict_json_loads(raw)
    except BenchmarkRunError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise BenchmarkRunError(f"{label} is not readable bounded JSON") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if type(value) is not dict:
        raise BenchmarkRunError(f"{label} must contain one JSON object")
    return value, raw


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise BenchmarkRunError(f"{label} is not a public identifier")
    try:
        validate_public_json(value, source=label)
    except (TypeError, ValueError):
        raise BenchmarkRunError(f"{label} is not a safe public identifier") from None
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise BenchmarkRunError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_opaque_key_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise BenchmarkRunError(f"{label} must be 32 random bytes in lowercase hex")
    return value


def _load_protocol_manifest(path: Path, comparator_registry: Mapping[str, Any]) -> dict[str, Any]:
    value, _ = _read_json(path, limit=MAX_CONFIG_BYTES, label="protocol manifest")
    required = {
        "schema_version",
        "protocol_id",
        "classification",
        "watermark_family",
        "protocol_registry_sha256",
        "comparator_registry_sha256",
        "requested_fprs",
        "sample_design",
        "analysis",
        "execution_requirements",
    }
    if set(value) != required or value.get("schema_version") != PROTOCOL_MANIFEST_SCHEMA_VERSION:
        raise BenchmarkRunError("protocol manifest fields do not match v1")
    if value.get("classification") != "real_protocol_preregistration_no_results":
        raise BenchmarkRunError("protocol manifest is not a real-run preregistration")
    _require_id(value.get("protocol_id"), "protocol_id")
    if value.get("watermark_family") not in {"kgw", "synthid_text"}:
        raise BenchmarkRunError("this runner manifest uses an unsupported watermark family")
    if value.get("protocol_registry_sha256") != registry_sha256():
        raise BenchmarkRunError("protocol manifest is bound to another protocol registry")
    if value.get("comparator_registry_sha256") != comparator_registry_sha256(comparator_registry):
        raise BenchmarkRunError("protocol manifest is bound to another comparator registry")
    fprs = value.get("requested_fprs")
    if (
        type(fprs) is not list
        or not fprs
        or len(fprs) != len(set(fprs))
        or any(
            type(item) not in (int, float) or isinstance(item, bool) or not 0 < item < 1
            for item in fprs
        )
    ):
        raise BenchmarkRunError("protocol requested_fprs are invalid")
    protocol = load_protocol_registry()
    design = value.get("sample_design")
    expected_design = {
        "split_ids": [item["id"] for item in protocol["splits"]],
        "cohort_ids": [item["id"] for item in protocol["cohorts"]],
        "task_ids": [item["id"] for item in protocol["tasks"]],
        "language_ids": [item["id"] for item in protocol["languages"]],
        "length_bin_ids": [item["id"] for item in protocol["length_bins"]],
        "split_disjoint_keys_required": True,
        "matched_decoding_required": True,
        "human_controls_required": True,
        "detector_effective_lengths_required": True,
    }
    if design != expected_design:
        raise BenchmarkRunError("protocol sample design differs from the canonical matrix")
    expected_analysis = {
        "primary_endpoint": "detector_scoped_gate_success_rate_over_all_attempts",
        "threshold_source": "disjoint_calibration_matched_generator_nulls",
        "uncertainty_unit": "prompt_or_document_cluster",
        "multiple_comparison_method": comparator_registry["analysis"]["method"],
        "comparison_control_condition_id": comparator_registry["control_condition_id"],
    }
    if value.get("analysis") != expected_analysis:
        raise BenchmarkRunError("protocol analysis differs from the frozen contract")
    expected_requirements = {
        "primary_detector_bound_to_generator_configuration": True,
        "cross_detector_required": True,
        "quality_and_task_checks_required": True,
        "failure_and_abstention_denominator": "all_attempts",
        "content_free_public_artifacts": True,
        "network_requires_explicit_opt_in": True,
        "model_download_requires_explicit_opt_in": True,
        "private_key_slot_echo_required": True,
        "exact_pair_seed_required": True,
        "exact_pair_decoding_commitment_required": True,
        "static_cross_detector_alias_rejection_required": True,
        "cluster_level_paired_inference_required": True,
        "hash_chained_checkpoint_required": True,
        "run_wide_budgets_required": True,
    }
    if value.get("execution_requirements") != expected_requirements:
        raise BenchmarkRunError("protocol execution requirements are incomplete")
    return value


def _adapter(value: Any, *, allow_network: bool, allow_model_download: bool) -> CommandScheme:
    if type(value) is not dict or set(value) != {"name", "family", "source", "sidecar", "argv"}:
        raise BenchmarkRunError("adapter configuration fields do not match v1")
    name = _require_id(value.get("name"), "adapter name")
    family = _require_id(value.get("family"), "adapter family")
    source = _require_id(value.get("source"), "adapter source")
    sidecar = value.get("sidecar")
    argv = value.get("argv")
    if (
        not isinstance(sidecar, str)
        or not sidecar
        or type(argv) is not list
        or not argv
        or len(argv) > 128
        or any(
            type(argument) is not str or not argument or len(argument) > 32_768 or "\0" in argument
            for argument in argv
        )
    ):
        raise BenchmarkRunError("adapter sidecar and bounded argv are required")
    try:
        result = CommandScheme(
            name=name,
            family=family,
            source=source,
            sidecar_path=Path(sidecar),
            command=tuple(argv),
        )
        result.allow_network = allow_network
        result.allow_model_download = allow_model_download
        result.static_manifest()
    except (AdapterContractError, OSError, ValueError):
        raise BenchmarkRunError("adapter configuration is invalid; details were redacted") from None
    return result


def _public_detector_manifest(adapter: CommandScheme) -> dict[str, Any]:
    return {
        key: value
        for key, value in adapter.reproducibility_manifest().items()
        if key in _PUBLIC_DETECTOR_FIELDS
    }


def _validate_detector_independence(adapters: list[CommandScheme]) -> None:
    """Reject detector aliases from static, content-addressed identities only."""
    manifests = [adapter.reproducibility_manifest() for adapter in adapters]
    digest_fields = (
        "sidecar_sha256",
        "command_sha256",
        "implementation_sha256",
        "configuration_sha256",
        "model_sha256",
        "tokenizer_sha256",
        "source_sha256",
    )
    identities: list[dict[str, Any]] = []
    for adapter, manifest in zip(adapters, manifests):
        if manifest.get("id") != adapter.name:
            raise BenchmarkRunError("detector sidecar id must match its registered adapter id")
        for field in digest_fields:
            _require_sha256(manifest.get(field), f"detector {adapter.name} {field}")
        executable = manifest.get("executable_digests")
        if type(executable) is not list or not executable:
            raise BenchmarkRunError("detector executable digests are incomplete")
        script_digests: list[str] = []
        for item in executable:
            if (
                type(item) is not dict
                or set(item) != {"argument_index", "basename", "sha256"}
                or type(item.get("argument_index")) is not int
                or item["argument_index"] < 0
                or not isinstance(item.get("basename"), str)
            ):
                raise BenchmarkRunError("detector executable digest entry is invalid")
            digest = _require_sha256(item.get("sha256"), "detector executable digest")
            if item["argument_index"] > 0:
                script_digests.append(digest)
        if not script_digests:
            script_digests = [str(item["sha256"]) for item in executable]
        identities.append(
            {
                "id": adapter.name,
                "sidecar": manifest["sidecar_sha256"],
                "command": manifest["command_sha256"],
                "scripts": tuple(sorted(script_digests)),
                "implementation_source": (
                    manifest["implementation_sha256"],
                    manifest["source_sha256"],
                ),
                "full": tuple(manifest[field] for field in digest_fields[2:]),
            }
        )
    for field in ("id", "sidecar", "command", "scripts", "implementation_source", "full"):
        values = [identity[field] for identity in identities]
        if len(values) != len(set(values)):
            raise BenchmarkRunError(
                "primary and cross detectors must have distinct static implementation identities"
            )


_PRIVATE_PUBLIC_KEYS = {
    "api_key",
    "authorization",
    "body",
    "candidate_text",
    "content",
    "cookie",
    "key_slot",
    "password",
    "private_key",
    "prompt",
    "response",
    "secret",
    "source_text",
    "text",
}


def _validate_public_tree(value: Any, *, active: set[int] | None = None, depth: int = 0) -> None:
    """Validate public values without coercing, redacting, or invoking hooks."""
    if depth > 128:
        raise BenchmarkRunError("public value nesting exceeds the limit")
    value_type = type(value)
    if value_type is dict or value_type is list:
        seen = set() if active is None else active
        identity = id(value)
        if identity in seen:
            raise BenchmarkRunError("public values cannot contain cycles")
        seen.add(identity)
        try:
            if value_type is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise BenchmarkRunError("public object keys must be plain strings")
                    normalized = key.lower().replace("-", "_")
                    if normalized in _PRIVATE_PUBLIC_KEYS or normalized.endswith(
                        ("_api_key", "_password", "_private_key", "_secret")
                    ):
                        raise BenchmarkRunError("public values contain a private-data field")
                    _validate_public_tree(item, active=seen, depth=depth + 1)
            else:
                for item in value:
                    _validate_public_tree(item, active=seen, depth=depth + 1)
        finally:
            seen.remove(identity)
        if depth == 0:
            try:
                _require_public_values(value)
            except EvidenceValidationError:
                raise BenchmarkRunError("public values contain private-looking text") from None
        return
    if value is None or value_type in (str, int, bool):
        if depth == 0:
            try:
                _require_public_values(value)
            except EvidenceValidationError:
                raise BenchmarkRunError("public values contain private-looking text") from None
        return
    if value_type is float and math.isfinite(value):
        return
    raise BenchmarkRunError("public values must contain finite plain JSON data")


def _public_json_bytes(value: Any, *, indent: int | None = None) -> bytes:
    _validate_public_tree(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
            separators=(",", ":") if indent is None else None,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise BenchmarkRunError("public value cannot be encoded as strict JSON") from None
    return (rendered + "\n").encode("utf-8")


class _CheckpointJournal:
    """Strict hash-chained JSONL journal; only a truncated final record is repairable."""

    _ZERO = "0" * 64

    def __init__(self, path: Path) -> None:
        self.path = path
        self.records: list[dict[str, Any]] = []
        self.sequence = 0
        self.previous_sha256 = self._ZERO
        self._valid_bytes = 0
        self._truncated_tail = False
        self._missing_final_newline = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        if (
            self.path.is_symlink()
            or not self.path.is_file()
            or self.path.stat().st_size > MAX_CHECKPOINT_BYTES
        ):
            raise BenchmarkRunError("checkpoint is not a bounded regular file")
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CHECKPOINT_BYTES:
                raise BenchmarkRunError("checkpoint is not a bounded regular file")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                raw = handle.read(MAX_CHECKPOINT_BYTES + 1)
            if len(raw) > MAX_CHECKPOINT_BYTES:
                raise BenchmarkRunError("checkpoint exceeds the size limit")
        except BenchmarkRunError:
            raise
        except OSError:
            raise BenchmarkRunError("checkpoint is not readable JSONL") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        lines: list[bytes]
        if raw and not raw.endswith(b"\n"):
            cutoff = raw.rfind(b"\n") + 1
            prefix, tail = raw[:cutoff], raw[cutoff:]
            lines = prefix.splitlines(keepends=True)
            try:
                # A valid final JSON value is a complete record even when its
                # optional trailing newline was lost. Ambiguous JSON remains
                # an error; only an actually incomplete syntax tail is repairable.
                strict_json_loads(tail)
            except StrictJSONError as exc:
                if "duplicate key" in str(exc) or "finite" in str(exc):
                    raise BenchmarkRunError(
                        "checkpoint contains an invalid complete record"
                    ) from None
                self._truncated_tail = True
            else:
                lines.append(tail)
                self._missing_final_newline = True
        else:
            lines = raw.splitlines(keepends=True)
        offset = 0
        for line in lines:
            offset += len(line)
            try:
                envelope = strict_json_loads(line)
            except StrictJSONError:
                raise BenchmarkRunError("checkpoint contains an invalid complete record") from None
            if type(envelope) is not dict or set(envelope) != {
                "schema_version",
                "sequence",
                "previous_sha256",
                "payload",
                "record_sha256",
            }:
                raise BenchmarkRunError("checkpoint envelope fields are invalid")
            unsigned = {
                key: envelope[key]
                for key in ("schema_version", "sequence", "previous_sha256", "payload")
            }
            expected = _sha256(_public_json_bytes(unsigned).rstrip(b"\n"))
            if (
                envelope["schema_version"] != "1.0"
                or envelope["sequence"] != self.sequence + 1
                or envelope["previous_sha256"] != self.previous_sha256
                or envelope["record_sha256"] != expected
                or type(envelope["payload"]) is not dict
            ):
                raise BenchmarkRunError("checkpoint hash chain is invalid")
            _validate_public_tree(envelope["payload"])
            self.sequence = int(envelope["sequence"])
            self.previous_sha256 = str(envelope["record_sha256"])
            self.records.append(dict(envelope["payload"]))
            self._valid_bytes = offset

    def append(self, payload: Mapping[str, Any]) -> None:
        if type(payload) is not dict:
            raise BenchmarkRunError("checkpoint payload must be a plain object")
        _validate_public_tree(payload)
        unsigned = {
            "schema_version": "1.0",
            "sequence": self.sequence + 1,
            "previous_sha256": self.previous_sha256,
            "payload": payload,
        }
        envelope = {
            **unsigned,
            "record_sha256": _sha256(_public_json_bytes(unsigned).rstrip(b"\n")),
        }
        encoded = _public_json_bytes(envelope)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_APPEND
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(self.path, flags, 0o600)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise BenchmarkRunError("checkpoint must be a regular file")
                if self._truncated_tail:
                    os.ftruncate(descriptor, self._valid_bytes)
                    os.lseek(descriptor, 0, os.SEEK_END)
                    self._truncated_tail = False
                separator = b"\n" if self._missing_final_newline else b""
                if self._valid_bytes + len(separator) + len(encoded) > MAX_CHECKPOINT_BYTES:
                    raise BenchmarkRunError("checkpoint exceeds the size limit")
                view = memoryview(separator + encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short checkpoint write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BenchmarkRunError:
            raise
        except OSError:
            raise BenchmarkRunError("checkpoint could not be appended safely") from None
        self.sequence += 1
        self.previous_sha256 = str(envelope["record_sha256"])
        self.records.append(dict(payload))
        self._valid_bytes += len(separator) + len(encoded)
        self._missing_final_newline = False


@dataclass
class _ExecutionBudget:
    limits: Mapping[str, int]
    journal: _CheckpointJournal
    deadline_at_unix: float
    cancellation_check: Callable[[], bool] | None
    records_used: int
    run_id: str
    requested_tokens_used: int = 0
    adapter_processes_used: int = 0
    cancellation_checks_used: int = 0
    reserved_cancellation_checks: int = 0

    @classmethod
    def create(
        cls,
        *,
        limits: Mapping[str, int],
        journal: _CheckpointJournal,
        records_used: int,
        cancellation_check: Callable[[], bool] | None,
        resume: bool,
        run_id: str,
    ) -> _ExecutionBudget:
        starts = [item for item in journal.records if item.get("event") == "run.started"]
        if resume:
            if len(starts) != 1:
                raise BenchmarkRunError("checkpoint must contain exactly one run start")
            start = starts[0]
            if (
                start.get("execution_budget") != dict(limits)
                or start.get("records_registered") != records_used
            ):
                raise BenchmarkRunError("checkpoint execution budget is incompatible")
            deadline = start.get("deadline_at_unix")
            if type(deadline) not in (int, float) or not math.isfinite(float(deadline)):
                raise BenchmarkRunError("checkpoint deadline is invalid")
        else:
            deadline = time.time() + int(limits["deadline_seconds"])
        budget = cls(
            limits=limits,
            journal=journal,
            deadline_at_unix=float(deadline),
            cancellation_check=cancellation_check,
            records_used=records_used,
            run_id=run_id,
        )
        for item in journal.records:
            if item.get("event") != "budget.reserved":
                continue
            kind = item.get("kind")
            amount = item.get("amount")
            if (
                kind
                not in {
                    "requested_tokens",
                    "adapter_processes",
                    "cancellation_checks",
                }
                or type(amount) is not int
                or amount < 1
            ):
                raise BenchmarkRunError("checkpoint budget reservation is invalid")
            setattr(budget, f"{kind}_used", getattr(budget, f"{kind}_used") + amount)
        budget._enforce_current()
        return budget

    def _enforce_current(self) -> None:
        if self.records_used > self.limits["max_records"]:
            raise BenchmarkRunError("record budget is exhausted")
        for kind in ("requested_tokens", "adapter_processes", "cancellation_checks"):
            if getattr(self, f"{kind}_used") > self.limits[f"max_{kind}"]:
                raise BenchmarkRunError(f"{kind} budget is exhausted")
        if time.time() > self.deadline_at_unix:
            raise BenchmarkRunError("run deadline is exhausted")

    def _reserve(self, kind: str, amount: int) -> None:
        self._enforce_current()
        current = getattr(self, f"{kind}_used")
        if current + amount > self.limits[f"max_{kind}"]:
            raise BenchmarkRunError(f"{kind} budget is exhausted")
        self.journal.append({"event": "budget.reserved", "kind": kind, "amount": amount})
        setattr(self, f"{kind}_used", current + amount)

    def reserve_cancellation_check(self) -> None:
        """Persist one cancellation probe before it can affect output."""
        self._reserve("cancellation_checks", 1)
        self.reserved_cancellation_checks += 1

    def perform_reserved_cancellation_check(self) -> None:
        """Perform one already-accounted cancellation probe."""
        if self.reserved_cancellation_checks < 1:
            raise BenchmarkRunError("cancellation check was not reserved")
        self.reserved_cancellation_checks -= 1
        try:
            cancelled = self.cancellation_check is not None and self.cancellation_check()
        except Exception:
            self.journal.append(
                {"event": "run.cancelled", "reason_code": "cancellation_check_failed"}
            )
            raise BenchmarkRunError("run cancellation check failed") from None
        if cancelled:
            self.journal.append({"event": "run.cancelled", "reason_code": "operator_cancelled"})
            raise BenchmarkRunError("run was cancelled")
        self._enforce_current()

    def checkpoint(self) -> None:
        """Persist and perform one cancellation/deadline checkpoint."""
        self.reserve_cancellation_check()
        self.perform_reserved_cancellation_check()

    def before_process(self) -> float:
        self.checkpoint()
        self._reserve("adapter_processes", 1)
        remaining = self.deadline_at_unix - time.time()
        if remaining <= 0:
            raise BenchmarkRunError("run deadline is exhausted")
        return remaining

    def reserve_tokens(self, amount: int) -> None:
        self._reserve("requested_tokens", amount)

    def public_summary(self) -> dict[str, Any]:
        return {
            "limits": dict(self.limits),
            "usage": {
                "records": self.records_used,
                "requested_tokens": self.requested_tokens_used,
                "adapter_processes": self.adapter_processes_used,
                "cancellation_checks": self.cancellation_checks_used,
            },
            "deadline_at_unix": self.deadline_at_unix,
        }


def _load_run_config(
    path: Path,
    comparator_registry: Mapping[str, Any],
    *,
    allow_network: bool,
    allow_model_download: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    value, _ = _read_json(path, limit=MAX_CONFIG_BYTES, label="run config")
    required = {
        "schema_version",
        "classification",
        "purpose",
        "seed",
        "generator_adapter",
        "cross_detector_adapters",
        "condition_adapters",
        "quality_adapter",
        "task_adapter",
        "key_ids",
        "key_id_policy",
        "key_slots",
        "execution_budget",
        "model_size_bytes",
        "human_review",
    }
    if set(value) != required or value.get("schema_version") != RUN_CONFIG_SCHEMA_VERSION:
        raise BenchmarkRunError("run config fields do not match v1")
    classification = value.get("classification")
    allowed_classifications = {
        "detector_scoped_real_adapter_benchmark",
        "synthetic_harness_fixture_not_performance_evidence",
    }
    if classification not in allowed_classifications:
        raise BenchmarkRunError("run classification is invalid")
    purpose = value.get("purpose")
    if purpose not in {"exploratory", "frozen_evaluation", "harness_conformance"}:
        raise BenchmarkRunError("run purpose is invalid")
    if classification.startswith("synthetic_") and purpose != "harness_conformance":
        raise BenchmarkRunError("synthetic fixtures can only validate harness conformance")
    if not classification.startswith("synthetic_") and purpose == "harness_conformance":
        raise BenchmarkRunError("real adapter runs cannot be labelled harness conformance")
    seed = value.get("seed")
    if type(seed) is not int or isinstance(seed, bool) or seed < 0:
        raise BenchmarkRunError("run seed must be a non-negative integer")
    generator = _adapter(
        value["generator_adapter"],
        allow_network=allow_network,
        allow_model_download=allow_model_download,
    )
    cross_values = value.get("cross_detector_adapters")
    if type(cross_values) is not list or not cross_values:
        raise BenchmarkRunError("KGW protocol requires at least one cross detector")
    cross = [
        _adapter(item, allow_network=allow_network, allow_model_download=allow_model_download)
        for item in cross_values
    ]
    if len({generator.name, *(item.name for item in cross)}) != len(cross) + 1:
        raise BenchmarkRunError("detector adapter names must be unique")
    condition_values = value.get("condition_adapters")
    if type(condition_values) is not dict:
        raise BenchmarkRunError("condition adapters must be an object")
    expected_conditions = {
        str(item["id"])
        for item in comparator_registry["conditions"]
        if item["adapter_required"] is True
    }
    if set(condition_values) != expected_conditions:
        raise BenchmarkRunError("every frozen executable comparator requires one adapter")
    conditions = {
        condition_id: _adapter(
            condition_values[condition_id],
            allow_network=allow_network,
            allow_model_download=allow_model_download,
        )
        for condition_id in sorted(condition_values)
    }
    quality = _adapter(
        value["quality_adapter"],
        allow_network=allow_network,
        allow_model_download=allow_model_download,
    )
    task = _adapter(
        value["task_adapter"],
        allow_network=allow_network,
        allow_model_download=allow_model_download,
    )
    key_ids = value.get("key_ids")
    if type(key_ids) is not dict or set(key_ids) != {
        "calibration",
        "development",
        "final_test",
    }:
        raise BenchmarkRunError("all split opaque key IDs are required")
    if value.get("key_id_policy") != "csprng_256bit_non_secret":
        raise BenchmarkRunError(
            "key_id_policy must attest that key IDs are random non-secret 256-bit values"
        )
    for split, key_id in key_ids.items():
        _require_opaque_key_id(key_id, f"{split} opaque key ID")
    if len(set(key_ids.values())) != len(key_ids):
        raise BenchmarkRunError("calibration, development, and final key IDs must be disjoint")
    key_slots = value.get("key_slots")
    if type(key_slots) is not dict or set(key_slots) != set(key_ids):
        raise BenchmarkRunError("all split key slots are required")
    for split, key_slot in key_slots.items():
        if (
            type(key_slot) is not str
            or not 16 <= len(key_slot) <= 256
            or any(character in key_slot for character in "\0\r\n")
        ):
            raise BenchmarkRunError(f"{split} key slot must be an opaque bounded identifier")
    if len(set(key_slots.values())) != len(key_slots):
        raise BenchmarkRunError("calibration, development, and final key slots must be disjoint")
    budget = value.get("execution_budget")
    budget_fields = {
        "max_records",
        "max_requested_tokens",
        "max_adapter_processes",
        "deadline_seconds",
        "max_cancellation_checks",
    }
    if type(budget) is not dict or set(budget) != budget_fields:
        raise BenchmarkRunError("execution_budget fields do not match v1")
    for field, maximum in (
        ("max_records", 10_000_000),
        ("max_requested_tokens", 10_000_000_000),
        ("max_adapter_processes", 100_000_000),
        ("deadline_seconds", 604_800),
        ("max_cancellation_checks", 100_000_000),
    ):
        item = budget.get(field)
        if type(item) is not int or item < 1 or item > maximum:
            raise BenchmarkRunError(f"execution budget {field} is invalid")
    model_size = value.get("model_size_bytes")
    if model_size is not None and (type(model_size) is not int or model_size < 0):
        raise BenchmarkRunError("model_size_bytes must be null or non-negative")
    human_review = value.get("human_review")
    try:
        validated_review = _validate_human_review(human_review)
        validated_review = validate_public_json(validated_review, source="human review metadata")
    except (ObservationValidationError, TypeError, ValueError):
        raise BenchmarkRunError("human_review violates the public metadata contract") from None
    if type(validated_review) is not dict:
        raise BenchmarkRunError("human_review violates the public metadata contract")
    value["human_review"] = validated_review
    adapters = {
        "generator": generator,
        "cross": cross,
        "conditions": conditions,
        "quality": quality,
        "task": task,
    }
    return value, adapters


def _load_inputs(path: Path) -> tuple[dict[str, Any], str]:
    value, _ = _read_json(path, limit=MAX_INPUT_BYTES, label="input corpus")
    if (
        set(value) != {"schema_version", "records"}
        or value.get("schema_version") != INPUT_CORPUS_SCHEMA_VERSION
    ):
        raise BenchmarkRunError("input corpus fields do not match v1")
    records = value.get("records")
    if type(records) is not list or not records:
        raise BenchmarkRunError("input corpus requires at least one record")
    protocol = load_protocol_registry()
    tasks = {str(item["id"]): item for item in protocol["tasks"]}
    languages = {str(item["id"]) for item in protocol["languages"]}
    splits = {str(item["id"]) for item in protocol["splits"]}
    seen: set[str] = set()
    clusters: dict[str, str] = {}
    human_fields = {
        "text",
        "license_id",
        "source_date",
        "domain",
        "selection_rule_sha256",
        "matching_rule_sha256",
        "contamination_risk",
        "memorization_risk",
    }
    for record in records:
        if type(record) is not dict or set(record) != {
            "record_id",
            "cluster_id",
            "split",
            "task",
            "language",
            "requested_tokens",
            "prompt",
            "human_control",
        }:
            raise BenchmarkRunError("input record fields do not match v1")
        record_id = _require_id(record.get("record_id"), "record_id")
        cluster_id = _require_id(record.get("cluster_id"), "cluster_id")
        if record_id in seen:
            raise BenchmarkRunError("input record ids must be unique")
        seen.add(record_id)
        split = record.get("split")
        if split not in splits:
            raise BenchmarkRunError("input record split is unknown")
        if cluster_id in clusters and clusters[cluster_id] != split:
            raise BenchmarkRunError("input clusters cannot cross split boundaries")
        clusters[cluster_id] = str(split)
        if record.get("task") not in tasks or record.get("language") not in languages:
            raise BenchmarkRunError("input record task or language is unknown")
        requested = record.get("requested_tokens")
        if type(requested) is not int or isinstance(requested, bool) or requested < 1:
            raise BenchmarkRunError("requested_tokens must be positive")
        if not isinstance(record.get("prompt"), str) or not record["prompt"]:
            raise BenchmarkRunError("input prompt must be a non-empty string")
        if len(f"{record_id}-positive") > 256:
            raise BenchmarkRunError("input record id is too long for derived samples")
        human = record.get("human_control")
        if human is not None:
            if split != "final_test" or type(human) is not dict or set(human) != human_fields:
                raise BenchmarkRunError("human controls require exact final-test metadata")
            if not isinstance(human.get("text"), str) or not human["text"]:
                raise BenchmarkRunError("human control text must be non-empty")
            for field in ("license_id", "domain"):
                _require_id(human.get(field), f"human {field}")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(human.get("source_date"))):
                raise BenchmarkRunError("human source_date must use YYYY-MM-DD")
            for field in ("selection_rule_sha256", "matching_rule_sha256"):
                _require_sha256(human.get(field), f"human {field}")
            for field in ("contamination_risk", "memorization_risk"):
                risk = human.get(field)
                if risk not in HUMAN_CONTROL_RISK_CODES and not (
                    isinstance(risk, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", risk)
                ):
                    raise BenchmarkRunError(f"human {field} is invalid")
    return value, _sha256(canonical_json(value))


def _seed(seed: int, *parts: str) -> int:
    payload = "\0".join((str(seed), *parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big") & 0x7FFFFFFF


def _adapter_telemetry(
    started: Any,
    response: Mapping[str, Any],
    adapter: CommandScheme,
) -> dict[str, Any]:
    ended = resource_snapshot()
    supplied = response.get("telemetry")
    supplied = supplied if isinstance(supplied, Mapping) else {}

    def nonnegative_int(field: str, offline_default: int | None = None) -> int:
        item = supplied.get(field, offline_default)
        if type(item) is not int or isinstance(item, bool) or item < 0:
            raise AdapterContractError(f"adapter {adapter.name} telemetry {field} is invalid")
        return item

    def nonnegative_float(field: str, offline_default: float | None = None) -> float:
        item = supplied.get(field, offline_default)
        if (
            type(item) not in (int, float)
            or isinstance(item, bool)
            or not math.isfinite(item)
            or item < 0
        ):
            raise AdapterContractError(f"adapter {adapter.name} telemetry {field} is invalid")
        return float(item)

    offline = adapter.static_manifest().get("network_required") is False
    remote_default = 0 if offline else None
    cost_default = 0.0 if offline else None
    peak_values = [
        item for item in (started.peak_rss_bytes, ended.peak_rss_bytes) if item is not None
    ]
    return {
        "wall_time_seconds": max(0.0, ended.wall_seconds - started.wall_seconds),
        "peak_rss_bytes": max(peak_values) if peak_values else None,
        "remote_queries": nonnegative_int("remote_queries", remote_default),
        "generated_tokens": nonnegative_int("generated_tokens", 0),
        "estimated_cost_usd": nonnegative_float("estimated_cost_usd", cost_default),
    }


def _failed_telemetry(started: Any, adapter: CommandScheme) -> dict[str, Any]:
    ended = resource_snapshot()
    peaks = [item for item in (started.peak_rss_bytes, ended.peak_rss_bytes) if item is not None]
    offline = adapter.static_manifest().get("network_required") is False
    return {
        "wall_time_seconds": max(0.0, ended.wall_seconds - started.wall_seconds),
        "peak_rss_bytes": max(peaks) if peaks else None,
        "remote_queries": 0 if offline else None,
        "generated_tokens": None,
        "estimated_cost_usd": 0.0 if offline else None,
    }


def _call(
    adapter: CommandScheme,
    payload: dict[str, Any],
    execution: _ExecutionBudget,
) -> tuple[dict[str, Any], dict[str, Any]]:
    def invoke(
        action: str,
        callback: Callable[[Callable[[], None]], dict[str, Any]],
    ) -> dict[str, Any]:
        remaining_seconds = execution.before_process()
        last_process_checkpoint = time.monotonic()

        def process_checkpoint() -> None:
            nonlocal last_process_checkpoint
            now = time.monotonic()
            if now - last_process_checkpoint < 0.1:
                return
            execution.checkpoint()
            last_process_checkpoint = now

        process_index = execution.adapter_processes_used
        execution.journal.append(
            {
                "event": "adapter.process.started",
                "run_id": execution.run_id,
                "adapter_id": adapter.name,
                "action": action,
                "process_index": process_index,
            }
        )
        started = resource_snapshot()
        configured_timeout = adapter.timeout
        try:
            # A per-adapter timeout can only tighten the absolute run deadline.
            adapter.timeout = min(float(configured_timeout), remaining_seconds)
            response = callback(process_checkpoint)
            # Even a process that exits between polling intervals must not
            # commit output after operator cancellation or deadline expiry.
            execution.checkpoint()
            telemetry = _adapter_telemetry(started, response, adapter)
        except (AdapterContractError, RuntimeError, OSError, ValueError):
            telemetry = _failed_telemetry(started, adapter)
            execution.journal.append(
                {
                    "event": "adapter.process.failed",
                    "run_id": execution.run_id,
                    "adapter_id": adapter.name,
                    "action": action,
                    "process_index": process_index,
                    "telemetry": telemetry,
                    "telemetry_complete": all(
                        telemetry[field] is not None
                        for field in (
                            "remote_queries",
                            "generated_tokens",
                            "estimated_cost_usd",
                        )
                    ),
                }
            )
            raise _AdapterInvocationFailure(telemetry) from None
        finally:
            adapter.timeout = configured_timeout
        execution.journal.append(
            {
                "event": "adapter.process.completed",
                "run_id": execution.run_id,
                "adapter_id": adapter.name,
                "action": action,
                "process_index": process_index,
                "telemetry": telemetry,
                "telemetry_complete": True,
            }
        )
        return response

    if adapter._capabilities is None:
        invoke(
            "capabilities",
            lambda checkpoint: adapter.capabilities(checkpoint=checkpoint),
        )
    response = invoke(
        str(payload.get("action", "unknown")),
        lambda checkpoint: adapter._call(payload, checkpoint=checkpoint),
    )
    process_record = execution.journal.records[-1]
    return response, dict(process_record["telemetry"])


def _combine_telemetry(*values: Mapping[str, Any]) -> dict[str, Any]:
    peaks = [
        item.get("peak_rss_bytes") for item in values if item.get("peak_rss_bytes") is not None
    ]
    return {
        "wall_time_seconds": sum(float(item["wall_time_seconds"]) for item in values),
        "peak_rss_bytes": max(peaks) if peaks else None,
        "remote_queries": sum(int(item["remote_queries"]) for item in values)
        if all(item["remote_queries"] is not None for item in values)
        else None,
        "generated_tokens": sum(int(item["generated_tokens"]) for item in values)
        if all(item["generated_tokens"] is not None for item in values)
        else None,
        "estimated_cost_usd": sum(float(item["estimated_cost_usd"]) for item in values)
        if all(item["estimated_cost_usd"] is not None for item in values)
        else None,
    }


def _generate(
    adapter: CommandScheme,
    prompt: str,
    *,
    requested_tokens: int,
    seed: int,
    watermarked: bool,
    key_slot: str,
    decoding_config_sha256: str,
    execution: _ExecutionBudget,
) -> tuple[str, dict[str, Any]]:
    execution.reserve_tokens(requested_tokens)
    response, telemetry = _call(
        adapter,
        {
            "action": "generate",
            "prompt": prompt,
            "max_new_tokens": requested_tokens,
            "seed": seed,
            "watermarked": watermarked,
            "key_slot": key_slot,
            "pair_seed": seed,
            "decoding_config_sha256": decoding_config_sha256,
        },
        execution,
    )
    text = response.get("text")
    if not isinstance(text, str):
        raise AdapterContractError(f"adapter {adapter.name} generation omitted string text")
    adapter._validate_response_metadata(response)
    if (
        response.get("requested_tokens") != requested_tokens
        or response.get("key_slot") != key_slot
        or response.get("pair_seed") != seed
        or response.get("decoding_config_sha256") != decoding_config_sha256
        or response.get("watermarked") is not watermarked
    ):
        raise AdapterContractError(
            f"adapter {adapter.name} generation did not echo its exact pair binding"
        )
    return text, telemetry


def _detect(
    adapter: CommandScheme,
    text: str,
    *,
    key_slot: str,
    execution: _ExecutionBudget,
) -> tuple[float, int, dict[str, Any]]:
    response, telemetry = _call(
        adapter, {"action": "detect", "text": text, "key_slot": key_slot}, execution
    )
    if response.get("key_slot") != key_slot:
        raise AdapterContractError(f"adapter {adapter.name} did not echo its detector key slot")
    try:
        score = float(response["score"])
    except (KeyError, TypeError, ValueError):
        raise AdapterContractError(
            f"adapter {adapter.name} detection omitted numeric score"
        ) from None
    if not math.isfinite(score):
        raise AdapterContractError(f"adapter {adapter.name} returned a non-finite score")
    metadata = adapter._validate_response_metadata(response)
    effective = metadata.get("effective_tokens")
    if type(effective) is not int or effective < 0:
        raise AdapterContractError(f"adapter {adapter.name} omitted effective detector tokens")
    return score, effective, telemetry


def _transform(
    adapter: CommandScheme,
    source: str,
    *,
    condition_id: str,
    task: str,
    language: str,
    seed: int,
    execution: _ExecutionBudget,
) -> tuple[str, str, str | None, dict[str, Any]]:
    try:
        response, telemetry = _call(
            adapter,
            {
                "action": "transform",
                "condition_id": condition_id,
                "source_text": source,
                "task": task,
                "language": language,
                "seed": seed,
            },
            execution,
        )
    except _AdapterInvocationFailure as exc:
        return (
            source,
            "failed",
            "transform_adapter_failed",
            exc.telemetry,
        )
    state = response.get("state")
    if state not in {"accepted", "failed", "abstained"}:
        return source, "failed", "transform_contract_failed", telemetry
    if state == "accepted":
        candidate = response.get("candidate_text")
        if not isinstance(candidate, str):
            return source, "failed", "transform_contract_failed", telemetry
        return candidate, state, None, telemetry
    # Adapter-supplied labels are untrusted and can echo source text. Publish
    # only host-defined outcome codes; raw adapter strings never enter evidence.
    error = "transform_failed" if state == "failed" else None
    return source, state, error, telemetry


def _check(
    adapter: CommandScheme,
    *,
    action: str,
    source: str,
    candidate: str,
    task: str,
    language: str,
    checker_kinds: list[str],
    execution: _ExecutionBudget,
) -> tuple[bool | None, str | None, dict[str, Any]]:
    try:
        response, telemetry = _call(
            adapter,
            {
                "action": action,
                "source_text": source,
                "candidate_text": candidate,
                "task": task,
                "language": language,
                "checker_kinds": checker_kinds,
            },
            execution,
        )
    except _AdapterInvocationFailure as exc:
        return (
            None,
            f"{action}_adapter_failed",
            exc.telemetry,
        )
    if (
        response.get("state", "completed") != "completed"
        or type(response.get("passed")) is not bool
    ):
        return None, f"{action}_contract_failed", telemetry
    return bool(response["passed"]), None, telemetry


def _write_json(path: Path, value: Any, *, resume: bool = False) -> None:
    # Validation must precede even a temporary-file creation.
    encoded = _public_json_bytes(value, indent=2)
    if path.exists():
        if resume and path.is_file() and not path.is_symlink() and path.read_bytes() == encoded:
            return
        raise BenchmarkRunError("output artifact already exists or differs")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise BenchmarkRunError("output artifact appeared during atomic write") from None
    except OSError:
        raise BenchmarkRunError("output artifact could not be written atomically") from None
    finally:
        if created:
            try:
                temporary.unlink()
            except OSError:
                pass


def _memory_artifact_descriptor(path: Path, value: Any) -> dict[str, Any]:
    """Describe the exact JSON bytes `_write_json` will publish without touching disk."""
    encoded = _public_json_bytes(value, indent=2)
    return {
        "path": path.name,
        "sha256": _sha256(encoded),
        "canonical_sha256": _sha256(canonical_json(value)),
        "bytes": len(encoded),
        "media_type": "application/json",
        "privacy_class": "public_aggregate_no_text",
    }


def _checkpoint_records(path: Path) -> list[dict[str, Any]]:
    return _CheckpointJournal(path).records


def _append_checkpoint(path: Path, value: Mapping[str, Any]) -> None:
    _CheckpointJournal(path).append(value)


def run_benchmark(
    *,
    protocol_manifest_path: Path,
    comparator_registry_path: Path,
    run_config_path: Path,
    input_corpus_path: Path,
    output_directory: Path,
    checkpoint_path: Path | None = None,
    resume: bool = False,
    allow_network: bool = False,
    allow_model_download: bool = False,
    bootstrap_replicates: int = 500,
    bootstrap_seed: int = 0,
    cancellation_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run the full registered matrix and return only public artifact identities."""
    invocation_started_at = time.time()
    if allow_model_download and not allow_network:
        raise BenchmarkRunError("model download permission requires network permission")
    if (
        type(bootstrap_replicates) is not int
        or not 2 <= bootstrap_replicates <= MAX_BOOTSTRAP_REPLICATES
        or type(bootstrap_seed) is not int
        or not 0 <= bootstrap_seed <= MAX_BOOTSTRAP_SEED
    ):
        raise BenchmarkRunError("bootstrap settings are invalid")
    comparator_registry = load_comparator_registry(comparator_registry_path)
    protocol_manifest = _load_protocol_manifest(protocol_manifest_path, comparator_registry)
    config, adapters = _load_run_config(
        run_config_path,
        comparator_registry,
        allow_network=allow_network,
        allow_model_download=allow_model_download,
    )
    if not config["classification"].startswith("synthetic_"):
        expected_family = protocol_manifest["watermark_family"]
        detector_adapters = [adapters["generator"], *adapters["cross"]]
        if any(adapter.family != expected_family for adapter in detector_adapters):
            raise BenchmarkRunError(
                "real detector adapters do not match the preregistered watermark family"
            )
    public_group_ids = [
        adapters["generator"].name,
        *(adapter.name for adapter in adapters["cross"]),
        *adapters["conditions"],
    ]
    if any("::" in identifier for identifier in public_group_ids):
        raise BenchmarkRunError(
            "aggregation contract 1.1 reserves the double-colon identifier delimiter"
        )
    corpus, corpus_sha256 = _load_inputs(input_corpus_path)
    if len(corpus["records"]) > config["execution_budget"]["max_records"]:
        raise BenchmarkRunError("input corpus exceeds the run-wide record budget")
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise BenchmarkRunError("output directory could not be created") from None
    checkpoint = checkpoint_path or output_directory / "progress.jsonl"
    detector_adapters = [adapters["generator"], *adapters["cross"]]
    # This preflight is static and must run before capability discovery or any adapter process.
    _validate_detector_independence(detector_adapters)
    detector_entries = [
        {
            "id": adapter.name,
            "role": "primary" if index == 0 else "cross",
            "manifest": _public_detector_manifest(adapter),
        }
        for index, adapter in enumerate(detector_adapters)
    ]
    transform_manifests = {
        condition_id: adapter.reproducibility_manifest()
        for condition_id, adapter in adapters["conditions"].items()
    }
    operation_registry = {
        "conditions": transform_manifests,
        "quality": adapters["quality"].reproducibility_manifest(),
        "task": adapters["task"].reproducibility_manifest(),
    }
    detector_reproducibility_manifests = {
        adapter.name: adapter.reproducibility_manifest() for adapter in detector_adapters
    }
    reproducibility_manifests = [
        *detector_reproducibility_manifests.values(),
        *transform_manifests.values(),
        operation_registry["quality"],
        operation_registry["task"],
    ]
    if any(item.get("reproducible") is not True for item in reproducibility_manifests):
        raise BenchmarkRunError(
            "every executable adapter needs a complete reproducible sidecar and executable digest"
        )
    scientific_identity = {
        "protocol_manifest_sha256": _sha256(canonical_json(protocol_manifest)),
        "comparator_registry_sha256": comparator_registry_sha256(comparator_registry),
        "input_corpus_sha256": corpus_sha256,
        "classification": config["classification"],
        "purpose": config["purpose"],
        "seed": config["seed"],
        "requested_fprs": protocol_manifest["requested_fprs"],
        "detectors": detector_reproducibility_manifests,
        "operations_sha256": _sha256(canonical_json(operation_registry)),
        "key_partition_ids": config["key_ids"],
        "key_id_policy": config["key_id_policy"],
        "execution_budget": config["execution_budget"],
        "model_size_bytes": config["model_size_bytes"],
        "human_review": config["human_review"],
        "bootstrap_replicates": bootstrap_replicates,
        "bootstrap_seed": bootstrap_seed,
        "network_allowed": allow_network,
        "model_download_allowed": allow_model_download,
    }
    run_id = _sha256(canonical_json(scientific_identity))
    journal = _CheckpointJournal(checkpoint)
    records = journal.records
    if resume:
        identities = {item.get("run_id") for item in records if item.get("event") == "run.started"}
        if identities != {run_id}:
            raise BenchmarkRunError("checkpoint is incompatible with this run")
    elif records or any(
        (output_directory / name).exists()
        for name in (
            "sample-registry.json",
            "observations.json",
            "comparator-registry.json",
            "evidence.json",
        )
    ):
        raise BenchmarkRunError("run output already exists; use --resume for the same run")
    else:
        journal.append(
            {
                "event": "run.started",
                "run_id": run_id,
                "execution_budget": config["execution_budget"],
                "records_registered": len(corpus["records"]),
                "deadline_at_unix": invocation_started_at
                + int(config["execution_budget"]["deadline_seconds"]),
            }
        )
        records = journal.records
    execution = _ExecutionBudget.create(
        limits=config["execution_budget"],
        journal=journal,
        records_used=len(corpus["records"]),
        cancellation_check=cancellation_check,
        resume=True,
        run_id=run_id,
    )

    completed_events = [
        item
        for item in records
        if item.get("event") == "run.completed" and item.get("run_id") == run_id
    ]
    if completed_events:
        if len(completed_events) != 1:
            raise BenchmarkRunError("checkpoint has multiple run completion records")
        sample_path = output_directory / "sample-registry.json"
        observation_path = output_directory / "observations.json"
        comparator_path = output_directory / "comparator-registry.json"
        evidence_path = output_directory / "evidence.json"
        bundle = read_bundle(evidence_path)
        completion = completed_events[0]
        bundle_manifest = bundle.get("manifest")
        if (
            type(completion.get("bundle_id")) is not str
            or bundle.get("bundle_id") != completion["bundle_id"]
            or type(bundle_manifest) is not dict
            or bundle_manifest.get("run_id") != run_id
        ):
            raise BenchmarkRunError("completed artifacts do not match the checkpoint")
        observations, _ = _read_json(
            observation_path,
            limit=MAX_CHECKPOINT_BYTES,
            label="existing observation set",
        )
        sample_registry, _ = _read_json(
            sample_path,
            limit=MAX_CHECKPOINT_BYTES,
            label="existing sample registry",
        )
        sample_report = validate_sample_registry(sample_registry)
        observation_manifest = (
            observations.get("run_manifest") if type(observations) is dict else None
        )
        results = bundle.get("results")
        if (
            type(observation_manifest) is not dict
            or observation_manifest.get("run_id") != run_id
            or type(results) is not dict
            or results.get("observation_set_id") != observations.get("observation_set_id")
            or results.get("sample_registry_sha256") != sample_report["sample_registry_sha256"]
        ):
            raise BenchmarkRunError("completed artifacts do not match the checkpoint")
        execution._enforce_current()
        return {
            "classification": config["classification"],
            "run_id": run_id,
            "bundle_id": bundle["bundle_id"],
            "sample_registry_sha256": sample_report["sample_registry_sha256"],
            "observation_set_id": observations["observation_set_id"],
            "aggregate_sha256": bundle["results"]["aggregate_sha256"],
            "sample_count": sample_report["sample_count"],
            "observation_count": len(observations["observations"]),
            "registry_complete": sample_report["registry_complete"],
            "comparative_hypotheses_tested": bundle["results"]["comparative_analysis"][
                "tested_hypotheses"
            ],
            "files": {
                "sample_registry": sample_path.name,
                "observations": observation_path.name,
                "comparator_registry": comparator_path.name,
                "evidence": evidence_path.name,
                "checkpoint": checkpoint.name,
            },
        }

    completed = {
        (
            str(item["observation"]["sample_id"]),
            str(item["observation"]["detector_id"]),
            str(item["observation"]["condition_id"]),
        ): item["observation"]
        for item in records
        if item.get("event") == "observation.completed"
        and item.get("run_id") == run_id
        and isinstance(item.get("observation"), dict)
    }
    failed_observation_attempts: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in records:
        if item.get("event") != "observation.failed" or item.get("run_id") != run_id:
            continue
        key = (
            str(item.get("sample_id")),
            str(item.get("detector_id")),
            str(item.get("condition_id")),
        )
        telemetry = item.get("telemetry")
        if type(telemetry) is not dict:
            raise BenchmarkRunError("checkpoint observation failure telemetry is incomplete")
        failed_observation_attempts.setdefault(key, []).append(
            {
                "attempt_index": int(item["attempt_index"]),
                "state": "failed",
                "error_class": str(item["error_class"]),
                "telemetry": telemetry,
                "telemetry_complete": bool(item["telemetry_complete"]),
            }
        )
    protocol = load_protocol_registry()
    task_checkers = {
        str(item["id"]): list(item["required_checker_kinds"]) for item in protocol["tasks"]
    }
    source_texts: dict[str, str] = {}
    source_detection: dict[tuple[str, str], tuple[float, int, dict[str, Any]]] = {}
    generation_telemetry: dict[str, dict[str, Any]] = {}
    samples: list[dict[str, Any]] = []

    def add_generated(
        record: Mapping[str, Any],
        *,
        marked: bool,
        pair_seed: int,
        decoding_config_sha256: str,
    ) -> None:
        suffix = "positive" if marked else "null"
        sample_id = f"{record['record_id']}-{suffix}"
        key_slot = str(config["key_slots"][record["split"]])
        text, generation = _generate(
            adapters["generator"],
            str(record["prompt"]),
            requested_tokens=int(record["requested_tokens"]),
            seed=pair_seed,
            watermarked=marked,
            key_slot=key_slot,
            decoding_config_sha256=decoding_config_sha256,
            execution=execution,
        )
        score, tokens, detection = _detect(
            adapters["generator"], text, key_slot=key_slot, execution=execution
        )
        source_texts[sample_id] = text
        generation_telemetry[sample_id] = generation
        source_detection[(adapters["generator"].name, sample_id)] = (score, tokens, detection)
        metadata = {
            "generator_id": adapters["generator"].name,
            "decoding_config_sha256": decoding_config_sha256,
        }
        if not marked:
            metadata["paired_sample_id"] = f"{record['record_id']}-positive"
        samples.append(
            {
                "sample_id": sample_id,
                "cluster_id": record["cluster_id"],
                "split": record["split"],
                "task": record["task"],
                "language": record["language"],
                "cohort": "watermarked_positive" if marked else "matched_generator_null",
                "input_sha256": _sha256(text),
                "effective_detector_tokens": tokens,
                "length_bin": length_bin_for(tokens),
                # The public v1 schema retains the legacy field name. Its value is
                # an independent opaque ID, never a digest of key material.
                "key_fingerprint": config["key_ids"][record["split"]],
                "task_checkers": task_checkers[str(record["task"])],
                "metadata": metadata,
            }
        )

    for record in corpus["records"]:
        pair_seed = _seed(config["seed"], str(record["record_id"]), "matched-pair")
        generator_manifest = adapters["generator"].reproducibility_manifest()
        decoding_config_sha256 = _sha256(
            canonical_json(
                {
                    "protocol": "exact-matched-pair-decoding-v1",
                    "pair_seed": pair_seed,
                    "requested_tokens": record["requested_tokens"],
                    "key_partition_id": config["key_ids"][record["split"]],
                    "configuration_sha256": generator_manifest["configuration_sha256"],
                    "implementation_sha256": generator_manifest["implementation_sha256"],
                    "model_sha256": generator_manifest["model_sha256"],
                    "tokenizer_sha256": generator_manifest["tokenizer_sha256"],
                    "source_sha256": generator_manifest["source_sha256"],
                }
            )
        )
        try:
            add_generated(
                record,
                marked=True,
                pair_seed=pair_seed,
                decoding_config_sha256=decoding_config_sha256,
            )
            add_generated(
                record,
                marked=False,
                pair_seed=pair_seed,
                decoding_config_sha256=decoding_config_sha256,
            )
        except (AdapterContractError, RuntimeError):
            attempt_index = 1 + sum(
                item.get("event") == "sample.failed"
                and item.get("run_id") == run_id
                and item.get("record_id") == record["record_id"]
                for item in journal.records
            )
            journal.append(
                {
                    "event": "sample.failed",
                    "run_id": run_id,
                    "record_id": record["record_id"],
                    "attempt_index": attempt_index,
                    "error_class": "generation_or_primary_detection_failed",
                },
            )
            raise BenchmarkRunError(
                "sample generation or primary detection failed; checkpoint retained"
            ) from None
        human = record["human_control"]
        if human is not None:
            sample_id = f"{record['record_id']}-human"
            text = str(human["text"])
            try:
                score, tokens, detection = _detect(
                    adapters["generator"],
                    text,
                    key_slot=str(config["key_slots"][record["split"]]),
                    execution=execution,
                )
            except (AdapterContractError, RuntimeError):
                attempt_index = 1 + sum(
                    item.get("event") == "sample.failed"
                    and item.get("run_id") == run_id
                    and item.get("record_id") == record["record_id"]
                    for item in journal.records
                )
                journal.append(
                    {
                        "event": "sample.failed",
                        "run_id": run_id,
                        "record_id": record["record_id"],
                        "attempt_index": attempt_index,
                        "error_class": "human_control_primary_detection_failed",
                    },
                )
                raise BenchmarkRunError(
                    "human-control detection failed; checkpoint retained"
                ) from None
            source_texts[sample_id] = text
            generation_telemetry[sample_id] = {
                "wall_time_seconds": 0.0,
                "peak_rss_bytes": None,
                "remote_queries": 0,
                "generated_tokens": 0,
                "estimated_cost_usd": 0.0,
            }
            source_detection[(adapters["generator"].name, sample_id)] = (
                score,
                tokens,
                detection,
            )
            samples.append(
                {
                    "sample_id": sample_id,
                    "cluster_id": record["cluster_id"],
                    "split": record["split"],
                    "task": record["task"],
                    "language": record["language"],
                    "cohort": "human_control",
                    "input_sha256": _sha256(text),
                    "effective_detector_tokens": tokens,
                    "length_bin": length_bin_for(tokens),
                    "key_fingerprint": None,
                    "task_checkers": task_checkers[str(record["task"])],
                    "metadata": {
                        "content_sha256": _sha256(text),
                        "license_id": human["license_id"],
                        "source_date": human["source_date"],
                        "domain": human["domain"],
                        "selection_rule_sha256": human["selection_rule_sha256"],
                        "matching_rule_sha256": human["matching_rule_sha256"],
                        "contamination_risk": human["contamination_risk"],
                        "memorization_risk": human["memorization_risk"],
                        "generator_exposed": False,
                        "rewriter_exposed": False,
                    },
                }
            )
    sample_registry: dict[str, Any] = {
        "schema_version": "1.0",
        "protocol_registry_sha256": registry_sha256(protocol),
        "frozen_before_final_test": config["purpose"] == "frozen_evaluation",
        "freeze_record_sha256": _sha256(canonical_json(scientific_identity)),
        "key_partitions": [
            {"key_fingerprint": fingerprint, "split": split}
            for split, fingerprint in sorted(config["key_ids"].items())
        ],
        "samples": sorted(samples, key=lambda item: item["sample_id"]),
    }
    if config["classification"].startswith("synthetic_"):
        sample_registry["registry_classification"] = config["classification"]
    _validate_new_sample_key_bindings(sample_registry, config["key_ids"])
    sample_report = validate_sample_registry(sample_registry)
    previous_registry = [
        item.get("sample_registry_sha256")
        for item in records
        if item.get("event") == "registry.completed" and item.get("run_id") == run_id
    ]
    if previous_registry and set(previous_registry) != {sample_report["sample_registry_sha256"]}:
        raise BenchmarkRunError("regenerated samples differ from the resumable checkpoint")
    sample_path = output_directory / "sample-registry.json"
    if not previous_registry:
        journal.append(
            {
                "event": "registry.completed",
                "run_id": run_id,
                "sample_registry_sha256": sample_report["sample_registry_sha256"],
            },
        )

    measured_samples = [
        item
        for item in sample_registry["samples"]
        if item["split"] == "final_test"
        or (item["split"] == "calibration" and item["cohort"] == "matched_generator_null")
    ]
    condition_rows = {str(item["id"]): item for item in comparator_registry["conditions"]}
    condition_descriptors = []
    quality_manifest_sha256 = _sha256(
        canonical_json(
            {
                "quality": operation_registry["quality"],
                "task": operation_registry["task"],
                "required_task_checkers": task_checkers,
            }
        )
    )
    for condition_id in condition_rows:
        if condition_id == comparator_registry["control_condition_id"]:
            transform_sha256 = _sha256(canonical_json(condition_rows[condition_id]))
        else:
            transform_sha256 = _sha256(
                canonical_json(
                    {
                        "registration": condition_rows[condition_id],
                        "runtime_manifest": transform_manifests[condition_id],
                    }
                )
            )
        condition_descriptors.append(
            {
                "id": condition_id,
                "transform_manifest_sha256": transform_sha256,
                "quality_gate_manifest_sha256": quality_manifest_sha256,
            }
        )

    for condition_id in condition_rows:
        for sample in measured_samples:
            sample_id = str(sample["sample_id"])
            required_keys = {
                (sample_id, detector.name, condition_id) for detector in detector_adapters
            }
            if required_keys <= set(completed):
                continue
            source = source_texts[sample_id]
            if condition_id == comparator_registry["control_condition_id"]:
                candidate = source
                transform_state = "accepted"
                error_class = None
                transform_telemetry = {
                    "wall_time_seconds": 0.0,
                    "peak_rss_bytes": None,
                    "remote_queries": 0,
                    "generated_tokens": 0,
                    "estimated_cost_usd": 0.0,
                }
            else:
                candidate, transform_state, error_class, transform_telemetry = _transform(
                    adapters["conditions"][condition_id],
                    source,
                    condition_id=condition_id,
                    task=str(sample["task"]),
                    language=str(sample["language"]),
                    seed=_seed(config["seed"], sample_id, condition_id),
                    execution=execution,
                )
            quality_passed: bool | None = None
            task_passed: bool | None = None
            gate_telemetry: list[Mapping[str, Any]] = []
            if transform_state == "accepted":
                quality_passed, gate_error, telemetry = _check(
                    adapters["quality"],
                    action="quality_check",
                    source=source,
                    candidate=candidate,
                    task=str(sample["task"]),
                    language=str(sample["language"]),
                    checker_kinds=list(sample["task_checkers"]),
                    execution=execution,
                )
                gate_telemetry.append(telemetry)
                if gate_error is not None:
                    transform_state, error_class = "failed", gate_error
                else:
                    task_passed, gate_error, telemetry = _check(
                        adapters["task"],
                        action="task_check",
                        source=source,
                        candidate=candidate,
                        task=str(sample["task"]),
                        language=str(sample["language"]),
                        checker_kinds=list(sample["task_checkers"]),
                        execution=execution,
                    )
                    gate_telemetry.append(telemetry)
                    if gate_error is not None:
                        transform_state, error_class = "failed", gate_error
            if transform_state != "accepted":
                quality_passed = None
                task_passed = None
            shared_telemetry = _combine_telemetry(transform_telemetry, *gate_telemetry)
            for detector_index, detector in enumerate(detector_adapters):
                key = (sample_id, detector.name, condition_id)
                if key in completed:
                    continue
                try:
                    key_slot = str(config["key_slots"][sample["split"]])
                    source_key = (detector.name, sample_id)
                    if source_key not in source_detection:
                        source_detection[source_key] = _detect(
                            detector,
                            source,
                            key_slot=key_slot,
                            execution=execution,
                        )
                    source_score, source_tokens, source_telemetry = source_detection[source_key]
                    candidate_score, candidate_tokens, candidate_telemetry = _detect(
                        detector,
                        candidate,
                        key_slot=key_slot,
                        execution=execution,
                    )
                except (AdapterContractError, RuntimeError) as exc:
                    if isinstance(exc, _AdapterInvocationFailure):
                        failure_telemetry = exc.telemetry
                    else:
                        latest = journal.records[-1] if journal.records else {}
                        failure_telemetry = latest.get("telemetry")
                        if type(failure_telemetry) is not dict:
                            failure_telemetry = {
                                "wall_time_seconds": 0.0,
                                "peak_rss_bytes": None,
                                "remote_queries": None,
                                "generated_tokens": None,
                                "estimated_cost_usd": None,
                            }
                    attempt_index = len(failed_observation_attempts.get(key, [])) + 1
                    journal.append(
                        {
                            "event": "observation.failed",
                            "run_id": run_id,
                            "sample_id": sample_id,
                            "detector_id": detector.name,
                            "condition_id": condition_id,
                            "attempt_index": attempt_index,
                            "error_class": "detector_adapter_failed",
                            "telemetry": failure_telemetry,
                            "telemetry_complete": all(
                                failure_telemetry[field] is not None
                                for field in (
                                    "remote_queries",
                                    "generated_tokens",
                                    "estimated_cost_usd",
                                )
                            ),
                        },
                    )
                    raise BenchmarkRunError(
                        "detector observation failed; checkpoint retained for resume"
                    ) from None
                attributed = [candidate_telemetry]
                if condition_id == comparator_registry["control_condition_id"]:
                    attributed.append(source_telemetry)
                    if detector_index == 0:
                        attributed.append(generation_telemetry[sample_id])
                if detector_index == 0:
                    attributed.append(shared_telemetry)
                observation_telemetry = _combine_telemetry(*attributed)
                prior_attempts = failed_observation_attempts.get(key, [])
                observation = {
                    "sample_id": sample_id,
                    "detector_id": detector.name,
                    "condition_id": condition_id,
                    "source_score": source_score,
                    "candidate_score": candidate_score,
                    "source_effective_tokens": source_tokens,
                    "candidate_effective_tokens": candidate_tokens,
                    "transformation_state": transform_state,
                    "quality_gate_passed": quality_passed,
                    "task_check_passed": task_passed,
                    "error_class": error_class,
                    "telemetry": observation_telemetry,
                    "attempt_history": [
                        *prior_attempts,
                        {
                            "attempt_index": len(prior_attempts) + 1,
                            "state": transform_state,
                            "error_class": error_class,
                            "telemetry": observation_telemetry,
                            "telemetry_complete": all(
                                observation_telemetry[field] is not None
                                for field in (
                                    "remote_queries",
                                    "generated_tokens",
                                    "estimated_cost_usd",
                                )
                            ),
                        },
                    ],
                }
                completed[key] = observation
                journal.append(
                    {
                        "event": "observation.completed",
                        "run_id": run_id,
                        "observation": observation,
                    },
                )

    # Reserve aggregation/finalization probes before the resource summary is
    # frozen. Every callback that can veto output is represented in the public
    # ledger, while aggregation enforces a hard total-work limit.
    aggregation_probe_count = (
        2
        + len(detector_entries)
        * len(condition_descriptors)
        * (2 * len(protocol_manifest["requested_fprs"]) + 2)
        + 1
    )
    for _ in range(aggregation_probe_count + 2):
        execution.reserve_cancellation_check()
    run_manifest = {
        "schema_version": "1.0",
        "aggregation_contract_version": "1.2",
        "bootstrap_replicates_count": bootstrap_replicates,
        "bootstrap_seed_count": bootstrap_seed,
        "classification": config["classification"],
        "protocol_id": protocol_manifest["protocol_id"],
        "watermark_family": protocol_manifest["watermark_family"],
        "run_id": run_id,
        "protocol_manifest_sha256": scientific_identity["protocol_manifest_sha256"],
        "comparator_registry_sha256": scientific_identity["comparator_registry_sha256"],
        "input_corpus_sha256": corpus_sha256,
        "adapter_registry_sha256": _sha256(
            canonical_json(
                {
                    "detectors": detector_reproducibility_manifests,
                    "operations": operation_registry,
                }
            )
        ),
        "network_allowed": allow_network,
        "model_download_allowed": allow_model_download,
        "sample_count": sample_report["sample_count"],
        "condition_count": len(condition_descriptors),
        "detector_count": len(detector_entries),
        "execution_budget_sha256": _sha256(canonical_json(config["execution_budget"])),
    }
    process_events = [
        item
        for item in journal.records
        if item.get("run_id") == run_id
        and item.get("event")
        in {
            "adapter.process.started",
            "adapter.process.completed",
            "adapter.process.failed",
        }
    ]
    process_ledger = {
        "started": sum(item["event"] == "adapter.process.started" for item in process_events),
        "completed": sum(item["event"] == "adapter.process.completed" for item in process_events),
        "failed": sum(item["event"] == "adapter.process.failed" for item in process_events),
        "telemetry_incomplete": sum(
            item["event"] in {"adapter.process.completed", "adapter.process.failed"}
            and item.get("telemetry_complete") is not True
            for item in process_events
        ),
    }
    process_ledger["telemetry_incomplete"] += max(
        0,
        process_ledger["started"] - process_ledger["completed"] - process_ledger["failed"],
    )
    process_ledger["telemetry_incomplete"] += max(
        0, execution.adapter_processes_used - process_ledger["started"]
    )
    terminal_process_events = [
        item
        for item in process_events
        if item["event"] in {"adapter.process.completed", "adapter.process.failed"}
    ]
    process_telemetry = [item["telemetry"] for item in terminal_process_events]
    resource_complete = process_ledger["telemetry_incomplete"] == 0
    process_peaks = [
        item["peak_rss_bytes"] for item in process_telemetry if item["peak_rss_bytes"] is not None
    ]
    adapter_process_resources = {
        "telemetry_complete": resource_complete,
        "wall_time_seconds": sum(item["wall_time_seconds"] for item in process_telemetry),
        "peak_rss_bytes": max(process_peaks) if process_peaks else None,
        "remote_queries": sum(item["remote_queries"] for item in process_telemetry)
        if resource_complete
        else None,
        "generated_tokens": sum(item["generated_tokens"] for item in process_telemetry)
        if resource_complete
        else None,
        "estimated_cost_usd": sum(item["estimated_cost_usd"] for item in process_telemetry)
        if resource_complete
        else None,
    }
    run_attempts = {
        "sample_failures": sum(
            item.get("event") == "sample.failed" and item.get("run_id") == run_id
            for item in journal.records
        ),
        "observation_failures": sum(
            item.get("event") == "observation.failed" and item.get("run_id") == run_id
            for item in journal.records
        ),
        "observation_attempts": sum(len(item["attempt_history"]) for item in completed.values()),
    }
    observation_set = finalize_observation_set(
        {
            "schema_version": "1.0",
            "sample_registry_sha256": sample_report["sample_registry_sha256"],
            "run_manifest": run_manifest,
            "detectors": detector_entries,
            "conditions": condition_descriptors,
            "requested_fprs": protocol_manifest["requested_fprs"],
            "observations": [completed[key] for key in sorted(completed)],
            "resource_summary": {
                "model_size_bytes": config["model_size_bytes"],
                "execution_budget": execution.public_summary(),
                "adapter_processes": process_ledger,
                "adapter_process_resources": adapter_process_resources,
                "run_attempts": run_attempts,
            },
            "human_review": config["human_review"],
            "reproduction": {
                "recipe_sha256": run_id,
                "timeout_seconds": int(config["execution_budget"]["deadline_seconds"]),
                "network_required": allow_network,
                "model_download_required": allow_model_download,
            },
        }
    )
    aggregate = aggregate_observation_set(
        observation_set,
        sample_registry,
        bootstrap_replicates=bootstrap_replicates,
        bootstrap_seed=bootstrap_seed,
        comparator_registry=comparator_registry,
        checkpoint=execution.perform_reserved_cancellation_check,
    )
    execution.perform_reserved_cancellation_check()
    observation_path = output_directory / "observations.json"
    comparator_path = output_directory / "comparator-registry.json"
    coverage = dict(aggregate["coverage"])
    coverage["artifact_handling"] = {
        "state": "complete",
        "reason": "source_artifacts_bound_by_digest",
    }
    public_results = dict(aggregate)
    public_results["score_tables"] = {
        name: {"sha256": table["sha256"], "records": len(table["records"])}
        for name, table in aggregate["score_tables"].items()
    }
    public_results["aggregate_sha256"] = results_identity(public_results)
    evidence_path = output_directory / "evidence.json"
    bundle = create_bundle(
        purpose=config["purpose"],
        manifest=run_manifest,
        protocol_coverage=coverage,
        results=public_results,
        resource_telemetry=aggregate["resource_telemetry"],
        reproduction=observation_set["reproduction"],
        artifacts=[
            _memory_artifact_descriptor(sample_path, sample_registry),
            _memory_artifact_descriptor(observation_path, observation_set),
            _memory_artifact_descriptor(comparator_path, comparator_registry),
        ],
        sample_registry_sha256=sample_report["sample_registry_sha256"],
        sample_count=sample_report["sample_count"],
    )
    _validate_public_tree(bundle)
    # Validate the complete public artifact graph before creating any artifact
    # temporary file. Checkpoint events follow the same validate-before-append rule.
    validate_bundle(bundle, artifact_root=output_directory, verify_artifacts=False)
    execution.perform_reserved_cancellation_check()
    _write_json(sample_path, sample_registry, resume=resume)
    _write_json(observation_path, observation_set, resume=resume)
    _write_json(comparator_path, comparator_registry, resume=resume)
    validate_bundle(bundle, artifact_root=output_directory, verify_artifacts=True)
    if evidence_path.exists():
        if not resume:
            raise BenchmarkRunError("evidence output already exists")
        existing, _ = _read_json(
            evidence_path, limit=MAX_CHECKPOINT_BYTES, label="existing evidence bundle"
        )
        if existing != bundle:
            raise BenchmarkRunError("existing evidence differs from resumed aggregate")
    else:
        write_bundle(evidence_path, bundle)
    execution._enforce_current()
    journal.append(
        {
            "event": "run.completed",
            "run_id": run_id,
            "bundle_id": bundle["bundle_id"],
            "completed_at_unix": int(time.time()),
        },
    )
    return {
        "classification": config["classification"],
        "run_id": run_id,
        "bundle_id": bundle["bundle_id"],
        "sample_registry_sha256": sample_report["sample_registry_sha256"],
        "observation_set_id": observation_set["observation_set_id"],
        "aggregate_sha256": public_results["aggregate_sha256"],
        "sample_count": sample_report["sample_count"],
        "observation_count": len(observation_set["observations"]),
        "registry_complete": sample_report["registry_complete"],
        "comparative_hypotheses_tested": aggregate["comparative_analysis"]["tested_hypotheses"],
        "files": {
            "sample_registry": sample_path.name,
            "observations": observation_path.name,
            "comparator_registry": comparator_path.name,
            "evidence": evidence_path.name,
            "checkpoint": checkpoint.name,
        },
    }
