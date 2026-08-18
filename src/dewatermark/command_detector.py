"""Bounded, versioned JSON-command detector adapter.

The adapter is intentionally detector-only.  Construction, capability access,
registration, and availability checks never start the command.  Source text is
sent on stdin only from :meth:`CommandDetector.detect` with an explicit
``action=detect`` request.

Commands are trusted executables selected by the caller, not security
sandboxes.  This module supplies consent gates, resource bounds, strict result
validation, and output redaction around that executable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import shutil
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Optional, Sequence, cast

from .bounded_process import BoundedProcessFailure, run_bounded_process
from .command_safety import (
    command_code_identity_sha256,
    validate_public_command,
    validate_public_json,
)
from .config import DewatermarkConfig, resolve
from .exceptions import AdapterError
from .models import CapabilityManifest, DetectionEvidence, DetectionStatus
from .request_context import (
    RequestContext,
    current_request_context,
    extension_resource_accounting,
    request_scope,
)

COMMAND_DETECTOR_PROTOCOL_VERSION = "1.1"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_STDOUT_BYTES = 64 * 1024
DEFAULT_MAX_STDERR_BYTES = 16 * 1024
_MAX_CAPTURE_BYTES = 16 * 1024 * 1024

ScoreDirection = Literal["higher", "lower"]
ThresholdOperator = Literal[">", ">=", "<", "<="]
SecretBinding = Literal["operator_managed_file"]
_PROTOCOL_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_LOWERCASE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_ALLOWED_STATUSES: tuple[DetectionStatus, ...] = (
    "detected",
    "not_detected",
    "insufficient_evidence",
    "unsupported",
    "configuration_mismatch",
    "detector_error",
)
_COMMAND_METADATA_FIELDS = frozenset(
    {
        "command_protocol_version",
        "configuration_sha256",
        "implementation_sha256",
        "minimum_effective_tokens",
        "score_direction",
        "secret_binding",
        "threshold",
        "threshold_operator",
        "watermark_target_sha256",
    }
)
_PUBLIC_COMMITMENT_FIELDS = frozenset(
    {
        "implementation_sha256",
        "profile_manifest_sha256",
        "source_file_sha256",
        "threshold_evidence_sha256",
        "tokenizer_sha256",
        "tokenizer_snapshot_sha256",
    }
)

# A command adapter is an isolation boundary for process credentials, even
# though the selected executable itself remains trusted.  In particular, do
# not pass the ambient environment to a detector: CI tokens, cloud credentials,
# and user API keys commonly live there.  PATH is required for a bare executable
# name.  Windows also needs these public process-discovery variables for normal
# executable and side-by-side assembly resolution.
_WINDOWS_COMMAND_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR", "PATHEXT")


class CommandDetectorError(AdapterError):
    """Base error for the runtime command-detector boundary."""


class CommandDetectorContractError(CommandDetectorError):
    """A command returned output that violated the versioned protocol."""


class CommandDetectorExecutionError(CommandDetectorError):
    """A command could not complete inside its declared resource bounds."""


class CommandDetectorConformanceError(CommandDetectorError):
    """One or more named golden vectors failed without reflecting their text."""


def _public_json_value(value: Any, *, path: str = "configuration") -> Any:
    """Validate JSON configuration while refusing credential-like fields."""
    return validate_public_json(value, source=path)


def _public_metadata(value: Any, *, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise TypeError(f"{path} must be a literal dictionary")
    commitments = {key: value[key] for key in _PUBLIC_COMMITMENT_FIELDS if key in value}
    for key, digest in commitments.items():
        if type(digest) is not str or _LOWERCASE_SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"{path} {key} must be a lowercase SHA-256 digest")
    remaining = {key: item for key, item in value.items() if key not in commitments}
    public = validate_public_json(remaining, source=path)
    return cast(dict[str, Any], {**public, **commitments})


def detector_configuration_sha256(configuration: Mapping[str, Any]) -> str:
    """Fingerprint public detector configuration without accepting secrets.

    Key material must be represented only by an opaque, non-derived public key
    identifier. Passing a field named like a credential is rejected so raw
    credential material cannot accidentally become a brute-forceable digest.
    """
    public = _public_json_value(configuration)
    encoded = json.dumps(public, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def _finite_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CommandDetectorContractError(f"detector response {field_name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise CommandDetectorContractError(f"detector response {field_name} must be finite")
    return result


def _nonnegative_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CommandDetectorContractError(
            f"detector response {field_name} must be a non-negative integer"
        )
    return value


def _protocol_major(value: Any, *, source: str) -> int:
    if not isinstance(value, str) or not _PROTOCOL_RE.fullmatch(value):
        raise CommandDetectorContractError(f"{source} protocol_version is invalid")
    return int(value.split(".", 1)[0])


def _protocol_minor(value: Any, *, source: str) -> int:
    _protocol_major(value, source=source)
    assert isinstance(value, str)
    return int(value.split(".", 1)[1])


def _validate_fingerprint(value: Any, *, source: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise CommandDetectorContractError(f"{source} configuration_sha256 is invalid")
    return value.lower()


def _validate_threshold_operator(
    value: Any, *, score_direction: ScoreDirection, source: str
) -> ThresholdOperator:
    allowed = (">", ">=") if score_direction == "higher" else ("<", "<=")
    if value not in allowed:
        expected = " or ".join(repr(item) for item in allowed)
        raise CommandDetectorContractError(
            f"{source} threshold_operator must be {expected} for {score_direction} scores"
        )
    return cast(ThresholdOperator, value)


def _threshold_met(score: float, threshold: float, operator: ThresholdOperator) -> bool:
    if operator == ">":
        return score > threshold
    if operator == ">=":
        return score >= threshold
    if operator == "<":
        return score < threshold
    return score <= threshold


def command_detector_manifest(
    *,
    identifier: str,
    schemes: Sequence[str],
    configuration_sha256: str,
    implementation_sha256: Optional[str] = None,
    threshold: float,
    score_direction: ScoreDirection = "higher",
    threshold_operator: Optional[ThresholdOperator] = None,
    minimum_effective_tokens: int = 0,
    version: str = "1",
    description: str = "External detector using the bounded JSON command protocol.",
    network_required: bool = False,
    model_download_possible: bool = False,
    requires_secret: bool = False,
    secret_binding: Optional[SecretBinding] = None,
    watermark_target_sha256: Optional[str] = None,
    minimum_characters: int = 0,
    calibrated: bool = False,
    independent: bool = False,
    metadata: Optional[Mapping[str, Any]] = None,
) -> CapabilityManifest:
    """Build a static capability manifest with a pinned decision contract."""
    if not identifier.strip():
        raise ValueError("detector identifier cannot be empty")
    if isinstance(schemes, str):
        raise TypeError("schemes must be a sequence of scheme identifiers, not one string")
    normalized_schemes = tuple(item.strip() for item in schemes)
    if not normalized_schemes or any(not item for item in normalized_schemes):
        raise ValueError("at least one non-empty detector scheme is required")
    if len(set(normalized_schemes)) != len(normalized_schemes):
        raise ValueError("detector schemes must be unique")
    fingerprint = _validate_fingerprint(configuration_sha256, source="manifest")
    declared_threshold = _finite_number(threshold, "manifest threshold")
    if score_direction not in ("higher", "lower"):
        raise ValueError("score_direction must be 'higher' or 'lower'")
    if threshold_operator is None:
        threshold_operator = ">=" if score_direction == "higher" else "<="
    declared_operator = _validate_threshold_operator(
        threshold_operator,
        score_direction=score_direction,
        source="manifest",
    )
    if (
        isinstance(minimum_effective_tokens, bool)
        or not isinstance(minimum_effective_tokens, int)
        or minimum_effective_tokens < 0
    ):
        raise ValueError("minimum_effective_tokens must be a non-negative integer")
    if isinstance(minimum_characters, bool) or not isinstance(minimum_characters, int):
        raise TypeError("minimum_characters must be an integer")
    if minimum_characters < 0:
        raise ValueError("minimum_characters must be non-negative")
    if secret_binding not in (None, "operator_managed_file"):
        raise ValueError("secret_binding must be 'operator_managed_file' when supplied")
    if secret_binding is not None and not requires_secret:
        raise ValueError("secret_binding requires requires_secret=True")
    public_metadata = _public_metadata(metadata or {}, path="metadata")
    metadata_implementation = public_metadata.pop("implementation_sha256", None)
    if implementation_sha256 is not None and metadata_implementation is not None:
        if implementation_sha256 != metadata_implementation:
            raise ValueError("implementation_sha256 declarations do not match")
    implementation = (
        implementation_sha256 if implementation_sha256 is not None else metadata_implementation
    )
    if implementation is not None and (
        not isinstance(implementation, str)
        or _LOWERCASE_SHA256_RE.fullmatch(implementation) is None
    ):
        raise ValueError("implementation_sha256 must be a lowercase SHA-256 digest")
    metadata_target = public_metadata.pop("watermark_target_sha256", None)
    if watermark_target_sha256 is not None and metadata_target is not None:
        if watermark_target_sha256 != metadata_target:
            raise ValueError("watermark_target_sha256 declarations do not match")
    target = watermark_target_sha256 if watermark_target_sha256 is not None else metadata_target
    if target is not None and (
        not isinstance(target, str) or _LOWERCASE_SHA256_RE.fullmatch(target) is None
    ):
        raise ValueError("watermark_target_sha256 must be a lowercase SHA-256 digest")
    reserved = {
        "command_protocol_version": COMMAND_DETECTOR_PROTOCOL_VERSION,
        "configuration_sha256": fingerprint,
        "threshold": declared_threshold,
        "score_direction": score_direction,
        "threshold_operator": declared_operator,
        "minimum_effective_tokens": minimum_effective_tokens,
    }
    if implementation is not None:
        reserved["implementation_sha256"] = implementation
    if secret_binding is not None:
        reserved["secret_binding"] = secret_binding
    if target is not None:
        reserved["watermark_target_sha256"] = target
    conflicts = set(public_metadata).intersection(reserved)
    if conflicts:
        raise ValueError("metadata cannot override command-detector contract fields")
    return CapabilityManifest(
        identifier=identifier.strip(),
        kind="detector",
        version=version,
        schemes=normalized_schemes,
        description=description,
        network_required=network_required,
        model_download_possible=model_download_possible,
        requires_secret=requires_secret,
        minimum_characters=minimum_characters,
        calibrated=calibrated,
        independent=independent,
        metadata={**public_metadata, **reserved},
    )


def _validate_command(command: tuple[str, ...]) -> tuple[str, ...]:
    return validate_public_command(command)


def _command_environment() -> dict[str, str]:
    """Return the minimal non-secret environment inherited by adapters."""
    environment = {"PATH": os.environ.get("PATH", os.defpath)}
    if os.name == "nt":
        for key in _WINDOWS_COMMAND_ENVIRONMENT_KEYS:
            value = os.environ.get(key)
            if value is not None:
                environment[key] = value
    return environment


@dataclass(frozen=True)
class _DetectorContract:
    protocol_version: str
    configuration_sha256: str
    threshold: float
    score_direction: ScoreDirection
    threshold_operator: ThresholdOperator
    threshold_operator_explicit: bool
    secret_binding: Optional[SecretBinding]
    implementation_sha256: Optional[str]
    watermark_target_sha256: Optional[str]
    minimum_effective_tokens: int


def _contract_from_manifest(capability: CapabilityManifest) -> _DetectorContract:
    if not isinstance(capability, CapabilityManifest) or capability.kind != "detector":
        raise TypeError("capability must be a detector CapabilityManifest")
    if not capability.identifier.strip() or not capability.schemes:
        raise ValueError("detector capability requires an identifier and at least one scheme")
    if any(not isinstance(item, str) or not item.strip() for item in capability.schemes):
        raise ValueError("detector capability schemes must be non-empty strings")
    if len(set(capability.schemes)) != len(capability.schemes):
        raise ValueError("detector capability schemes must be unique")
    metadata = capability.metadata
    if type(metadata) is not dict:
        raise TypeError("capability.metadata must be a literal dictionary")
    non_contract_metadata = {
        key: value for key, value in metadata.items() if key not in _COMMAND_METADATA_FIELDS
    }
    _public_metadata(non_contract_metadata, path="capability.metadata")
    version = metadata.get("command_protocol_version")
    if _protocol_major(version, source="manifest") != _protocol_major(
        COMMAND_DETECTOR_PROTOCOL_VERSION, source="runtime"
    ):
        raise CommandDetectorContractError("manifest uses an incompatible command protocol")
    modern_contract = _protocol_minor(version, source="manifest") >= 1
    fingerprint = _validate_fingerprint(metadata.get("configuration_sha256"), source="manifest")
    threshold = _finite_number(metadata.get("threshold"), "manifest threshold")
    direction = metadata.get("score_direction")
    if direction not in ("higher", "lower"):
        raise CommandDetectorContractError("manifest score_direction must be 'higher' or 'lower'")
    raw_operator = metadata.get("threshold_operator") if modern_contract else None
    operator_explicit = modern_contract
    if raw_operator is None:
        if modern_contract:
            raise CommandDetectorContractError(
                "manifest threshold_operator is required by command protocol 1.1"
            )
        raw_operator = ">=" if direction == "higher" else "<="
    operator = _validate_threshold_operator(
        raw_operator,
        score_direction=cast(ScoreDirection, direction),
        source="manifest",
    )
    minimum_tokens = metadata.get("minimum_effective_tokens")
    if (
        isinstance(minimum_tokens, bool)
        or not isinstance(minimum_tokens, int)
        or minimum_tokens < 0
    ):
        raise CommandDetectorContractError(
            "manifest minimum_effective_tokens must be a non-negative integer"
        )
    raw_secret_binding = metadata.get("secret_binding") if modern_contract else None
    if raw_secret_binding not in (None, "operator_managed_file"):
        raise CommandDetectorContractError("manifest secret_binding is unsupported")
    if raw_secret_binding is not None and not capability.requires_secret:
        raise CommandDetectorContractError("manifest secret_binding requires requires_secret=true")
    target = metadata.get("watermark_target_sha256") if modern_contract else None
    if target is not None and (
        not isinstance(target, str) or _LOWERCASE_SHA256_RE.fullmatch(target) is None
    ):
        raise CommandDetectorContractError(
            "manifest watermark_target_sha256 must be a lowercase SHA-256 digest"
        )
    implementation = metadata.get("implementation_sha256") if modern_contract else None
    if implementation is not None and (
        not isinstance(implementation, str)
        or _LOWERCASE_SHA256_RE.fullmatch(implementation) is None
    ):
        raise CommandDetectorContractError(
            "manifest implementation_sha256 must be a lowercase SHA-256 digest"
        )
    return _DetectorContract(
        protocol_version=cast(str, version),
        configuration_sha256=fingerprint,
        threshold=threshold,
        score_direction=cast(ScoreDirection, direction),
        threshold_operator=operator,
        threshold_operator_explicit=operator_explicit,
        secret_binding=cast(Optional[SecretBinding], raw_secret_binding),
        implementation_sha256=implementation,
        watermark_target_sha256=target,
        minimum_effective_tokens=minimum_tokens,
    )


def _validate_limits(timeout_seconds: float, stdout_bytes: int, stderr_bytes: int) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or timeout_seconds > 3600
    ):
        raise ValueError("timeout_seconds must be finite and between 0 and 3600")
    for name, value in (("max_stdout_bytes", stdout_bytes), ("max_stderr_bytes", stderr_bytes)):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= _MAX_CAPTURE_BYTES
        ):
            raise ValueError(f"{name} must be between 1 and {_MAX_CAPTURE_BYTES}")


def _run_bounded_command(
    command: tuple[str, ...],
    payload: bytes,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> bytes:
    """Run argv directly through the shared process-tree boundary."""

    def checkpoint() -> None:
        context = current_request_context()
        if context is not None:
            context.checkpoint()

    try:
        result = run_bounded_process(
            command,
            payload,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            environment=_command_environment(),
            checkpoint=checkpoint,
        )
    except BoundedProcessFailure as exc:
        if exc.kind == "launch_failed":
            message = "command detector could not be launched; process details were redacted"
        elif exc.kind == "timed_out":
            message = "command detector timed out; stdout and stderr were redacted"
        elif exc.kind == "output_limit":
            message = "command detector exceeded its output limit; stdout and stderr were redacted"
        elif exc.kind == "nonzero_exit":
            message = (
                f"command detector exited with status {exc.returncode}; "
                "stdout and stderr were redacted"
            )
        else:
            message = "command detector cleanup failed; process details were redacted"
        raise CommandDetectorExecutionError(message) from None
    return result.stdout


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CommandDetectorContractError("detector response contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise CommandDetectorContractError("detector response contains a non-finite JSON number")


def _decode_response(output: bytes) -> Mapping[str, Any]:
    try:
        text = output.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise CommandDetectorContractError(
            "command detector returned non-UTF-8 output; response content was redacted"
        ) from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except CommandDetectorContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise CommandDetectorContractError(
            "command detector returned invalid JSON; response content was redacted"
        ) from None
    if not isinstance(value, Mapping):
        raise CommandDetectorContractError("command detector must return one JSON object")
    return value


class CommandDetector:
    """Detector backed by one explicitly configured JSON command."""

    def __init__(
        self,
        command: tuple[str, ...],
        capability: CapabilityManifest,
        config: Optional[DewatermarkConfig] = None,
        *,
        timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
        max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
        max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
    ) -> None:
        self._command = _validate_command(command)
        self.capability = capability
        self._contract = _contract_from_manifest(capability)
        self._config = resolve(config)
        _validate_limits(timeout_seconds, max_stdout_bytes, max_stderr_bytes)
        self._timeout_seconds = float(timeout_seconds)
        self._max_stdout_bytes = max_stdout_bytes
        self._max_stderr_bytes = max_stderr_bytes
        # Compatibility for code that reads a detector threshold directly.
        self.threshold = self._contract.threshold

    def __repr__(self) -> str:
        return "<command detector; representation redacted>"

    def available(self) -> bool:
        """Check only executable presence; never invoke it or import a plugin."""
        executable = self._command[0]
        if os.path.dirname(executable):
            return os.path.isfile(executable) and os.access(executable, os.X_OK)
        return shutil.which(executable) is not None

    def _verification_code_sha256(self) -> Optional[str]:
        """Return the current bounded executable/script identity for assurance."""
        return command_code_identity_sha256(self._command)

    def _static_evidence(
        self, text: str, status: DetectionStatus, reason: str
    ) -> DetectionEvidence:
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme=self.capability.schemes[0],
            status=status,
            threshold=self._contract.threshold,
            text_characters=len(text),
            reason=reason,
            details={
                "protocol_version": self._contract.protocol_version,
                "configuration_sha256": self._contract.configuration_sha256,
                "effective_tokens": 0,
                "score_direction": self._contract.score_direction,
                "threshold_operator": self._contract.threshold_operator,
            },
        )

    def _preflight(
        self,
        text: str,
        *,
        allow_network: bool,
        allow_model_download: bool,
    ) -> Optional[DetectionEvidence]:
        if self.capability.network_required and not allow_network:
            return self._static_evidence(
                text,
                "configuration_mismatch",
                "detector requires explicit remote-processing consent",
            )
        if self.capability.model_download_possible and not allow_model_download:
            return self._static_evidence(
                text,
                "configuration_mismatch",
                "detector requires explicit model-download consent",
            )
        if (
            self.capability.requires_secret
            and self._contract.secret_binding != "operator_managed_file"
        ):
            return self._static_evidence(
                text,
                "configuration_mismatch",
                "detector requires a secret, but the command adapter has no explicit secret channel",
            )
        if not text:
            return self._static_evidence(
                text, "insufficient_evidence", "detector requires non-empty text"
            )
        if len(text) < self.capability.minimum_characters:
            return self._static_evidence(
                text,
                "insufficient_evidence",
                f"detector requires at least {self.capability.minimum_characters} characters",
            )
        if len(text) > self._config.max_input_chars:
            return self._static_evidence(
                text,
                "configuration_mismatch",
                "text exceeds the configured command-detector input limit",
            )
        return None

    def detect(self, text: str) -> DetectionEvidence:
        if not isinstance(text, str):
            raise TypeError("command detector text must be a string")
        context = current_request_context()
        if context is None:
            with request_scope(RequestContext.from_config(self._config)):
                return self.detect(text)
        allow_network = self._config.allow_remote_processing and context.allow_remote_processing
        allow_model_download = self._config.allow_model_download and context.allow_model_download
        preflight = self._preflight(
            text,
            allow_network=allow_network,
            allow_model_download=allow_model_download,
        )
        if preflight is not None:
            return preflight
        timeout = min(self._timeout_seconds, float(self._config.request_timeout))
        timeout = context.remaining_seconds(timeout)
        accounting = extension_resource_accounting(self.capability)
        if accounting == "network":
            # The child controls its own endpoints, so the parent conservatively
            # reserves one external-command operation without publishing argv or
            # an endpoint. Untrusted adapters still require OS/container policy.
            context.before_remote_call(
                "https://external-command-detector.invalid/detect",
                "remote",
                {"text": text},
            )
        if accounting == "model" or self.capability.model_download_possible:
            context.record_model_access(
                self.capability.identifier,
                cached=not self.capability.model_download_possible,
                download_allowed=allow_model_download,
            )
        request = {
            "protocol_version": self._contract.protocol_version,
            "action": "detect",
            "detector": self.capability.identifier,
            "configuration_sha256": self._contract.configuration_sha256,
            "policy": {
                "allow_network": allow_network,
                "allow_model_download": allow_model_download,
            },
            "text": text,
        }
        payload = json.dumps(
            request, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        output = _run_bounded_command(
            self._command,
            payload,
            timeout_seconds=timeout,
            max_stdout_bytes=self._max_stdout_bytes,
            max_stderr_bytes=self._max_stderr_bytes,
        )
        evidence = self._normalize_response(_decode_response(output), text)
        context.checkpoint()
        return evidence

    def _normalize_response(self, response: Mapping[str, Any], text: str) -> DetectionEvidence:
        response_version = response.get("protocol_version")
        if _protocol_major(response_version, source="response") != _protocol_major(
            COMMAND_DETECTOR_PROTOCOL_VERSION, source="runtime"
        ):
            raise CommandDetectorContractError(
                "command detector returned an incompatible protocol version"
            )
        if (
            self._contract.threshold_operator_explicit
            and _protocol_minor(response_version, source="response") < 1
        ):
            raise CommandDetectorContractError(
                "command detector response does not support the bound decision contract"
            )
        if response.get("action") != "detect.result":
            raise CommandDetectorContractError(
                "command detector response action must be detect.result"
            )
        if response.get("detector") != self.capability.identifier:
            raise CommandDetectorContractError(
                "command detector response identifier does not match its static manifest"
            )
        scheme = response.get("scheme")
        if not isinstance(scheme, str) or scheme not in self.capability.schemes:
            raise CommandDetectorContractError(
                "command detector response scheme is not declared by its static manifest"
            )
        raw_status = response.get("status")
        if raw_status not in _ALLOWED_STATUSES:
            raise CommandDetectorContractError("command detector response status is invalid")
        status = cast(DetectionStatus, raw_status)
        response_fingerprint = _validate_fingerprint(
            response.get("configuration_sha256"), source="response"
        )
        effective_tokens = _nonnegative_integer(
            response.get("effective_tokens"), "effective_tokens"
        )
        direction = response.get("score_direction")
        if direction not in ("higher", "lower"):
            raise CommandDetectorContractError(
                "detector response score_direction must be 'higher' or 'lower'"
            )
        raw_operator = (
            response.get("threshold_operator")
            if self._contract.threshold_operator_explicit
            else self._contract.threshold_operator
        )
        if raw_operator is None:
            if self._contract.threshold_operator_explicit:
                raise CommandDetectorContractError(
                    "detector response threshold_operator is required by its static manifest"
                )
            raw_operator = self._contract.threshold_operator
        operator = _validate_threshold_operator(
            raw_operator,
            score_direction=cast(ScoreDirection, direction),
            source="response",
        )
        raw_score = response.get("score")
        score = _finite_number(raw_score, "score") if raw_score is not None else None
        threshold = _finite_number(response.get("threshold"), "threshold")
        if status in ("detected", "not_detected") and score is None:
            raise CommandDetectorContractError(
                "detected and not_detected responses require a numeric score and threshold"
            )
        mismatch_fields: list[str] = []
        if response_fingerprint != self._contract.configuration_sha256:
            mismatch_fields.append("configuration_sha256")
        if direction != self._contract.score_direction:
            mismatch_fields.append("score_direction")
        if operator != self._contract.threshold_operator:
            mismatch_fields.append("threshold_operator")
        if threshold != self._contract.threshold:
            mismatch_fields.append("threshold")
        details: dict[str, Any] = {
            "protocol_version": cast(str, response_version),
            "configuration_sha256": self._contract.configuration_sha256,
            "effective_tokens": effective_tokens,
            "score_direction": self._contract.score_direction,
            "threshold_operator": self._contract.threshold_operator,
        }
        reason_code = response.get("reason_code")
        reason: Optional[str] = None
        if reason_code is not None:
            if not isinstance(reason_code, str) or not _REASON_CODE_RE.fullmatch(reason_code):
                raise CommandDetectorContractError("detector response reason_code is invalid")
            details["reason_code"] = "detector_reported_reason"
            reason = "command detector reported a reason code"
        for optional_numeric in ("p_value", "z_score"):
            if optional_numeric in response:
                value = _finite_number(response[optional_numeric], optional_numeric)
                if optional_numeric == "p_value" and not 0 <= value <= 1:
                    raise CommandDetectorContractError(
                        "detector response p_value must be between 0 and 1"
                    )
                details[optional_numeric] = value
        if mismatch_fields:
            details["mismatch_fields"] = sorted(mismatch_fields)
            return DetectionEvidence(
                detector=self.capability.identifier,
                scheme=scheme,
                status="configuration_mismatch",
                score=score,
                threshold=self._contract.threshold,
                text_characters=len(text),
                reason="command detector output does not match its static capability manifest",
                details=details,
            )
        if status in ("detected", "not_detected"):
            assert score is not None
            positive = _threshold_met(
                score,
                self._contract.threshold,
                self._contract.threshold_operator,
            )
            if (status == "detected") != positive:
                raise CommandDetectorContractError(
                    "command detector status contradicts its score, threshold, and direction"
                )
        if effective_tokens < self._contract.minimum_effective_tokens:
            details["reported_status"] = status
            status = "insufficient_evidence"
            reason = (
                "detector produced fewer effective tokens than its static minimum "
                f"({self._contract.minimum_effective_tokens})"
            )
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme=scheme,
            status=status,
            score=score,
            threshold=self._contract.threshold,
            text_characters=len(text),
            reason=reason,
            details=details,
        )


@dataclass(frozen=True, repr=False)
class CommandDetectorFactory:
    """Callable, static-manifest factory suitable for ``register_detector``."""

    command: tuple[str, ...]
    capability: CapabilityManifest
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES

    def __post_init__(self) -> None:
        _validate_command(self.command)
        _contract_from_manifest(self.capability)
        _validate_limits(self.timeout_seconds, self.max_stdout_bytes, self.max_stderr_bytes)

    def __repr__(self) -> str:
        return "<command detector factory; representation redacted>"

    def __call__(self, config: Optional[DewatermarkConfig] = None) -> CommandDetector:
        return CommandDetector(
            self.command,
            self.capability,
            config,
            timeout_seconds=self.timeout_seconds,
            max_stdout_bytes=self.max_stdout_bytes,
            max_stderr_bytes=self.max_stderr_bytes,
        )


def make_command_detector_factory(
    command: tuple[str, ...],
    capability: CapabilityManifest,
    *,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
) -> CommandDetectorFactory:
    """Create a registration-ready factory without starting the command."""
    return CommandDetectorFactory(
        command=command,
        capability=capability,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )


@dataclass(frozen=True, repr=False)
class DetectorGoldenVector:
    """One named, content-redacting detector conformance vector."""

    name: str
    text: str
    expected_status: DetectionStatus
    expected_score: Optional[float]
    expected_threshold: float
    expected_effective_tokens: int

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.text, str):
            raise ValueError("golden vector requires a name and string text")
        if self.expected_status not in _ALLOWED_STATUSES:
            raise ValueError("golden vector expected_status is invalid")
        if self.expected_score is not None and not math.isfinite(float(self.expected_score)):
            raise ValueError("golden vector expected_score must be finite")
        if not math.isfinite(float(self.expected_threshold)):
            raise ValueError("golden vector expected_threshold must be finite")
        if (
            isinstance(self.expected_effective_tokens, bool)
            or not isinstance(self.expected_effective_tokens, int)
            or self.expected_effective_tokens < 0
        ):
            raise ValueError("golden vector expected_effective_tokens must be non-negative")

    def __repr__(self) -> str:
        return f"DetectorGoldenVector(name={self.name!r}, text=<redacted>)"


@dataclass(frozen=True)
class DetectorConformanceCase:
    name: str
    passed: bool
    mismatches: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectorConformanceReport:
    detector: str
    protocol_version: str
    cases: tuple[DetectorConformanceCase, ...]

    @property
    def passed(self) -> bool:
        return bool(self.cases) and all(item.passed for item in self.cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "protocol_version": self.protocol_version,
            "passed": self.passed,
            "cases": [
                {
                    "name": item.name,
                    "passed": item.passed,
                    "mismatches": list(item.mismatches),
                }
                for item in self.cases
            ],
        }


def run_command_detector_conformance(
    detector: CommandDetector,
    vectors: Sequence[DetectorGoldenVector],
    *,
    absolute_tolerance: float = 1e-9,
) -> DetectorConformanceReport:
    """Run golden vectors and report only names and mismatched field names."""
    if absolute_tolerance < 0 or not math.isfinite(absolute_tolerance):
        raise ValueError("absolute_tolerance must be finite and non-negative")
    cases: list[DetectorConformanceCase] = []
    for vector in vectors:
        mismatches: list[str] = []
        try:
            evidence = detector.detect(vector.text)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                raise
            mismatches.append("execution")
        else:
            if evidence.status != vector.expected_status:
                mismatches.append("status")
            if vector.expected_score is None:
                if evidence.score is not None:
                    mismatches.append("score")
            elif evidence.score is None or not math.isclose(
                evidence.score,
                vector.expected_score,
                rel_tol=0.0,
                abs_tol=absolute_tolerance,
            ):
                mismatches.append("score")
            if evidence.threshold is None or not math.isclose(
                evidence.threshold,
                vector.expected_threshold,
                rel_tol=0.0,
                abs_tol=absolute_tolerance,
            ):
                mismatches.append("threshold")
            if evidence.details.get("effective_tokens") != vector.expected_effective_tokens:
                mismatches.append("effective_tokens")
        cases.append(
            DetectorConformanceCase(
                name=vector.name,
                passed=not mismatches,
                mismatches=tuple(sorted(set(mismatches))),
            )
        )
    return DetectorConformanceReport(
        detector=detector.capability.identifier,
        protocol_version=COMMAND_DETECTOR_PROTOCOL_VERSION,
        cases=tuple(cases),
    )


def assert_command_detector_conformance(
    detector: CommandDetector,
    vectors: Sequence[DetectorGoldenVector],
    *,
    absolute_tolerance: float = 1e-9,
) -> DetectorConformanceReport:
    """Raise a content-redacting error when any golden vector fails."""
    report = run_command_detector_conformance(
        detector, vectors, absolute_tolerance=absolute_tolerance
    )
    if not report.passed:
        failed_count = sum(not case.passed for case in report.cases)
        raise CommandDetectorConformanceError(
            f"command detector conformance failed for {failed_count} case(s)"
        )
    return report


__all__ = [
    "COMMAND_DETECTOR_PROTOCOL_VERSION",
    "CommandDetector",
    "CommandDetectorConformanceError",
    "CommandDetectorContractError",
    "CommandDetectorError",
    "CommandDetectorExecutionError",
    "CommandDetectorFactory",
    "DetectorConformanceCase",
    "DetectorConformanceReport",
    "DetectorGoldenVector",
    "SecretBinding",
    "ThresholdOperator",
    "assert_command_detector_conformance",
    "command_detector_manifest",
    "detector_configuration_sha256",
    "make_command_detector_factory",
    "run_command_detector_conformance",
]
