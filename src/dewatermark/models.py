"""Versioned, JSON-serializable public result models."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, Optional

SCHEMA_VERSION = "1.0"
RemovalMode = Literal[
    "auto", "sanitize", "paraphrase", "full", "sira", "bias_inversion", "adversarial"
]
SanitizeProfile = Literal["safe", "aggressive"]
ResultStatus = Literal["success", "unchanged", "partial", "failed"]
DetectionStatus = Literal[
    "detected",
    "not_detected",
    "insufficient_evidence",
    "unsupported",
    "configuration_mismatch",
    "detector_error",
]
TransformationStatus = Literal[
    "unchanged",
    "unicode_sanitized",
    "mitigation_verified",
    "mitigation_unverified",
    "unsupported_scheme",
    "rejected_quality",
    "failed",
]
VerificationStatus = Literal["verified_cleared", "residual", "not_verifiable", "failed"]


class _RedactedRepr:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<dewatermark result; representation redacted>"


_PRIVATE_METADATA_KEYS = {
    "api_key",
    "authorization",
    "body",
    "candidate",
    "content",
    "credential",
    "headers",
    "password",
    "private_key",
    "prompt",
    "response",
    "secret",
    "source_text",
    "text",
    "token",
}
_PRIVATE_PATH_KEYS = {
    "directories",
    "directory",
    "file",
    "filename",
    "filenames",
    "files",
    "path",
    "paths",
}
_PRIVATE_PATH_SUFFIXES = (
    "_directories",
    "_directory",
    "_file",
    "_filename",
    "_filenames",
    "_files",
    "_path",
    "_paths",
)
_PUBLIC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_ABSOLUTE_PRIVATE_PATH = re.compile(r"^(?:/|~[/\\]|[A-Za-z]:[/\\]|\\\\)")
_EMBEDDED_PRIVATE_PATH = re.compile(
    r"(?i)(?:^|[\s\"'(=])(?:/(?:Users|home|root|private|var|etc|opt|tmp)/|"
    r"~[/\\]|[A-Za-z]:[/\\]|\\\\)"
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:sk|rk)[-_](?:live|test|proj|ant)?[-_A-Za-z0-9]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_SENSITIVE_VALUE_MARKER = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:api[-_]?key|bearer|credential|password|private|secret|token)"
    r"(?![A-Za-z0-9])"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DECISION_OPERATORS = frozenset({">", ">=", "<", "<="})


def _private_metadata_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _PRIVATE_METADATA_KEYS or normalized.endswith(
        ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
    )


def _private_path_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _PRIVATE_PATH_KEYS or normalized.endswith(_PRIVATE_PATH_SUFFIXES)


def _unsafe_public_text(value: str) -> bool:
    """Identify values that must never enter a public result representation."""
    if len(value) > 4096 or any(character in value for character in ("\x00", "\r", "\n")):
        return True
    stripped = value.strip()
    if _ABSOLUTE_PRIVATE_PATH.match(stripped) or _EMBEDDED_PRIVATE_PATH.search(value):
        return True
    if re.search(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", stripped):
        return True
    if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
        return True
    # Public identifiers may otherwise look syntactically valid while carrying
    # an accidentally pasted credential. Requiring two explicit privacy markers
    # avoids treating ordinary identifiers such as ``secret-provider`` as secret
    # material while covering credential-bearing labels and diagnostic strings.
    return len(_SENSITIVE_VALUE_MARKER.findall(value)) >= 2


def _public_identifier(value: Any) -> str:
    if (
        type(value) is str
        and _PUBLIC_IDENTIFIER.fullmatch(value)
        and not _unsafe_public_text(value)
    ):
        return value
    return "redacted-identifier"


def _public_metadata(value: Any, *, key: str = "") -> Any:
    if _private_metadata_key(key):
        return "<redacted>"
    if _private_path_key(key):
        return None if value is None else "<redacted>"
    value_type = type(value)
    if value_type is dict:
        projected: dict[str, Any] = {}
        for item_key, item in value.items():
            if type(item_key) is not str or _unsafe_public_text(item_key):
                continue
            projected[item_key] = _public_metadata(item, key=item_key)
        return projected
    if value_type in (list, tuple):
        return [_public_metadata(item) for item in value]
    if value_type is str:
        return _public_text(value)
    if value is None or value_type in (bool, int):
        return value
    if value_type is float:
        return value if math.isfinite(value) else "<redacted>"
    # Never reflect an arbitrary object's class name or representation. Both
    # are user-controlled and can contain credentials.
    return "<redacted>"


def _public_mapping(value: Any) -> dict[str, Any]:
    projected = _public_metadata(value)
    return projected if type(projected) is dict else {}


def _public_strings(value: Any) -> list[str]:
    if type(value) not in (list, tuple):
        return []
    return [_public_text(item) for item in value]


def _public_text(value: Any) -> str:
    return value if type(value) is str and not _unsafe_public_text(value) else "<redacted>"


def _public_optional_text(value: Any) -> Optional[str]:
    return value if value is None else _public_text(value)


def _public_bool(value: Any) -> bool:
    return value if type(value) is bool else False


def _public_integer(value: Any) -> int:
    return value if type(value) is int else 0


def _public_number(value: Any) -> Optional[float | int]:
    if type(value) in (int, float) and math.isfinite(float(value)):
        return value
    return None


def _threshold_decision(score: float | int, threshold: float | int, operator: str) -> bool:
    if operator == ">":
        return score > threshold
    if operator == ">=":
        return score >= threshold
    if operator == "<":
        return score < threshold
    return score <= threshold


@dataclass(frozen=True, repr=False)
class CapabilityManifest(_RedactedRepr, Mapping[str, Any]):
    """Static, side-effect-free description of an extension capability."""

    identifier: str
    kind: Literal["detector", "transformer", "scorer", "quality_gate", "semantic_scorer", "chunker"]
    version: str = "1"
    schemes: tuple[str, ...] = ()
    description: str = ""
    network_required: bool = False
    model_download_possible: bool = False
    requires_secret: bool = False
    minimum_characters: int = 0
    calibrated: bool = False
    independent: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Several planning and receipt paths intentionally read these static
        # fields directly. Normalize exact strings at construction so a
        # credential or host path cannot bypass ``to_dict`` through those paths.
        if type(self.identifier) is str:
            object.__setattr__(self, "identifier", _public_identifier(self.identifier))
        for name in ("version", "description"):
            value = getattr(self, name)
            if type(value) is str:
                object.__setattr__(self, name, _public_text(value))
        if type(self.schemes) is tuple:
            object.__setattr__(
                self,
                "schemes",
                tuple(_public_text(item) if type(item) is str else item for item in self.schemes),
            )

    def to_dict(self) -> dict[str, Any]:
        # Construct this explicitly instead of ``asdict``: dataclass deep-copy
        # traversal could invoke hooks on an arbitrary metadata object before
        # the public projection has a chance to reject it.
        return {
            "identifier": _public_identifier(self.identifier),
            "kind": _public_text(self.kind),
            "version": _public_text(self.version),
            "schemes": _public_strings(self.schemes),
            "description": _public_text(self.description),
            "network_required": _public_bool(self.network_required),
            "model_download_possible": _public_bool(self.model_download_possible),
            "requires_secret": _public_bool(self.requires_secret),
            "minimum_characters": _public_integer(self.minimum_characters),
            "calibrated": _public_bool(self.calibrated),
            "independent": _public_bool(self.independent),
            "metadata": _public_mapping(self.metadata),
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, repr=False)
class DetectionEvidence(_RedactedRepr, Mapping[str, Any]):
    """A detector-scoped observation; never an authorship classification."""

    detector: str
    status: DetectionStatus
    scheme: Optional[str] = None
    score: Optional[float] = None
    threshold: Optional[float] = None
    text_characters: int = 0
    reason: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = {
            "detector": _public_text(self.detector),
            "status": _public_text(self.status),
            "scheme": _public_optional_text(self.scheme),
            "score": _public_number(self.score),
            "threshold": _public_number(self.threshold),
            "text_characters": _public_integer(self.text_characters),
            "reason": _public_optional_text(self.reason),
            "details": _public_mapping(self.details),
            "schema_version": self.schema_version,
        }
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.details[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, repr=False)
class VerificationEvidence(_RedactedRepr, Mapping[str, Any]):
    """Before/after detector evidence and its deliberately narrow conclusion."""

    status: VerificationStatus
    detector: Optional[str] = None
    before: Optional[DetectionEvidence] = None
    after: Optional[DetectionEvidence] = None
    reason: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("verification evidence has an invalid schema version")
        if self.status not in {"verified_cleared", "residual", "not_verifiable", "failed"}:
            raise ValueError("verification evidence has an invalid status")
        if self.status != "verified_cleared":
            return
        if (
            type(self.detector) is not str
            or not self.detector
            or type(self.before) is not DetectionEvidence
            or type(self.after) is not DetectionEvidence
            or type(self.before.detector) is not str
            or type(self.after.detector) is not str
            or type(self.before.scheme) is not str
            or not self.before.scheme
            or type(self.after.scheme) is not str
            or self.before.detector != self.detector
            or self.after.detector != self.detector
            or self.before.status != "detected"
            or self.after.status != "not_detected"
            or self.before.scheme != self.after.scheme
            or type(self.before.details) is not dict
            or type(self.after.details) is not dict
            or self.reason is not None
        ):
            raise ValueError("verified clearance requires complete paired detector evidence")
        configuration = self.before.details.get("configuration_sha256")
        direction = self.before.details.get("score_direction")
        operator = self.before.details.get("threshold_operator")
        before_score = _public_number(self.before.score)
        after_score = _public_number(self.after.score)
        threshold = _public_number(self.before.threshold)
        after_threshold = _public_number(self.after.threshold)
        if (
            type(configuration) is not str
            or _SHA256.fullmatch(configuration) is None
            or type(direction) is not str
            or direction not in {"higher", "lower"}
            or type(operator) is not str
            or operator not in _DECISION_OPERATORS
            or before_score is None
            or after_score is None
            or threshold is None
            or after_threshold is None
            or float(threshold) != float(after_threshold)
            or (operator in {">", ">="}) != (direction == "higher")
            or self.after.details.get("configuration_sha256") != configuration
            or self.after.details.get("score_direction") != direction
            or self.after.details.get("threshold_operator") != operator
        ):
            raise ValueError("verified clearance requires one bound detector decision contract")
        before_positive = _threshold_decision(before_score, threshold, operator)
        after_positive = _threshold_decision(after_score, threshold, operator)
        if not before_positive or after_positive:
            raise ValueError("verified clearance contradicts its detector threshold")

    def to_dict(self) -> dict[str, Any]:
        value = {
            "status": _public_text(self.status),
            "detector": _public_optional_text(self.detector),
            "before": self.before.to_dict() if type(self.before) is DetectionEvidence else None,
            "after": self.after.to_dict() if type(self.after) is DetectionEvidence else None,
            "reason": _public_optional_text(self.reason),
            "schema_version": _public_text(self.schema_version),
        }
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, repr=False)
class EvidenceReceipt(_RedactedRepr, Mapping[str, Any]):
    """Content-free, reproducible assurance record for one operation."""

    input_sha256: str
    output_sha256: str
    mode: RemovalMode
    detection: DetectionStatus
    transformation: TransformationStatus
    verification: VerificationStatus
    changed: bool
    detector: Optional[str] = None
    detector_before: Optional[DetectionEvidence] = None
    detector_after: Optional[DetectionEvidence] = None
    quality: Mapping[str, Any] = field(default_factory=dict)
    resources: Mapping[str, Any] = field(default_factory=dict)
    provenance: Mapping[str, Any] = field(default_factory=dict)
    policy: Mapping[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    claim_scope: str = "No authorship inference; verification is limited to the named detector."
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = {
            "input_sha256": _public_text(self.input_sha256),
            "output_sha256": _public_text(self.output_sha256),
            "mode": _public_text(self.mode),
            "detection": _public_text(self.detection),
            "transformation": _public_text(self.transformation),
            "verification": _public_text(self.verification),
            "changed": _public_bool(self.changed),
            "detector": _public_optional_text(self.detector),
            "detector_before": (
                self.detector_before.to_dict()
                if type(self.detector_before) is DetectionEvidence
                else None
            ),
            "detector_after": (
                self.detector_after.to_dict()
                if type(self.detector_after) is DetectionEvidence
                else None
            ),
            "quality": _public_mapping(self.quality),
            "resources": _public_mapping(self.resources),
            "provenance": _public_mapping(self.provenance),
            "policy": _public_mapping(self.policy),
            "warnings": _public_strings(self.warnings),
            "claim_scope": _public_text(self.claim_scope),
            "schema_version": _public_text(self.schema_version),
        }
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, repr=False)
class StageResult(_RedactedRepr, Mapping[str, Any]):
    """One observable pipeline stage with stable common fields."""

    name: str
    status: ResultStatus = "success"
    changed: bool = False
    accepted: bool = True
    backend: Optional[str] = None
    fallback_reason: Optional[str] = None
    warning: Optional[str] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = {
            "stage": _public_text(self.name),
            "status": _public_text(self.status),
            "changed": _public_bool(self.changed),
            "accepted": _public_bool(self.accepted),
            "backend": _public_optional_text(self.backend),
            "fallback_reason": _public_optional_text(self.fallback_reason),
            "warning": _public_optional_text(self.warning),
            "error": _public_optional_text(self.error),
            "latency_ms": _public_number(self.latency_ms),
            "details": _public_mapping(self.details),
        }
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        if key == "stage":
            return self.name
        if hasattr(self, key):
            return getattr(self, key)
        return self.details[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, repr=False)
class RemovalReport(_RedactedRepr, Mapping[str, Any]):
    """Stable summary intended for APIs, CLIs, and agent tool results."""

    mode: RemovalMode
    status: ResultStatus
    changed: bool
    char_count_before: int
    char_count_after: int
    chars_removed: int = 0
    sanitize_profile: SanitizeProfile = "safe"
    backend: Optional[str] = None
    fallback_reason: Optional[str] = None
    warnings: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    detection_status: DetectionStatus = "unsupported"
    transformation_status: TransformationStatus = "unchanged"
    verification_status: VerificationStatus = "not_verifiable"
    detector: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = {
            "mode": _public_text(self.mode),
            "status": _public_text(self.status),
            "changed": _public_bool(self.changed),
            "char_count_before": _public_integer(self.char_count_before),
            "char_count_after": _public_integer(self.char_count_after),
            "chars_removed": _public_integer(self.chars_removed),
            "sanitize_profile": _public_text(self.sanitize_profile),
            "backend": _public_optional_text(self.backend),
            "fallback_reason": _public_optional_text(self.fallback_reason),
            "warnings": _public_strings(self.warnings),
            "metadata": _public_mapping(self.metadata),
            "detection_status": _public_text(self.detection_status),
            "transformation_status": _public_text(self.transformation_status),
            "verification_status": _public_text(self.verification_status),
            "detector": _public_optional_text(self.detector),
            "schema_version": _public_text(self.schema_version),
        }
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.metadata[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True, repr=False)
class ExecutionPlan(_RedactedRepr):
    """Side-effect-free description of what a removal request would require."""

    mode: RemovalMode
    backend: str
    network_required: bool
    model_download_possible: bool
    available: bool
    reason: Optional[str] = None
    estimated_remote_calls: int = 0
    limits: Mapping[str, int] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": _public_text(self.mode),
            "backend": _public_text(self.backend),
            "network_required": _public_bool(self.network_required),
            "model_download_possible": _public_bool(self.model_download_possible),
            "available": _public_bool(self.available),
            "reason": _public_optional_text(self.reason),
            "estimated_remote_calls": _public_integer(self.estimated_remote_calls),
            "limits": _public_mapping(self.limits),
            "schema_version": _public_text(self.schema_version),
        }


@dataclass(frozen=True, repr=False)
class BatchItemResult(_RedactedRepr):
    """One ordered batch outcome; failures do not discard successful siblings."""

    index: int
    result: Any = None
    error: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    @property
    def succeeded(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "index": self.index,
            "succeeded": self.succeeded,
            "result": self.result.to_dict() if self.result is not None else None,
            "error": self.error,
        }
