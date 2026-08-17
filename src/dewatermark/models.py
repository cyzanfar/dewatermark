"""Versioned, JSON-serializable public result models."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
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


def _private_metadata_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _PRIVATE_METADATA_KEYS or normalized.endswith(
        ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
    )


def _public_metadata(value: Any, *, key: str = "") -> Any:
    if _private_metadata_key(key):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {
            str(item_key): _public_metadata(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_public_metadata(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


@dataclass(frozen=True)
class CapabilityManifest(Mapping[str, Any]):
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

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["schemes"] = list(self.schemes)
        value["metadata"] = _public_metadata(self.metadata)
        return value

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True)
class DetectionEvidence(Mapping[str, Any]):
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
        return {key: item for key, item in asdict(self).items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.details[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True)
class VerificationEvidence(Mapping[str, Any]):
    """Before/after detector evidence and its deliberately narrow conclusion."""

    status: VerificationStatus
    detector: Optional[str] = None
    before: Optional[DetectionEvidence] = None
    after: Optional[DetectionEvidence] = None
    reason: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True)
class EvidenceReceipt(Mapping[str, Any]):
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
        value = asdict(self)
        value["warnings"] = list(self.warnings)
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True)
class StageResult(Mapping[str, Any]):
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
        value = asdict(self)
        value["stage"] = value.pop("name")
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


@dataclass(frozen=True)
class RemovalReport(Mapping[str, Any]):
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
        value = asdict(self)
        value["warnings"] = list(self.warnings)
        return {key: item for key, item in value.items() if item is not None}

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.metadata[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


@dataclass(frozen=True)
class ExecutionPlan:
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
        return asdict(self)


@dataclass(frozen=True)
class BatchItemResult:
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
