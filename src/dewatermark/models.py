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
