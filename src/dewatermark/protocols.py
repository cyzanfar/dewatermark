"""Structural extension contracts; implementations need not inherit them."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .models import CapabilityManifest, DetectionEvidence
from .quality import QualityGateDecision, QualityReport
from .quality_gates import PairwiseAssessment


@runtime_checkable
class Scorer(Protocol):
    def available(self) -> bool: ...
    def self_information(self, text: str) -> list[dict[str, Any]]: ...
    def score(self, text: str) -> Mapping[str, Any]: ...


@runtime_checkable
class PlannableScorer(Scorer, Protocol):
    """A scorer with static privacy/model requirements."""

    @property
    def capability(self) -> CapabilityManifest: ...


@runtime_checkable
class Rewriter(Protocol):
    def available(self) -> bool: ...
    def rewrite(self, text: str, **options: Any) -> tuple[str, Mapping[str, Any]]: ...


@runtime_checkable
class PlannableRewriter(Rewriter, Protocol):
    """A rewriter with static requirements suitable for agent planning."""

    @property
    def capability(self) -> CapabilityManifest: ...


@runtime_checkable
class QualityGate(Protocol):
    @property
    def capability(self) -> CapabilityManifest: ...
    def evaluate(self, source: str, candidate: str) -> QualityGateDecision | QualityReport: ...


@runtime_checkable
class NLIAdapter(Protocol):
    """Adapter consumed by :class:`BidirectionalNLIGate`."""

    @property
    def capability(self) -> CapabilityManifest: ...
    def available(self) -> bool: ...
    def entailment_probability(self, premise: str, hypothesis: str) -> float: ...


@runtime_checkable
class PairwiseQualityAdapter(Protocol):
    """Adapter consumed by claim-QA, entity, citation, and task gates."""

    @property
    def capability(self) -> CapabilityManifest: ...
    def available(self) -> bool: ...
    def assess(self, source: str, candidate: str) -> PairwiseAssessment: ...


@runtime_checkable
class SemanticScorer(Protocol):
    @property
    def capability(self) -> CapabilityManifest: ...
    def __call__(self, source: str, candidate: str) -> float: ...


@runtime_checkable
class Detector(Protocol):
    """A named detector with enough metadata to scope its evidence."""

    @property
    def capability(self) -> CapabilityManifest: ...
    def available(self) -> bool: ...
    def detect(self, text: str) -> DetectionEvidence | Mapping[str, Any] | float: ...


@runtime_checkable
class Transformer(Protocol):
    """Candidate producer. The orchestrator, not the transformer, accepts output."""

    @property
    def capability(self) -> CapabilityManifest: ...
    def available(self) -> bool: ...
    def transform(self, text: str, **options: Any) -> tuple[str, Mapping[str, Any]]: ...


@runtime_checkable
class Chunker(Protocol):
    @property
    def capability(self) -> CapabilityManifest: ...
    def split(self, text: str, max_chars: int) -> Sequence[str]: ...
