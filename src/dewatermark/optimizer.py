"""Detector-guided, quality-constrained watermark mitigation.

The optimizer treats every strategy output as untrusted. Only this module may
accept a candidate, and it does so only after the central quality pipeline, the
primary detector, and at least one distinct held-out verifier all agree. Failed
searches always return the original text.
"""

from __future__ import annotations

import hashlib
import inspect
import math
from dataclasses import dataclass, field, replace
from difflib import SequenceMatcher
from typing import Any, Literal, Mapping, Optional, Protocol, Sequence, cast, runtime_checkable

from .config import DewatermarkConfig, resolve
from .detector_session import (
    DetectorObservation,
    DetectorPolicyDriftError,
    DetectorQueryBudgetExceeded,
    DetectorSession,
    SessionVerification,
    SignalSpan,
)
from .extension_safety import require_extension
from .localization import LocalizedSignal
from .models import CapabilityManifest, _public_identifier
from .quality import QualityReport, evaluate_candidate
from .request_context import (
    RequestContext,
    ResourceBudgetExceeded,
    begin_extension_usage,
    checkpoint,
    current_request_context,
    extension_usage_error,
    public_quality_report,
    request_scope,
)

MitigationStatus = Literal["verified", "abstained", "rolled_back"]
MitigationReason = Literal[
    "verified_clearance",
    "source_not_detected",
    "primary_detector_unavailable",
    "held_out_verifier_required",
    "no_candidates",
    "quality_rejected",
    "residual_signal",
    "verification_inconclusive",
    "held_out_residual",
    "detector_budget_exhausted",
    "resource_budget_exhausted",
]
_MITIGATION_REASONS = frozenset(
    {
        "verified_clearance",
        "source_not_detected",
        "primary_detector_unavailable",
        "held_out_verifier_required",
        "no_candidates",
        "quality_rejected",
        "residual_signal",
        "verification_inconclusive",
        "held_out_residual",
        "detector_budget_exhausted",
        "resource_budget_exhausted",
    }
)
_MITIGATION_CLAIM_SCOPE = (
    "Clearance is limited to the named detector configurations; no authorship or "
    "universal watermark inference is made."
)
_REASONS_BY_STATUS = {
    "verified": frozenset({"verified_clearance"}),
    "abstained": frozenset(
        {
            "source_not_detected",
            "primary_detector_unavailable",
            "held_out_verifier_required",
            "detector_budget_exhausted",
            "resource_budget_exhausted",
        }
    ),
    "rolled_back": frozenset(
        {
            "no_candidates",
            "quality_rejected",
            "residual_signal",
            "verification_inconclusive",
            "held_out_residual",
            "detector_budget_exhausted",
            "resource_budget_exhausted",
        }
    ),
}
TraceKind = Literal[
    "source_scored",
    "strategy_rejected",
    "candidate_rejected",
    "candidate_scored",
    "candidate_verified",
]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _finite(value: Optional[float]) -> Optional[float]:
    return value if value is not None and math.isfinite(value) else None


def _is_sha256(value: Any) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _same_observation_binding(left: DetectorObservation, right: DetectorObservation) -> bool:
    """Compare immutable evidence identity while ignoring the cache marker."""
    return (
        left.detector == right.detector
        and left.role == right.role
        and left.text_sha256 == right.text_sha256
        and left.policy_sha256 == right.policy_sha256
        and left.evidence is right.evidence
    )


@dataclass(frozen=True, repr=False)
class DetectorFeedback:
    """Content-free detector state supplied to an adaptive strategy."""

    detector: str
    status: str
    score: Optional[float]
    threshold: Optional[float]
    p_value: Optional[float]
    detection_margin: Optional[float]
    localization: tuple[SignalSpan, ...] = ()

    @classmethod
    def from_observation(cls, observation: DetectorObservation) -> "DetectorFeedback":
        evidence = observation.evidence
        return cls(
            detector=observation.detector,
            status=evidence.status,
            score=_finite(evidence.score),
            threshold=_finite(evidence.threshold),
            p_value=_finite(observation.p_value),
            detection_margin=_finite(observation.detection_margin),
            localization=observation.localization,
        )

    def __repr__(self) -> str:
        return "<dewatermark detector feedback; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "detector": self.detector,
            "status": self.status,
            "score": self.score,
            "threshold": self.threshold,
            "p_value": self.p_value,
            "detection_margin": self.detection_margin,
            "localization": [span.to_dict() for span in self.localization],
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, repr=False)
class StrategyContext:
    """Deterministic, content-free context for one strategy invocation."""

    round_index: int
    invocation_index: int
    random_seed: int
    candidate_limit: int
    feedback: DetectorFeedback
    source_localization: tuple[SignalSpan, ...] = ()

    def __repr__(self) -> str:
        return "<dewatermark strategy context; content redacted>"


@dataclass(frozen=True, repr=False)
class CandidateProposal:
    """One untrusted candidate returned by a strategy."""

    text: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.text) is not str:
            raise TypeError("candidate proposal text must be a string")

    def __repr__(self) -> str:
        return "<dewatermark candidate proposal; text redacted>"


@runtime_checkable
class CandidateStrategy(Protocol):
    """Manifest-backed strategy that may return several untrusted candidates."""

    capability: CapabilityManifest

    def available(self) -> bool: ...

    def generate(
        self, text: str, *, context: StrategyContext, **options: Any
    ) -> Sequence[str | CandidateProposal]: ...


@dataclass(frozen=True, repr=False)
class StrategyBinding:
    """Bind a strategy to private runtime options that never enter receipts."""

    strategy: Any = field(repr=False, compare=False)
    options: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.strategy is None:
            raise ValueError("strategy binding requires a strategy")
        if type(self.options) is not dict or any(type(key) is not str for key in self.options):
            raise TypeError("strategy options must be a dictionary with string keys")
        if "context" in self.options:
            raise ValueError("strategy options cannot override context")

    def __repr__(self) -> str:
        return "<dewatermark strategy binding; extension and options redacted>"


@dataclass(frozen=True)
class SearchLimits:
    """Hard bounds for one deterministic search."""

    max_rounds: int = 2
    beam_width: int = 4
    max_candidates: int = 32
    max_transform_calls: int = 32
    max_detector_queries: int = 64
    max_candidate_characters: int = 1_000_000
    max_verification_candidates: int = 8

    def __post_init__(self) -> None:
        bounds = {
            "max_rounds": (self.max_rounds, 1, 32),
            "beam_width": (self.beam_width, 1, 32),
            "max_candidates": (self.max_candidates, 1, 1000),
            "max_transform_calls": (self.max_transform_calls, 1, 1000),
            "max_detector_queries": (self.max_detector_queries, 1, 100_000),
            "max_candidate_characters": (self.max_candidate_characters, 1, 10_000_000),
            "max_verification_candidates": (self.max_verification_candidates, 1, 128),
        }
        for name, (value, lower, upper) in bounds.items():
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"{name} must be between {lower} and {upper}")


@dataclass(frozen=True, repr=False)
class SearchTraceEvent:
    """One content-free search decision."""

    index: int
    kind: TraceKind
    status: str
    text_sha256: Optional[str] = None
    parent_sha256: Optional[str] = None
    strategy: Optional[str] = None
    reason_code: Optional[str] = None
    edit_characters: Optional[int] = None
    quality_passed: Optional[bool] = None
    detector_status: Optional[str] = None
    detection_margin: Optional[float] = None

    def __repr__(self) -> str:
        return "<dewatermark search trace event; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values = {
            "index": self.index,
            "kind": self.kind,
            "status": self.status,
            "text_sha256": self.text_sha256,
            "parent_sha256": self.parent_sha256,
            "strategy": self.strategy,
            "reason_code": self.reason_code,
            "edit_characters": self.edit_characters,
            "quality_passed": self.quality_passed,
            "detector_status": self.detector_status,
            "detection_margin": self.detection_margin,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, repr=False)
class MitigationReceipt:
    """Content-free record of a constrained search and its rollback decision."""

    status: MitigationStatus
    reason_code: MitigationReason
    input_sha256: str
    output_sha256: str
    changed: bool
    edit_characters: int
    edit_fraction: float
    selected_strategy: Optional[str]
    primary_before: Optional[DetectorObservation]
    primary_after: Optional[DetectorObservation]
    verification: Optional[SessionVerification]
    quality: Mapping[str, Any]
    trace: tuple[SearchTraceEvent, ...]
    resources: Mapping[str, Any]
    claim_scope: str = _MITIGATION_CLAIM_SCOPE
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if (
            self.status not in {"verified", "abstained", "rolled_back"}
            or self.reason_code not in _MITIGATION_REASONS
            or self.reason_code not in _REASONS_BY_STATUS.get(self.status, ())
            or self.schema_version != "1.0"
            or self.claim_scope != _MITIGATION_CLAIM_SCOPE
            or not _is_sha256(self.input_sha256)
            or not _is_sha256(self.output_sha256)
            or type(self.changed) is not bool
            or type(self.edit_characters) is not int
            or self.edit_characters < 0
            or type(self.edit_fraction) is not float
            or not math.isfinite(self.edit_fraction)
            or self.edit_fraction < 0.0
            or type(self.trace) is not tuple
            or any(type(event) is not SearchTraceEvent for event in self.trace)
            or type(self.quality) is not dict
            or type(self.resources) is not dict
            or (
                self.primary_before is not None
                and type(self.primary_before) is not DetectorObservation
            )
            or (
                self.primary_after is not None
                and type(self.primary_after) is not DetectorObservation
            )
            or (
                self.verification is not None and type(self.verification) is not SessionVerification
            )
        ):
            raise ValueError("mitigation receipt is not internally consistent")
        if self.status != "verified":
            if (
                self.changed
                or self.input_sha256 != self.output_sha256
                or self.edit_characters != 0
                or self.edit_fraction != 0.0
                or self.selected_strategy is not None
                or (self.verification is not None and self.verification.verified)
            ):
                raise ValueError("unverified mitigation receipt must describe exact rollback")
            return
        if (
            self.reason_code != "verified_clearance"
            or not self.changed
            or type(self.selected_strategy) is not str
            or not self.selected_strategy
            or _public_identifier(self.selected_strategy) != self.selected_strategy
            or self.edit_characters < 1
            or self.edit_fraction <= 0.0
            or self.input_sha256 == self.output_sha256
            or type(self.primary_before) is not DetectorObservation
            or type(self.primary_after) is not DetectorObservation
            or type(self.verification) is not SessionVerification
            or not self.verification.verified
            or self.quality.get("passed") is not True
            or self.input_sha256 != self.primary_before.text_sha256
            or self.output_sha256 != self.primary_after.text_sha256
            or self.verification.primary_before is None
            or self.verification.primary_after is None
            or not _same_observation_binding(self.primary_before, self.verification.primary_before)
            or not _same_observation_binding(self.primary_after, self.verification.primary_after)
        ):
            raise ValueError("verified mitigation receipt requires bound clearance evidence")

    def __repr__(self) -> str:
        return "<dewatermark mitigation receipt; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "schema_version": self.schema_version,
            "status": self.status,
            "reason_code": self.reason_code,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "changed": self.changed,
            "edit_characters": self.edit_characters,
            "edit_fraction": self.edit_fraction,
            "selected_strategy": self.selected_strategy,
            "primary_before": (
                self.primary_before.to_dict() if self.primary_before is not None else None
            ),
            "primary_after": (
                self.primary_after.to_dict() if self.primary_after is not None else None
            ),
            "verification": self.verification.to_dict() if self.verification is not None else None,
            "quality": dict(self.quality),
            "trace": [event.to_dict() for event in self.trace],
            "resources": dict(self.resources),
            "claim_scope": self.claim_scope,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, repr=False)
class MitigationResult:
    """Verified candidate or the unchanged source after abstention/rollback."""

    cleaned_text: str = field(repr=False)
    status: MitigationStatus
    reason_code: MitigationReason
    changed: bool
    receipt: MitigationReceipt

    def __post_init__(self) -> None:
        if (
            self.status != self.receipt.status
            or self.reason_code != self.receipt.reason_code
            or self.changed != self.receipt.changed
            or _digest(self.cleaned_text) != self.receipt.output_sha256
        ):
            raise ValueError("mitigation result and receipt are inconsistent")
        if self.status == "verified":
            if (
                not self.changed
                or self.reason_code != "verified_clearance"
                or self.receipt.selected_strategy is None
                or self.receipt.verification is None
                or not self.receipt.verification.verified
            ):
                raise ValueError("verified mitigation requires complete verification evidence")
        elif self.changed or self.receipt.selected_strategy is not None:
            raise ValueError("unverified mitigation cannot expose a changed candidate")

    def __repr__(self) -> str:
        return "<dewatermark mitigation result; text redacted>"

    def to_dict(self) -> dict[str, Any]:
        """Return the complete public v1 result required by its JSON schema."""
        return {
            "schema_version": "1.0",
            "status": self.status,
            "reason_code": self.reason_code,
            "changed": self.changed,
            "cleaned_text": self.cleaned_text,
            "receipt": self.receipt.to_dict(),
        }


@dataclass(repr=False)
class _SearchNode:
    text: str = field(repr=False)
    observation: DetectorObservation
    quality: Optional[QualityReport]
    edit_characters: int
    strategy: Optional[str]


class _Trace:
    def __init__(self) -> None:
        self.events: list[SearchTraceEvent] = []

    def add(self, kind: TraceKind, status: str, **values: Any) -> None:
        self.events.append(
            SearchTraceEvent(index=len(self.events) + 1, kind=kind, status=status, **values)
        )


def _edit_characters(source: str, candidate: str) -> int:
    """Deterministic changed-character count used for minimum-edit ordering."""
    if source == candidate:
        return 0
    # SequenceMatcher is quadratic on adversarial repetitive strings. Preserve
    # its useful fine-grained metric for ordinary passages and use one bounded,
    # conservative changed-span metric for large candidate pairs.
    if len(source) * len(candidate) > 4_000_000:
        prefix = 0
        shared = min(len(source), len(candidate))
        while prefix < shared and source[prefix] == candidate[prefix]:
            prefix += 1
        suffix = 0
        while (
            suffix < shared - prefix
            and source[len(source) - suffix - 1] == candidate[len(candidate) - suffix - 1]
        ):
            suffix += 1
        return max(len(source) - prefix - suffix, len(candidate) - prefix - suffix)
    matcher = SequenceMatcher(a=source, b=candidate, autojunk=False)
    total = 0
    for tag, left_start, left_end, right_start, right_end in matcher.get_opcodes():
        if tag != "equal":
            total += max(left_end - left_start, right_end - right_start)
    return total


def _node_rank(node: _SearchNode) -> tuple[int, float, int, str]:
    status = node.observation.evidence.status
    status_rank = 0 if status == "not_detected" else (1 if status == "detected" else 2)
    margin = node.observation.detection_margin
    return (
        status_rank,
        margin if margin is not None else math.inf,
        node.edit_characters,
        node.observation.text_sha256,
    )


def _bindings(strategies: Sequence[Any | StrategyBinding]) -> tuple[StrategyBinding, ...]:
    if type(strategies) not in (list, tuple):
        raise TypeError("strategies must be a list or tuple")
    if not strategies:
        raise ValueError("at least one strategy is required")
    return tuple(
        item if type(item) is StrategyBinding else StrategyBinding(strategy=item)
        for item in strategies
    )


def _invoke_strategy(
    binding: StrategyBinding,
    text: str,
    context: StrategyContext,
    config: DewatermarkConfig,
) -> tuple[str, tuple[Any, ...], Optional[str]]:
    """Run one reviewed strategy and discard all free-form diagnostics."""
    try:
        capability = require_extension(binding.strategy, "transformer", config)
    except PermissionError:
        return "unavailable-strategy", (), "strategy_consent_required"
    except Exception:
        return "unavailable-strategy", (), "invalid_strategy_manifest"
    identifier = capability.identifier
    if len(text) < capability.minimum_characters:
        return identifier, (), "strategy_minimum_length"
    try:
        usage_before, accounting = begin_extension_usage(capability)
        checkpoint()
    except ResourceBudgetExceeded:
        raise
    try:
        if inspect.getattr_static(binding.strategy, "available", None) is not None:
            available = binding.strategy.available()
            if type(available) is not bool:
                raise TypeError("strategy availability must be boolean")
            if not available:
                usage_error = extension_usage_error(
                    usage_before,
                    network_required=capability.network_required,
                    resource_accounting=accounting,
                )
                return identifier, (), usage_error or "strategy_unavailable"

        options = dict(binding.options)
        if inspect.getattr_static(binding.strategy, "generate", None) is not None:
            raw = binding.strategy.generate(text, context=context, **options)
            if type(raw) not in (list, tuple):
                raise TypeError("strategy generate result must be a list or tuple")
            candidates = tuple(raw[: context.candidate_limit])
        elif inspect.getattr_static(binding.strategy, "transform", None) is not None:
            raw = binding.strategy.transform(text, **options)
            if type(raw) is not tuple or len(raw) != 2 or type(raw[1]) is not dict:
                raise TypeError("legacy transformer returned an invalid result")
            candidates = (raw[0],)
        else:
            raise TypeError("strategy must implement generate or transform")
        checkpoint()
    except ResourceBudgetExceeded:
        raise
    except Exception:
        usage_error = extension_usage_error(
            usage_before,
            network_required=capability.network_required,
            resource_accounting=accounting,
        )
        return identifier, (), usage_error or "strategy_error"
    usage_error = extension_usage_error(
        usage_before,
        network_required=capability.network_required,
        resource_accounting=accounting,
    )
    if usage_error is not None:
        return identifier, (), usage_error
    return identifier, candidates, None


def _quality(source: str, candidate: str, config: DewatermarkConfig) -> Optional[QualityReport]:
    try:
        return evaluate_candidate(source, candidate, config)
    except ResourceBudgetExceeded:
        raise
    except Exception:
        return None


def _reason_for_source(observation: DetectorObservation) -> MitigationReason:
    if observation.evidence.status == "not_detected":
        return "source_not_detected"
    return "primary_detector_unavailable"


def _make_result(
    *,
    source: str,
    output: str,
    status: MitigationStatus,
    reason: MitigationReason,
    trace: _Trace,
    session: DetectorSession,
    request_context: RequestContext,
    limits: SearchLimits,
    primary_before: Optional[DetectorObservation],
    primary_after: Optional[DetectorObservation] = None,
    verification: Optional[SessionVerification] = None,
    quality: Optional[QualityReport] = None,
    selected_strategy: Optional[str] = None,
    edit_characters: int = 0,
) -> MitigationResult:
    changed = status == "verified" and output != source
    if not changed:
        output = source
        edit_characters = 0
        selected_strategy = None
        quality_public: Mapping[str, Any] = {}
    else:
        quality_public = public_quality_report(quality) if quality is not None else {}
    resources: dict[str, Any] = session.ledger()
    resources["request"] = request_context.ledger()
    resources["search_limits"] = {
        "max_rounds": limits.max_rounds,
        "beam_width": limits.beam_width,
        "max_candidates": limits.max_candidates,
        "max_transform_calls": limits.max_transform_calls,
        "max_detector_queries": limits.max_detector_queries,
        "max_candidate_characters": limits.max_candidate_characters,
        "max_verification_candidates": limits.max_verification_candidates,
    }
    receipt = MitigationReceipt(
        status=status,
        reason_code=reason,
        input_sha256=_digest(source),
        output_sha256=_digest(output),
        changed=changed,
        edit_characters=edit_characters,
        edit_fraction=round(edit_characters / max(1, len(source)), 8),
        selected_strategy=selected_strategy,
        primary_before=primary_before,
        primary_after=primary_after,
        verification=verification,
        quality=quality_public,
        trace=tuple(trace.events),
        resources=resources,
    )
    return MitigationResult(
        cleaned_text=output,
        status=status,
        reason_code=reason,
        changed=changed,
        receipt=receipt,
    )


def _execute_mitigation(
    source: str,
    *,
    strategies: tuple[StrategyBinding, ...],
    session: DetectorSession,
    config: DewatermarkConfig,
    limits: SearchLimits,
    request_context: RequestContext,
    source_localization: tuple[SignalSpan, ...],
) -> MitigationResult:
    trace = _Trace()
    try:
        source_observation = session.score(source)
    except DetectorQueryBudgetExceeded:
        return _make_result(
            source=source,
            output=source,
            status="abstained",
            reason="detector_budget_exhausted",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=None,
        )
    except DetectorPolicyDriftError:
        return _make_result(
            source=source,
            output=source,
            status="abstained",
            reason="primary_detector_unavailable",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=None,
        )
    except ResourceBudgetExceeded:
        return _make_result(
            source=source,
            output=source,
            status="abstained",
            reason="resource_budget_exhausted",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=None,
        )
    trace.add(
        "source_scored",
        source_observation.evidence.status,
        text_sha256=source_observation.text_sha256,
        detector_status=source_observation.evidence.status,
        detection_margin=source_observation.detection_margin,
    )
    if source_observation.evidence.status != "detected":
        return _make_result(
            source=source,
            output=source,
            status="abstained",
            reason=_reason_for_source(source_observation),
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=source_observation,
        )
    if session.verifier_count < 1:
        return _make_result(
            source=source,
            output=source,
            status="abstained",
            reason="held_out_verifier_required",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=source_observation,
        )

    effective_source_localization = source_localization or source_observation.localization

    source_node = _SearchNode(
        text=source,
        observation=source_observation,
        quality=None,
        edit_characters=0,
        strategy=None,
    )
    frontier = [source_node]
    cleared: list[_SearchNode] = []
    seen = {_digest(source)}
    candidates_seen = 0
    transform_calls = 0
    quality_rejections = 0
    detector_failures = 0

    try:
        for round_index in range(limits.max_rounds):
            next_frontier: list[_SearchNode] = []
            for parent in sorted(frontier, key=_node_rank):
                for binding in strategies:
                    if (
                        candidates_seen >= limits.max_candidates
                        or transform_calls >= limits.max_transform_calls
                    ):
                        break
                    transform_calls += 1
                    remaining = limits.max_candidates - candidates_seen
                    strategy_context = StrategyContext(
                        round_index=round_index,
                        invocation_index=transform_calls,
                        random_seed=config.random_seed + transform_calls - 1,
                        candidate_limit=remaining,
                        feedback=DetectorFeedback.from_observation(parent.observation),
                        source_localization=effective_source_localization,
                    )
                    strategy_name, proposals, strategy_error = _invoke_strategy(
                        binding, parent.text, strategy_context, config
                    )
                    if strategy_error is not None:
                        trace.add(
                            "strategy_rejected",
                            "rejected",
                            parent_sha256=parent.observation.text_sha256,
                            strategy=strategy_name,
                            reason_code=strategy_error,
                        )
                        continue
                    for raw_proposal in proposals:
                        if candidates_seen >= limits.max_candidates:
                            break
                        candidates_seen += 1
                        if type(raw_proposal) is CandidateProposal:
                            candidate = raw_proposal.text
                        elif type(raw_proposal) is str:
                            candidate = raw_proposal
                        else:
                            trace.add(
                                "candidate_rejected",
                                "rejected",
                                parent_sha256=parent.observation.text_sha256,
                                strategy=strategy_name,
                                reason_code="invalid_candidate_type",
                            )
                            continue
                        if type(candidate) is not str:
                            trace.add(
                                "candidate_rejected",
                                "rejected",
                                parent_sha256=parent.observation.text_sha256,
                                strategy=strategy_name,
                                reason_code="invalid_candidate_type",
                            )
                            continue
                        if not candidate or len(candidate) > limits.max_candidate_characters:
                            trace.add(
                                "candidate_rejected",
                                "rejected",
                                parent_sha256=parent.observation.text_sha256,
                                strategy=strategy_name,
                                reason_code="candidate_size_rejected",
                            )
                            continue
                        candidate_sha = _digest(candidate)
                        if candidate_sha in seen:
                            trace.add(
                                "candidate_rejected",
                                "rejected",
                                text_sha256=candidate_sha,
                                parent_sha256=parent.observation.text_sha256,
                                strategy=strategy_name,
                                reason_code="duplicate_candidate",
                            )
                            continue
                        seen.add(candidate_sha)
                        edits = _edit_characters(source, candidate)
                        quality = _quality(source, candidate, config)
                        if quality is None or not quality.passed:
                            quality_rejections += 1
                            trace.add(
                                "candidate_rejected",
                                "rejected",
                                text_sha256=candidate_sha,
                                parent_sha256=parent.observation.text_sha256,
                                strategy=strategy_name,
                                reason_code=(
                                    "quality_error" if quality is None else "quality_rejected"
                                ),
                                edit_characters=edits,
                                quality_passed=False,
                            )
                            continue
                        observation = session.score(candidate)
                        trace.add(
                            "candidate_scored",
                            observation.evidence.status,
                            text_sha256=candidate_sha,
                            parent_sha256=parent.observation.text_sha256,
                            strategy=strategy_name,
                            edit_characters=edits,
                            quality_passed=True,
                            detector_status=observation.evidence.status,
                            detection_margin=observation.detection_margin,
                        )
                        node = _SearchNode(
                            text=candidate,
                            observation=observation,
                            quality=quality,
                            edit_characters=edits,
                            strategy=strategy_name,
                        )
                        if observation.evidence.status == "not_detected":
                            cleared.append(node)
                        elif observation.evidence.status == "detected":
                            next_frontier.append(node)
                        else:
                            detector_failures += 1
                if (
                    candidates_seen >= limits.max_candidates
                    or transform_calls >= limits.max_transform_calls
                ):
                    break
            # Keep the source eligible for a later deterministic attempt/seed,
            # while detected candidates carry localized incremental progress.
            next_frontier.append(source_node)
            unique_frontier = {
                node.observation.text_sha256: node for node in next_frontier
            }.values()
            frontier = sorted(unique_frontier, key=_node_rank)[: limits.beam_width]
    except DetectorQueryBudgetExceeded:
        return _make_result(
            source=source,
            output=source,
            status="rolled_back",
            reason="detector_budget_exhausted",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=source_observation,
        )
    except DetectorPolicyDriftError:
        return _make_result(
            source=source,
            output=source,
            status="rolled_back",
            reason="verification_inconclusive",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=source_observation,
        )
    except ResourceBudgetExceeded:
        return _make_result(
            source=source,
            output=source,
            status="rolled_back",
            reason="resource_budget_exhausted",
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=source_observation,
        )

    if not cleared:
        reason: MitigationReason
        if quality_rejections and quality_rejections == len(seen) - 1:
            reason = "quality_rejected"
        elif candidates_seen == 0 or (len(seen) == 1 and not detector_failures):
            reason = "no_candidates"
        else:
            reason = "residual_signal"
        return _make_result(
            source=source,
            output=source,
            status="rolled_back",
            reason=reason,
            trace=trace,
            session=session,
            request_context=request_context,
            limits=limits,
            primary_before=source_observation,
        )

    ordered = sorted(cleared, key=lambda node: (node.edit_characters, _node_rank(node)))
    last_verification: Optional[SessionVerification] = None
    try:
        for node in ordered[: limits.max_verification_candidates]:
            verification = session.verify(source, node.text)
            last_verification = verification
            trace.add(
                "candidate_verified",
                verification.status,
                text_sha256=node.observation.text_sha256,
                strategy=node.strategy,
                edit_characters=node.edit_characters,
                quality_passed=True,
                detector_status=node.observation.evidence.status,
                detection_margin=node.observation.detection_margin,
                reason_code=verification.reason_code,
            )
            if verification.verified:
                # Verification can finish just as the shared request expires or
                # is cancelled. Recheck immediately before committing changed
                # text so no stale successful result crosses the final boundary.
                checkpoint()
                return _make_result(
                    source=source,
                    output=node.text,
                    status="verified",
                    reason="verified_clearance",
                    trace=trace,
                    session=session,
                    request_context=request_context,
                    limits=limits,
                    primary_before=source_observation,
                    primary_after=node.observation,
                    verification=verification,
                    quality=node.quality,
                    selected_strategy=node.strategy,
                    edit_characters=node.edit_characters,
                )
    except DetectorQueryBudgetExceeded:
        reason = "detector_budget_exhausted"
    except ResourceBudgetExceeded:
        reason = "resource_budget_exhausted"
    except DetectorPolicyDriftError:
        reason = "verification_inconclusive"
    else:
        reason = (
            "held_out_residual"
            if last_verification is not None and last_verification.status == "residual"
            else "verification_inconclusive"
        )
    return _make_result(
        source=source,
        output=source,
        status="rolled_back",
        reason=cast(MitigationReason, reason),
        trace=trace,
        session=session,
        request_context=request_context,
        limits=limits,
        primary_before=source_observation,
        verification=(
            last_verification
            if last_verification is None or not last_verification.verified
            else None
        ),
    )


def mitigate(
    text: str,
    primary_detector: str | Any,
    strategies: Sequence[Any | StrategyBinding],
    *,
    verifier_detectors: Sequence[str | Any] = (),
    config: Optional[DewatermarkConfig] = None,
    limits: Optional[SearchLimits] = None,
    source_localization: Sequence[SignalSpan | LocalizedSignal] = (),
) -> MitigationResult:
    """Find the smallest quality-safe candidate cleared by held-out detectors.

    Strategy order, candidate order, beam ranking, and tie-breaking are stable.
    This function never returns a changed candidate unless verification succeeds;
    every other outcome contains the exact original input.
    """
    if type(text) is not str or not text:
        raise ValueError("text must be a non-empty string")
    if type(source_localization) not in (list, tuple):
        raise TypeError("source_localization must be a list or tuple")
    normalized_items: list[SignalSpan] = []
    for span in source_localization:
        if type(span) is SignalSpan:
            normalized_items.append(span)
        elif type(span) is LocalizedSignal:
            normalized_items.append(
                SignalSpan(
                    span.start,
                    span.end,
                    p_value=span.smallest_p_value,
                )
            )
        else:
            raise ValueError("source_localization contains an invalid span")
    normalized_localization = tuple(normalized_items)
    if any(
        type(span) is not SignalSpan
        or span.start < 0
        or span.end <= span.start
        or span.end > len(text)
        for span in normalized_localization
    ):
        raise ValueError("source_localization contains an invalid span")
    cfg = resolve(config)
    search_limits = limits or SearchLimits(
        max_candidates=cfg.max_search_candidates,
        max_detector_queries=cfg.max_detector_queries,
        max_candidate_characters=cfg.max_input_chars,
    )
    search_limits = replace(
        search_limits,
        max_candidates=min(search_limits.max_candidates, cfg.max_search_candidates),
        max_detector_queries=min(search_limits.max_detector_queries, cfg.max_detector_queries),
        max_candidate_characters=min(search_limits.max_candidate_characters, cfg.max_input_chars),
    )
    if len(text) > min(cfg.max_input_chars, search_limits.max_candidate_characters):
        raise ValueError("text exceeds the configured input limit")
    strategy_bindings = _bindings(strategies)
    if len(strategy_bindings) > cfg.max_batch_items:
        raise ValueError("strategies exceeds max_batch_items")
    session = DetectorSession(
        primary_detector,
        verifier_detectors=verifier_detectors,
        config=cfg,
        max_queries=search_limits.max_detector_queries,
    )

    active = current_request_context()
    if active is not None:
        return _execute_mitigation(
            text,
            strategies=strategy_bindings,
            session=session,
            config=cfg,
            limits=search_limits,
            request_context=active,
            source_localization=normalized_localization,
        )
    context = RequestContext.from_config(cfg)
    with request_scope(context):
        return _execute_mitigation(
            text,
            strategies=strategy_bindings,
            session=session,
            config=cfg,
            limits=search_limits,
            request_context=context,
            source_localization=normalized_localization,
        )
