"""Cheap, deterministic quality gates for generated rewrites.

These checks are deliberately conservative and dependency-free.  They do not
claim to prove semantic equivalence; they catch the common catastrophic cases
(truncation, dropped numbers/URLs/quoted strings, placeholders, and repetition)
before a candidate can replace the source.  Applications may provide a stronger
semantic scorer on top of this report.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Literal, Optional, cast

from .extension_safety import (
    implementation_sha256,
    manifest_sha256,
    require_extension,
    static_capability,
)
from .request_context import (
    ExtensionUsageRejected,
    begin_extension_usage,
    checkpoint,
    extension_usage_error,
)

_NUMBER = re.compile(r"(?<!\w)[+-]?\d+(?:,\d{3})*(?:\.\d+)?%?(?!\w)")
_URL = re.compile(r"(?:https?://|www\.)[^\s<>]+", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_QUOTED = re.compile(r"(?:\"[^\"\n]{2,}\"|'[^'\n]{2,}')")
_PLACEHOLDER = re.compile(r"\[(?:BLANK|MASK)(?:_\d+)?\]|<mask>", re.I)
_DATE = re.compile(
    r"\b(?:"
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|"
    r"Dec(?:ember)?)\s+\d{1,2}(?:,\s*\d{4})?|"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}"
    r")\b",
    re.I,
)
_UNIT = re.compile(
    r"(?<!\w)[+-]?\d+(?:,\d{3})*(?:\.\d+)?\s*"
    r"(?:%|kg|g|mg|lb|lbs|oz|km|m|cm|mm|mi|ft|in|s|ms|h|hr|hrs|"
    r"°[CF]|K|USD|EUR|GBP|MB|GB|TB|kW|MW)(?!\w)",
    re.I,
)
_ENTITY = re.compile(r"\b(?:[A-Z][\w'-]+(?:\s+[A-Z][\w'-]+)+|[A-Z]{2,})\b")
_NEGATION = re.compile(
    r"\b(?:not|never|no|none|neither|nor|without|cannot|can't|won't|isn't|aren't|"
    r"wasn't|weren't|doesn't|don't|didn't|hasn't|haven't|hadn't)\b",
    re.I,
)
_MODAL = re.compile(r"\b(?:must|shall|should|may|might|can|could|will|would|required)\b", re.I)
_INLINE_CODE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_FENCE = re.compile(r"^\s*```([^\n`]*)$", re.M)
_FENCED_BLOCK = re.compile(r"^\s*```[^\n`]*\n.*?^\s*```\s*$", re.M | re.S)
_HEADING = re.compile(r"^(#{1,6})\s+", re.M)
_LIST_MARKER = re.compile(r"^(\s*)(?:([-+*])|(\d+)[.)])\s+", re.M)
_TABLE_SEPARATOR = re.compile(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$", re.M)
_MARKDOWN_LINK = re.compile(r"\[[^\]\n]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")
_HTML_TAG = re.compile(r"<\s*(/?)\s*([A-Za-z][\w:-]*)\b[^>]*>")
_CITATION = re.compile(
    r"(?:"
    r"\bdoi:\s*10\.\d{4,9}/[-._;()/:A-Z0-9]+|"
    r"https?://doi\.org/10\.\d{4,9}/[-._;()/:A-Z0-9]+|"
    r"\barXiv:\s*\d{4}\.\d{4,5}(?:v\d+)?|"
    r"(?<!\w)\[(?:\d{1,4}(?:\s*[-,]\s*\d{1,4})*)\]|"
    r"(?<!\w)\[\^[^\]\n]+\]"
    r")",
    re.I,
)

QualityGateStatus = Literal["passed", "failed", "abstained", "error"]
QualityGateType = Literal[
    "semantic_similarity",
    "bidirectional_nli",
    "atomic_claim_qa",
    "entity_linking",
    "citation_grounding",
    "task_contract",
    "external",
]
ScoreDirection = Literal["higher", "lower"]

_GATE_TYPES = frozenset(
    {
        "semantic_similarity",
        "bidirectional_nli",
        "atomic_claim_qa",
        "entity_linking",
        "citation_grounding",
        "task_contract",
        "external",
    }
)
_GATE_STATUSES = frozenset({"passed", "failed", "abstained", "error"})
_GATE_REASON_CODES = frozenset(
    {
        "threshold_met",
        "threshold_not_met",
        "adapter_unavailable",
        "adapter_error",
        "invalid_adapter_result",
        "no_items_checked",
        "request_context_required",
        "remote_usage_not_accounted",
        "model_usage_not_accounted",
        "extension_rejected",
        "gate_passed",
        "gate_failed",
        "prerequisite_failed",
    }
)


@dataclass(frozen=True)
class QualityGateDecision:
    """Content-free decision returned by a v0.6 pairwise quality gate.

    Gate implementations return this small typed value instead of a free-form
    mapping. The central assurance pipeline owns the gate identifier, required
    policy, threshold enforcement, and final candidate acceptance.
    """

    status: QualityGateStatus
    score: Optional[float] = None
    source_entails_candidate: Optional[float] = None
    candidate_entails_source: Optional[float] = None
    threshold: Optional[float] = None
    score_direction: ScoreDirection = "higher"
    checked_items: int = 0
    reason_code: Optional[str] = None


@dataclass(frozen=True)
class QualityGateOutcome:
    """Validated, content-free receipt record for one configured quality gate."""

    identifier: str
    gate_type: QualityGateType
    status: QualityGateStatus
    required: bool
    score: Optional[float] = None
    source_entails_candidate: Optional[float] = None
    candidate_entails_source: Optional[float] = None
    threshold: Optional[float] = None
    score_direction: ScoreDirection = "higher"
    checked_items: int = 0
    reason_code: Optional[str] = None
    capability_sha256: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True)
class QualityGateBinding:
    """Bind a gate to required or advisory acceptance semantics.

    Required gates fail closed on failure, abstention, exceptions, invalid
    results, or missing consent. Advisory gates are still recorded but cannot
    override deterministic failures or required gates.
    """

    gate: Any = field(repr=False, compare=False)
    required: bool = True

    def __post_init__(self) -> None:
        if self.gate is None:
            raise ValueError("quality gate binding requires a gate")
        if type(self.required) is not bool:
            raise TypeError("quality gate required policy must be boolean")


def _items(pattern: re.Pattern[str], text: str, group: int = 0) -> list[str]:
    return [m.group(group) for m in pattern.finditer(text)]


def _counter_delta(
    pattern: re.Pattern[str], source: str, candidate: str, *, group: int = 0
) -> tuple[list[str], list[str]]:
    source_items = Counter(_items(pattern, source, group))
    candidate_items = Counter(_items(pattern, candidate, group))
    return sorted((source_items - candidate_items).elements()), sorted(
        (candidate_items - source_items).elements()
    )


def _normalized_counter_delta(
    pattern: re.Pattern[str], source: str, candidate: str, normalize: Callable[[str], str]
) -> tuple[list[str], list[str]]:
    left = Counter(normalize(item) for item in _items(pattern, source))
    right = Counter(normalize(item) for item in _items(pattern, candidate))
    return sorted((left - right).elements()), sorted((right - left).elements())


def _entity_items(text: str) -> list[str]:
    date_spans = [(match.start(), match.end()) for match in _DATE.finditer(text)]
    values = []
    for match in _ENTITY.finditer(text):
        # Calendar phrases such as "On June 3" are already protected by the
        # date gate and are not named entities. Avoid rejecting simple reorderings.
        if any(match.start() < end and match.end() > start for start, end in date_spans):
            continue
        values.append(match.group(0))
    return values


def _entity_delta(source: str, candidate: str) -> tuple[list[str], list[str]]:
    left = Counter(_entity_items(source))
    right = Counter(_entity_items(candidate))
    return sorted((left - right).elements()), sorted((right - left).elements())


def _modal_class(value: str) -> str:
    value = value.lower()
    if value in ("must", "shall", "required"):
        return "obligation"
    if value == "should":
        return "recommendation"
    if value in ("may", "might", "can", "could"):
        return "possibility"
    if value == "will":
        return "future"
    return "conditional"


def _json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_json_shape(item) for item in value]
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    # Numbers and booleans are facts, so keep their exact values.
    return value


def _structure_errors(source: str, candidate: str) -> list[str]:
    errors: list[str] = []
    source_blocks = _items(_FENCED_BLOCK, source)
    candidate_blocks = _items(_FENCED_BLOCK, candidate)
    if Counter(source_blocks) != Counter(candidate_blocks):
        errors.append("fenced code blocks changed")
    source_fences = _items(_FENCE, source, 1)
    candidate_fences = _items(_FENCE, candidate, 1)
    if source_fences and Counter(source_fences) != Counter(candidate_fences):
        errors.append("Markdown code-fence structure changed")
    missing_code, introduced_code = _counter_delta(_INLINE_CODE, source, candidate, group=1)
    if missing_code or introduced_code:
        errors.append("inline code spans changed")
    missing_targets, introduced_targets = _counter_delta(_MARKDOWN_LINK, source, candidate, group=1)
    if missing_targets or introduced_targets:
        errors.append("Markdown link targets changed")
    source_tags = [(match.group(1), match.group(2).lower()) for match in _HTML_TAG.finditer(source)]
    candidate_tags = [
        (match.group(1), match.group(2).lower()) for match in _HTML_TAG.finditer(candidate)
    ]
    if source_tags and Counter(source_tags) != Counter(candidate_tags):
        errors.append("HTML tag structure changed")
    source_headings = [len(item) for item in _items(_HEADING, source, 1)]
    candidate_headings = [len(item) for item in _items(_HEADING, candidate, 1)]
    if source_headings != candidate_headings:
        errors.append("Markdown heading structure changed")
    source_lists = [
        (len(match.group(1).expandtabs(4)), "ordered" if match.group(3) else "unordered")
        for match in _LIST_MARKER.finditer(source)
    ]
    candidate_lists = [
        (len(match.group(1).expandtabs(4)), "ordered" if match.group(3) else "unordered")
        for match in _LIST_MARKER.finditer(candidate)
    ]
    if source_lists != candidate_lists:
        errors.append("Markdown list structure changed")
    if len(_items(_TABLE_SEPARATOR, source)) != len(_items(_TABLE_SEPARATOR, candidate)):
        errors.append("Markdown table structure changed")
    try:
        source_json = json.loads(source)
    except (TypeError, ValueError):
        source_json = None
    else:
        try:
            candidate_json = json.loads(candidate)
        except (TypeError, ValueError):
            errors.append("candidate is not valid JSON")
        else:
            if _json_shape(source_json) != _json_shape(candidate_json):
                errors.append("JSON keys, types, or protected scalar values changed")
    return errors


def distinct_1_ratio(text: str, window: int = 80) -> float:
    words = re.findall(r"\w+", text.lower())[-window:]
    return len(set(words)) / len(words) if words else 1.0


@dataclass(frozen=True, repr=False)
class QualityReport:
    passed: bool
    length_ratio: float
    distinct_1_ratio: float
    missing_numbers: list[str] = field(default_factory=list)
    missing_urls: list[str] = field(default_factory=list)
    missing_emails: list[str] = field(default_factory=list)
    missing_quotes: list[str] = field(default_factory=list)
    unresolved_placeholders: bool = False
    semantic_score: Optional[float] = None
    reasons: list[str] = field(default_factory=list)
    introduced_numbers: list[str] = field(default_factory=list)
    missing_dates: list[str] = field(default_factory=list)
    introduced_dates: list[str] = field(default_factory=list)
    missing_units: list[str] = field(default_factory=list)
    introduced_units: list[str] = field(default_factory=list)
    introduced_urls: list[str] = field(default_factory=list)
    introduced_emails: list[str] = field(default_factory=list)
    introduced_quotes: list[str] = field(default_factory=list)
    missing_negations: list[str] = field(default_factory=list)
    introduced_negations: list[str] = field(default_factory=list)
    missing_modalities: list[str] = field(default_factory=list)
    introduced_modalities: list[str] = field(default_factory=list)
    missing_entities: list[str] = field(default_factory=list)
    introduced_entities: list[str] = field(default_factory=list)
    missing_citations: list[str] = field(default_factory=list)
    introduced_citations: list[str] = field(default_factory=list)
    structure_errors: list[str] = field(default_factory=list)
    gate_outcomes: tuple[QualityGateOutcome, ...] = ()

    def __repr__(self) -> str:
        return "<dewatermark quality report; content differences redacted>"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["gate_outcomes"] = [outcome.to_dict() for outcome in self.gate_outcomes]
        return value


def _public_identifier(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        return value
    import hashlib

    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]
    return f"quality-gate-sha256:{digest}"


def _finite_optional(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("quality gate scores and thresholds must be finite numbers")
    number = float(value)
    if not math.isfinite(number):
        raise TypeError("quality gate scores and thresholds must be finite numbers")
    return number


def _gate_type(capability: Any) -> QualityGateType:
    raw = capability.metadata.get("quality_gate_type", "external")
    return cast(QualityGateType, raw) if type(raw) is str and raw in _GATE_TYPES else "external"


def _normalize_decision(
    decision: Any,
    *,
    capability: Any,
    required: bool,
) -> QualityGateOutcome:
    """Validate an untrusted gate decision and attach central policy metadata."""
    if type(decision) is not QualityGateDecision:
        raise TypeError("quality gate must return QualityGateDecision")
    if decision.status not in _GATE_STATUSES:
        raise TypeError("quality gate returned an invalid status")
    if decision.score_direction not in ("higher", "lower"):
        raise TypeError("quality gate returned an invalid score direction")
    if type(decision.checked_items) is not int or decision.checked_items < 0:
        raise TypeError("quality gate checked_items must be a non-negative integer")
    score = _finite_optional(decision.score)
    forward = _finite_optional(decision.source_entails_candidate)
    reverse = _finite_optional(decision.candidate_entails_source)
    threshold = _finite_optional(decision.threshold)
    gate_type = _gate_type(capability)
    reason = (
        decision.reason_code
        if type(decision.reason_code) is str and decision.reason_code in _GATE_REASON_CODES
        else None
    )
    status: QualityGateStatus = decision.status
    if gate_type == "bidirectional_nli" and status in ("passed", "failed"):
        if (
            score is None
            or forward is None
            or reverse is None
            or threshold is None
            or decision.checked_items < 2
            or not all(0.0 <= value <= 1.0 for value in (score, forward, reverse, threshold))
            or not math.isclose(score, min(forward, reverse), rel_tol=1e-9, abs_tol=1e-12)
        ):
            raise TypeError("bidirectional NLI gate returned incomplete directional evidence")
    if gate_type in {
        "atomic_claim_qa",
        "entity_linking",
        "citation_grounding",
        "task_contract",
    } and status in ("passed", "failed"):
        if score is None or threshold is None or decision.checked_items < 1:
            raise TypeError("pairwise quality gate returned incomplete aggregate evidence")
    # Passing without a score/threshold is legitimate for task contracts, but a
    # gate cannot claim to have checked evidence when it reports zero items.
    if status == "passed" and decision.checked_items < 1:
        status = "abstained"
        reason = "no_items_checked"
    if status in ("passed", "failed") and score is not None and threshold is not None:
        meets = score >= threshold if decision.score_direction == "higher" else score <= threshold
        status = "passed" if meets else "failed"
        reason = "threshold_met" if meets else "threshold_not_met"
    elif status in ("abstained", "error"):
        score = None
        forward = None
        reverse = None
    return QualityGateOutcome(
        identifier=_public_identifier(capability.identifier),
        gate_type=gate_type,
        status=status,
        required=required,
        score=score,
        source_entails_candidate=forward,
        candidate_entails_source=reverse,
        threshold=threshold,
        score_direction=decision.score_direction,
        checked_items=decision.checked_items,
        reason_code=reason,
        capability_sha256=manifest_sha256(capability),
    )


def _error_outcome(
    *, capability: Any = None, gate: Any = None, required: bool, reason: str
) -> QualityGateOutcome:
    identifier = getattr(capability, "identifier", None)
    if type(identifier) is not str:
        try:
            identifier = f"implementation-sha256:{implementation_sha256(gate)}"
        except Exception:
            identifier = "unidentified-quality-gate"
    capability_digest = manifest_sha256(capability) if capability is not None else None
    return QualityGateOutcome(
        identifier=_public_identifier(identifier),
        gate_type=_gate_type(capability) if capability is not None else "external",
        status="error",
        required=required,
        checked_items=0,
        reason_code=reason if reason in _GATE_REASON_CODES else "extension_rejected",
        capability_sha256=capability_digest,
    )


def evaluate_quality(
    source: str,
    candidate: str,
    *,
    min_length_ratio: float = 0.70,
    max_length_ratio: float = 1.35,
    min_distinct_ratio: float = 0.35,
    semantic_scorer: Optional[Callable[[str, str], float]] = None,
    min_semantic_score: Optional[float] = None,
    extension_config: Any = None,
) -> QualityReport:
    source_words = max(1, len(source.split()))
    ratio = len(candidate.split()) / source_words
    distinct = distinct_1_ratio(candidate)
    missing_numbers, introduced_numbers = _counter_delta(_NUMBER, source, candidate)
    missing_urls, introduced_urls = _counter_delta(_URL, source, candidate)
    missing_emails, introduced_emails = _counter_delta(_EMAIL, source, candidate)
    missing_quotes, introduced_quotes = _counter_delta(_QUOTED, source, candidate)
    missing_dates, introduced_dates = _counter_delta(_DATE, source, candidate)
    missing_units, introduced_units = _counter_delta(_UNIT, source, candidate)
    missing_entities, introduced_entities = _entity_delta(source, candidate)
    missing_citations, introduced_citations = _counter_delta(_CITATION, source, candidate)
    missing_negations, introduced_negations = _normalized_counter_delta(
        _NEGATION, source, candidate, lambda _value: "negation"
    )
    missing_modalities, introduced_modalities = _normalized_counter_delta(
        _MODAL, source, candidate, _modal_class
    )
    structure_errors = _structure_errors(source, candidate)
    placeholders = bool(_PLACEHOLDER.search(candidate))
    semantic = None
    gate_outcomes: tuple[QualityGateOutcome, ...] = ()
    if semantic_scorer is not None and min_semantic_score is not None:
        capability = require_extension(semantic_scorer, "semantic_scorer", extension_config)
        semantic_status: QualityGateStatus = "error"
        semantic_reason = "adapter_error"
        try:
            before, accounting = begin_extension_usage(capability)
            checkpoint()
            raw_semantic = semantic_scorer(source, candidate)
            checkpoint()
            if type(raw_semantic) not in (int, float) or not math.isfinite(float(raw_semantic)):
                raise TypeError("semantic scorer must return a finite number")
            usage_error = extension_usage_error(
                before,
                network_required=capability.network_required,
                resource_accounting=accounting,
            )
            if usage_error:
                semantic_reason = usage_error
            else:
                semantic = float(raw_semantic)
                semantic_status = "passed" if semantic >= min_semantic_score else "failed"
                semantic_reason = (
                    "threshold_met" if semantic_status == "passed" else "threshold_not_met"
                )
        except ExtensionUsageRejected as exc:
            semantic = None
            semantic_reason = exc.reason_code
        except Exception:
            semantic = None
        gate_outcomes = (
            QualityGateOutcome(
                identifier=_public_identifier(capability.identifier),
                gate_type="semantic_similarity",
                status=semantic_status,
                required=True,
                score=semantic,
                threshold=min_semantic_score,
                checked_items=1 if semantic is not None else 0,
                reason_code=semantic_reason,
                capability_sha256=manifest_sha256(capability),
            ),
        )

    reasons = []
    if not candidate.strip():
        reasons.append("empty candidate")
    if not min_length_ratio <= ratio <= max_length_ratio:
        reasons.append("length ratio outside configured bounds")
    if distinct < min_distinct_ratio:
        reasons.append("degenerate repetition")
    if missing_numbers:
        reasons.append("numbers were dropped")
    if introduced_numbers:
        reasons.append("numbers were introduced")
    if missing_dates or introduced_dates:
        reasons.append("dates changed")
    if missing_units or introduced_units:
        reasons.append("quantities or units changed")
    if missing_urls:
        reasons.append("URLs were dropped")
    if introduced_urls:
        reasons.append("URLs were introduced")
    if missing_emails:
        reasons.append("email addresses were dropped")
    if introduced_emails:
        reasons.append("email addresses were introduced")
    if missing_quotes:
        reasons.append("quoted text was dropped")
    if introduced_quotes:
        reasons.append("quoted text was introduced")
    if missing_negations or introduced_negations:
        reasons.append("negation changed")
    if missing_modalities or introduced_modalities:
        reasons.append("modality changed")
    if missing_entities or introduced_entities:
        reasons.append("protected entity-like spans changed")
    if missing_citations or introduced_citations:
        reasons.append("citations changed")
    if structure_errors:
        reasons.append("document structure changed")
    if placeholders:
        reasons.append("unresolved mask placeholder")
    if min_semantic_score is not None and (semantic is None or semantic < min_semantic_score):
        reasons.append("semantic score below threshold")

    return QualityReport(
        passed=not reasons,
        length_ratio=round(ratio, 4),
        distinct_1_ratio=round(distinct, 4),
        missing_numbers=missing_numbers,
        missing_urls=missing_urls,
        missing_emails=missing_emails,
        missing_quotes=missing_quotes,
        unresolved_placeholders=placeholders,
        semantic_score=semantic,
        reasons=reasons,
        introduced_numbers=introduced_numbers,
        missing_dates=missing_dates,
        introduced_dates=introduced_dates,
        missing_units=missing_units,
        introduced_units=introduced_units,
        introduced_urls=introduced_urls,
        introduced_emails=introduced_emails,
        introduced_quotes=introduced_quotes,
        missing_negations=missing_negations,
        introduced_negations=introduced_negations,
        missing_modalities=missing_modalities,
        introduced_modalities=introduced_modalities,
        missing_entities=missing_entities,
        introduced_entities=introduced_entities,
        missing_citations=missing_citations,
        introduced_citations=introduced_citations,
        structure_errors=structure_errors,
        gate_outcomes=gate_outcomes,
    )


def evaluate_candidate(source: str, candidate: str, config) -> QualityReport:
    """Run deterministic checks, then every configured pairwise gate.

    The dependency-free report is always authoritative. A legacy injected gate
    is additive and cannot replace or erase those checks. New-style gates return
    :class:`QualityGateDecision`; only this function converts those untrusted
    decisions into receipt outcomes and accepts a candidate.
    """
    base = evaluate_quality(
        source,
        candidate,
        min_length_ratio=config.quality_min_length_ratio,
        max_length_ratio=config.quality_max_length_ratio,
        semantic_scorer=config.semantic_scorer,
        min_semantic_score=config.quality_min_semantic_score,
        extension_config=config,
    )
    outcomes = list(base.gate_outcomes)
    required_failed = False

    legacy_gate = getattr(config, "quality_gate", None)
    if legacy_gate is not None:
        if not base.passed:
            capability = static_capability(legacy_gate, "quality_gate")
            outcomes.append(
                QualityGateOutcome(
                    identifier=_public_identifier(capability.identifier),
                    gate_type=_gate_type(capability),
                    status="abstained",
                    required=True,
                    checked_items=0,
                    reason_code="prerequisite_failed",
                    capability_sha256=manifest_sha256(capability),
                )
            )
        else:
            capability = require_extension(legacy_gate, "quality_gate", config)
            try:
                before, accounting = begin_extension_usage(capability)
                checkpoint()
                report = legacy_gate.evaluate(source, candidate)
                checkpoint()
                if type(report) is not QualityReport:
                    raise TypeError("legacy quality gate must return QualityReport")
                if type(report.passed) is not bool:
                    raise TypeError("quality gate passed flag must be boolean")
                if not all(
                    type(value) in (int, float) and math.isfinite(value)
                    for value in (report.length_ratio, report.distinct_1_ratio)
                ):
                    raise TypeError("quality gate ratios must be finite numbers")
                usage_error = extension_usage_error(
                    before,
                    network_required=capability.network_required,
                    resource_accounting=accounting,
                )
                if usage_error:
                    outcome = QualityGateOutcome(
                        identifier=_public_identifier(capability.identifier),
                        gate_type=_gate_type(capability),
                        status="error",
                        required=True,
                        checked_items=0,
                        reason_code=usage_error,
                        capability_sha256=manifest_sha256(capability),
                    )
                else:
                    outcome = QualityGateOutcome(
                        identifier=_public_identifier(capability.identifier),
                        gate_type=_gate_type(capability),
                        status="passed" if report.passed else "failed",
                        required=True,
                        checked_items=1,
                        reason_code="gate_passed" if report.passed else "gate_failed",
                        capability_sha256=manifest_sha256(capability),
                    )
            except ExtensionUsageRejected as exc:
                outcome = _error_outcome(
                    capability=capability,
                    gate=legacy_gate,
                    required=True,
                    reason=exc.reason_code,
                )
            except Exception:
                outcome = _error_outcome(
                    capability=capability,
                    gate=legacy_gate,
                    required=True,
                    reason="extension_rejected",
                )
            outcomes.append(outcome)
            required_failed = outcome.status != "passed"

    configured = getattr(config, "quality_gates", ())
    for item in configured:
        binding = item if type(item) is QualityGateBinding else QualityGateBinding(item)
        gate_capability = None
        if not base.passed or required_failed:
            try:
                gate_capability = static_capability(binding.gate, "quality_gate")
                outcome = QualityGateOutcome(
                    identifier=_public_identifier(gate_capability.identifier),
                    gate_type=_gate_type(gate_capability),
                    status="abstained",
                    required=binding.required,
                    checked_items=0,
                    reason_code="prerequisite_failed",
                    capability_sha256=manifest_sha256(gate_capability),
                )
            except ExtensionUsageRejected as exc:
                outcome = _error_outcome(
                    capability=gate_capability,
                    gate=binding.gate,
                    required=binding.required,
                    reason=exc.reason_code,
                )
            except Exception:
                outcome = _error_outcome(
                    capability=gate_capability,
                    gate=binding.gate,
                    required=binding.required,
                    reason="extension_rejected",
                )
        else:
            try:
                gate_capability = require_extension(binding.gate, "quality_gate", config)
                before, accounting = begin_extension_usage(gate_capability)
                checkpoint()
                decision = binding.gate.evaluate(source, candidate)
                checkpoint()
                usage_error = extension_usage_error(
                    before,
                    network_required=gate_capability.network_required,
                    resource_accounting=accounting,
                )
                outcome = (
                    _error_outcome(
                        capability=gate_capability,
                        gate=binding.gate,
                        required=binding.required,
                        reason=usage_error,
                    )
                    if usage_error is not None
                    else _normalize_decision(
                        decision,
                        capability=gate_capability,
                        required=binding.required,
                    )
                )
            except Exception:
                outcome = _error_outcome(
                    capability=gate_capability,
                    gate=binding.gate,
                    required=binding.required,
                    reason="extension_rejected",
                )
        outcomes.append(outcome)
        if binding.required and outcome.status != "passed":
            required_failed = True

    reasons = list(base.reasons)
    if required_failed and "external quality gate rejected candidate" not in reasons:
        reasons.append("external quality gate rejected candidate")
    return replace(
        base,
        passed=base.passed and not required_failed,
        reasons=reasons,
        gate_outcomes=tuple(outcomes),
    )
