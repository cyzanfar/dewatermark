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
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from .extension_safety import require_extension

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


@dataclass(frozen=True)
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
    structure_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


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
    missing_negations, introduced_negations = _normalized_counter_delta(
        _NEGATION, source, candidate, lambda _value: "negation"
    )
    missing_modalities, introduced_modalities = _normalized_counter_delta(
        _MODAL, source, candidate, _modal_class
    )
    structure_errors = _structure_errors(source, candidate)
    placeholders = bool(_PLACEHOLDER.search(candidate))
    semantic = None
    if semantic_scorer is not None and min_semantic_score is not None:
        require_extension(semantic_scorer, "semantic_scorer", extension_config)
        raw_semantic = semantic_scorer(source, candidate)
        if (
            isinstance(raw_semantic, bool)
            or not isinstance(raw_semantic, (int, float))
            or not math.isfinite(float(raw_semantic))
        ):
            raise TypeError("semantic scorer must return a finite number")
        semantic = float(raw_semantic)

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
        structure_errors=structure_errors,
    )


def evaluate_candidate(source: str, candidate: str, config) -> QualityReport:
    """Run an injected quality gate or the conservative built-in gate."""
    if config.quality_gate is not None:
        require_extension(config.quality_gate, "quality_gate", config)
        report = config.quality_gate.evaluate(source, candidate)
        if not isinstance(report, QualityReport):
            raise TypeError("quality gate must return QualityReport")
        if not isinstance(report.passed, bool):
            raise TypeError("quality gate passed flag must be boolean")
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            for value in (report.length_ratio, report.distinct_1_ratio)
        ):
            raise TypeError("quality gate ratios must be finite numbers")
        return QualityReport(
            passed=bool(report.passed),
            length_ratio=float(report.length_ratio),
            distinct_1_ratio=float(report.distinct_1_ratio),
            unresolved_placeholders=bool(report.unresolved_placeholders),
            semantic_score=(
                float(report.semantic_score)
                if isinstance(report.semantic_score, (int, float))
                and not isinstance(report.semantic_score, bool)
                and math.isfinite(float(report.semantic_score))
                else None
            ),
            reasons=[] if report.passed else ["external quality gate rejected candidate"],
            structure_errors=(
                ["external quality gate reported a structural mismatch"]
                if report.structure_errors
                else []
            ),
        )
    return evaluate_quality(
        source,
        candidate,
        min_length_ratio=config.quality_min_length_ratio,
        max_length_ratio=config.quality_max_length_ratio,
        semantic_scorer=config.semantic_scorer,
        min_semantic_score=config.quality_min_semantic_score,
        extension_config=config,
    )
