"""Cheap, deterministic quality gates for generated rewrites.

These checks are deliberately conservative and dependency-free.  They do not
claim to prove semantic equivalence; they catch the common catastrophic cases
(truncation, dropped numbers/URLs/quoted strings, placeholders, and repetition)
before a candidate can replace the source.  Applications may provide a stronger
semantic scorer on top of this report.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

_NUMBER = re.compile(r"(?<!\w)[+-]?\d+(?:,\d{3})*(?:\.\d+)?%?(?!\w)")
_URL = re.compile(r"(?:https?://|www\.)[^\s<>]+", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_QUOTED = re.compile(r"(?:\"[^\"\n]{2,}\"|'[^'\n]{2,}')")
_PLACEHOLDER = re.compile(r"\[(?:BLANK|MASK)(?:_\d+)?\]|<mask>", re.I)


def _items(pattern: re.Pattern, text: str) -> set[str]:
    return {m.group(0) for m in pattern.finditer(text)}


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
) -> QualityReport:
    source_words = max(1, len(source.split()))
    ratio = len(candidate.split()) / source_words
    distinct = distinct_1_ratio(candidate)
    missing_numbers = sorted(_items(_NUMBER, source) - _items(_NUMBER, candidate))
    missing_urls = sorted(_items(_URL, source) - _items(_URL, candidate))
    missing_emails = sorted(_items(_EMAIL, source) - _items(_EMAIL, candidate))
    missing_quotes = sorted(_items(_QUOTED, source) - _items(_QUOTED, candidate))
    placeholders = bool(_PLACEHOLDER.search(candidate))
    semantic = semantic_scorer(source, candidate) if semantic_scorer else None

    reasons = []
    if not candidate.strip():
        reasons.append("empty candidate")
    if not min_length_ratio <= ratio <= max_length_ratio:
        reasons.append("length ratio outside configured bounds")
    if distinct < min_distinct_ratio:
        reasons.append("degenerate repetition")
    if missing_numbers:
        reasons.append("numbers were dropped")
    if missing_urls:
        reasons.append("URLs were dropped")
    if missing_emails:
        reasons.append("email addresses were dropped")
    if missing_quotes:
        reasons.append("quoted text was dropped")
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
    )


def evaluate_candidate(source: str, candidate: str, config) -> QualityReport:
    """Run an injected quality gate or the conservative built-in gate."""
    if config.quality_gate is not None:
        report = config.quality_gate.evaluate(source, candidate)
        if not isinstance(report, QualityReport):
            raise TypeError("quality gate must return QualityReport")
        return report
    return evaluate_quality(
        source,
        candidate,
        min_length_ratio=config.quality_min_length_ratio,
        max_length_ratio=config.quality_max_length_ratio,
        semantic_scorer=config.semantic_scorer,
        min_semantic_score=config.quality_min_semantic_score,
    )
