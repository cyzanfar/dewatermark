"""Content-free localization of detector evidence in long or mixed text.

Localization is an editing aid, not a second detector.  The full document is
scored first.  When a detector does not provide native character spans, this
module scores overlapping windows through :class:`DetectorSession` and merges
positive windows.  Window-level p-values receive a Bonferroni correction;
status-only detectors are labelled exploratory rather than statistically
localized.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Literal, Optional, Sequence

from .detector_session import (
    DetectorObservation,
    DetectorPolicyDriftError,
    DetectorQueryBudgetExceeded,
    DetectorSession,
    SignalSpan,
)
from .extension_safety import manifest_sha256

LocalizationStatus = Literal[
    "localized",
    "localized_exploratory",
    "not_detected",
    "not_localized",
    "insufficient_evidence",
    "failed",
]
LocalizationMethod = Literal[
    "detector_attribution",
    "bonferroni_windows",
    "exploratory_windows",
    "none",
]
_MAX_WINDOWED_CHARACTERS = 4_000_000


def _text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _finite(value: Any) -> Optional[float]:
    if isinstance(value, bool) or type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


@dataclass(frozen=True, repr=False)
class LocalizedSignal:
    """One merged, half-open character range without retaining its contents."""

    start: int
    end: int
    contributing_windows: int
    strongest_margin: Optional[float] = None
    smallest_p_value: Optional[float] = None

    def __repr__(self) -> str:
        return "<dewatermark localized signal; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "start": self.start,
            "end": self.end,
            "contributing_windows": self.contributing_windows,
            "strongest_margin": self.strongest_margin,
            "smallest_p_value": self.smallest_p_value,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, repr=False)
class LocalizationReport:
    """Content-free result of one bounded localization request."""

    status: LocalizationStatus
    method: LocalizationMethod
    detector: str
    text_sha256: str
    text_characters: int
    window_characters: int
    stride_characters: int
    windows_scored: int
    spans: tuple[LocalizedSignal, ...] = ()
    familywise_alpha: Optional[float] = None
    adjusted_window_alpha: Optional[float] = None
    reason_code: Optional[str] = None
    detector_ledger: dict[str, int] | None = None
    schema_version: str = "1.0"

    def __repr__(self) -> str:
        return "<dewatermark localization report; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "schema_version": self.schema_version,
            "status": self.status,
            "method": self.method,
            "detector": self.detector,
            "text_sha256": self.text_sha256,
            "text_characters": self.text_characters,
            "window_characters": self.window_characters,
            "stride_characters": self.stride_characters,
            "windows_scored": self.windows_scored,
            "spans": [span.to_dict() for span in self.spans],
            "familywise_alpha": self.familywise_alpha,
            "adjusted_window_alpha": self.adjusted_window_alpha,
            "reason_code": self.reason_code,
            "detector_ledger": dict(self.detector_ledger or {}),
        }
        return {key: value for key, value in values.items() if value is not None}


def _window_ranges(length: int, window: int, stride: int) -> tuple[tuple[int, int], ...]:
    if length <= window:
        return ((0, length),)
    starts = list(range(0, length - window + 1, stride))
    final = length - window
    if starts[-1] != final:
        starts.append(final)
    return tuple((start, start + window) for start in starts)


def _window_count(length: int, window: int, stride: int) -> int:
    """Count windows without allocating ranges or sliced text."""
    if length <= window:
        return 1
    quotient, remainder = divmod(length - window, stride)
    return quotient + 1 + int(remainder != 0)


def _merge_ranges(
    ranges: Sequence[tuple[int, int, Optional[float], Optional[float]]],
) -> tuple[LocalizedSignal, ...]:
    if not ranges:
        return ()
    ordered = sorted(ranges, key=lambda item: (item[0], item[1]))
    merged: list[LocalizedSignal] = []
    start, end, margin, p_value = ordered[0]
    count = 1
    margins = [margin] if margin is not None else []
    p_values = [p_value] if p_value is not None else []
    for next_start, next_end, next_margin, next_p in ordered[1:]:
        if next_start <= end:
            end = max(end, next_end)
            count += 1
            if next_margin is not None:
                margins.append(next_margin)
            if next_p is not None:
                p_values.append(next_p)
            continue
        merged.append(
            LocalizedSignal(
                start=start,
                end=end,
                contributing_windows=count,
                strongest_margin=max(margins) if margins else None,
                smallest_p_value=min(p_values) if p_values else None,
            )
        )
        start, end, count = next_start, next_end, 1
        margins = [next_margin] if next_margin is not None else []
        p_values = [next_p] if next_p is not None else []
    merged.append(
        LocalizedSignal(
            start=start,
            end=end,
            contributing_windows=count,
            strongest_margin=max(margins) if margins else None,
            smallest_p_value=min(p_values) if p_values else None,
        )
    )
    return tuple(merged)


def _native_spans(spans: Sequence[SignalSpan]) -> tuple[LocalizedSignal, ...]:
    return _merge_ranges(tuple((span.start, span.end, None, span.p_value) for span in spans))


def _base_report(
    *,
    status: LocalizationStatus,
    method: LocalizationMethod,
    observation: DetectorObservation,
    text: str,
    window_characters: int,
    stride_characters: int,
    windows_scored: int,
    session: DetectorSession,
    spans: tuple[LocalizedSignal, ...] = (),
    familywise_alpha: Optional[float] = None,
    adjusted_window_alpha: Optional[float] = None,
    reason_code: Optional[str] = None,
) -> LocalizationReport:
    return LocalizationReport(
        status=status,
        method=method,
        detector=observation.detector,
        text_sha256=_text_digest(text),
        text_characters=len(text),
        window_characters=window_characters,
        stride_characters=stride_characters,
        windows_scored=windows_scored,
        spans=spans,
        familywise_alpha=familywise_alpha,
        adjusted_window_alpha=adjusted_window_alpha,
        reason_code=reason_code,
        detector_ledger=session.ledger(),
    )


def localize(
    text: str,
    session: DetectorSession,
    *,
    window_characters: int = 1200,
    stride_characters: int = 600,
    familywise_alpha: float = 0.01,
) -> LocalizationReport:
    """Locate likely marked spans without retaining or returning their text.

    A full-document positive is required before any windows are scored. Native
    detector spans are preferred. For generic windowing, calibrated p-values
    are required for a multiplicity-controlled ``localized`` result; otherwise
    the result is explicitly ``localized_exploratory``.
    """
    if type(text) is not str or not text:
        raise ValueError("text must be a non-empty string")
    if not isinstance(session, DetectorSession):
        raise TypeError("session must be a DetectorSession")
    if type(window_characters) is not int or window_characters < 32:
        raise ValueError("window_characters must be an integer of at least 32")
    if (
        type(stride_characters) is not int
        or stride_characters < 1
        or stride_characters > window_characters
    ):
        raise ValueError("stride_characters must be between 1 and window_characters")
    if (
        isinstance(familywise_alpha, bool)
        or type(familywise_alpha) not in (int, float)
        or not math.isfinite(float(familywise_alpha))
        or not 0.0 < float(familywise_alpha) < 1.0
    ):
        raise ValueError("familywise_alpha must be a finite number between 0 and 1")

    try:
        primary_capability = session.primary_capability()
        capability_sha256 = manifest_sha256(primary_capability)
        calibrated = primary_capability.calibrated
    except Exception:
        primary_capability = None
        capability_sha256 = None
        calibrated = False
    try:
        full = session.score(text)
    except DetectorPolicyDriftError:
        return LocalizationReport(
            status="failed",
            method="none",
            detector=(
                primary_capability.identifier
                if primary_capability is not None
                else "primary-detector"
            ),
            text_sha256=_text_digest(text),
            text_characters=len(text),
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            spans=(),
            reason_code="detector_policy_drift",
            detector_ledger=session.ledger(),
        )

    def capability_stable() -> bool:
        if capability_sha256 is None:
            return False
        try:
            return manifest_sha256(session.primary_capability()) == capability_sha256
        except Exception:
            return False

    if not capability_stable():
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="detector_policy_drift",
        )
    full_status = full.evidence.status
    if full_status == "not_detected":
        return _base_report(
            status="not_detected",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="full_document_not_detected",
        )
    if full_status == "insufficient_evidence":
        return _base_report(
            status="insufficient_evidence",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="full_document_insufficient_evidence",
        )
    if full_status != "detected":
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="full_document_detector_inconclusive",
        )
    if full.localization:
        native = _native_spans(full.localization)
        native_p_values_complete = all(
            span.p_value is not None and 0.0 <= span.p_value <= 1.0 for span in full.localization
        )
        native_error_control = (
            primary_capability is not None
            and type(primary_capability.metadata) is dict
            and primary_capability.metadata.get("localization_calibrated") is True
            and primary_capability.metadata.get("localization_error_control") == "familywise"
        )
        native_controlled = calibrated and native_p_values_complete and native_error_control
        if not calibrated:
            native_reason = "detector_not_calibrated"
        elif not native_p_values_complete:
            native_reason = "native_p_values_unavailable"
        elif not native_error_control:
            native_reason = "native_error_control_unbound"
        else:
            native_reason = None
        return _base_report(
            status="localized" if native_controlled else "localized_exploratory",
            method="detector_attribution",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            spans=native,
            reason_code=native_reason,
        )

    effective_window = min(window_characters, len(text))
    window_count = _window_count(len(text), effective_window, stride_characters)
    if window_count > session.config.max_batch_items:
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="window_batch_limit_exceeded",
        )
    if window_count > session.queries_remaining:
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="detector_query_budget_exhausted",
        )
    if window_count * effective_window > _MAX_WINDOWED_CHARACTERS:
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="window_character_budget_exhausted",
        )

    ranges = _window_ranges(len(text), effective_window, stride_characters)
    windows = tuple(text[start:end] for start, end in ranges)
    try:
        observations = session.score_many(windows)
    except DetectorQueryBudgetExceeded:
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="detector_query_budget_exhausted",
        )
    except DetectorPolicyDriftError:
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=0,
            session=session,
            reason_code="detector_policy_drift",
        )
    if not capability_stable():
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=len(observations),
            session=session,
            reason_code="detector_policy_drift",
        )

    decision_statuses_complete = bool(observations) and all(
        item.evidence.status in {"detected", "not_detected"} for item in observations
    )
    if not decision_statuses_complete:
        return _base_report(
            status="failed",
            method="none",
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=len(observations),
            session=session,
            reason_code="window_detector_inconclusive",
        )

    p_values_complete = all(
        item.p_value is not None and 0.0 <= item.p_value <= 1.0 for item in observations
    )
    controlled = p_values_complete and calibrated
    adjusted = float(familywise_alpha) / len(observations) if controlled and observations else None
    positives: list[tuple[int, int, Optional[float], Optional[float]]] = []
    for (start, end), observation in zip(ranges, observations):
        p_value = _finite(observation.p_value)
        selected = (
            controlled
            and adjusted is not None
            and p_value is not None
            and p_value <= adjusted
            and observation.evidence.status == "detected"
        ) or (not controlled and observation.evidence.status == "detected")
        if selected:
            positives.append((start, end, observation.detection_margin, p_value))
    spans = _merge_ranges(positives)
    method: LocalizationMethod = "bonferroni_windows" if controlled else "exploratory_windows"
    if not calibrated:
        reason_code = "detector_not_calibrated"
    elif not p_values_complete:
        reason_code = "window_p_values_unavailable"
    else:
        reason_code = None
    if not spans:
        return _base_report(
            status="not_localized",
            method=method,
            observation=full,
            text=text,
            window_characters=window_characters,
            stride_characters=stride_characters,
            windows_scored=len(observations),
            session=session,
            familywise_alpha=float(familywise_alpha) if controlled else None,
            adjusted_window_alpha=adjusted if controlled else None,
            reason_code="no_window_met_localization_rule",
        )
    return _base_report(
        status="localized" if controlled else "localized_exploratory",
        method=method,
        observation=full,
        text=text,
        window_characters=window_characters,
        stride_characters=stride_characters,
        windows_scored=len(observations),
        session=session,
        spans=spans,
        familywise_alpha=float(familywise_alpha) if controlled else None,
        adjusted_window_alpha=adjusted if controlled else None,
        reason_code=reason_code,
    )


__all__ = [
    "LocalizedSignal",
    "LocalizationMethod",
    "LocalizationReport",
    "LocalizationStatus",
    "localize",
]
