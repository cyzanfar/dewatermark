from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from dewatermark.config import DewatermarkConfig
from dewatermark.detector_session import DetectorSession
from dewatermark.localization import localize
from dewatermark.models import CapabilityManifest, DetectionEvidence
from dewatermark.schemas import localization_result_schema


def _assert_public(report):
    Draft202012Validator(localization_result_schema()).validate(report.to_dict())


class _WindowDetector:
    capability = CapabilityManifest(
        identifier="test/window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=True,
        independent=False,
        metadata={"score_direction": "higher", "resource_accounting": "none"},
    )

    def available(self):
        return True

    def detect(self, text):
        marked = "MARK" in text
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme="test-window",
            status="detected" if marked else "not_detected",
            score=2.0 if marked else 0.0,
            threshold=1.0,
            details={
                "score_direction": "higher",
                "p_value": 0.0001 if marked else 0.9,
            },
        )


class _StatusOnlyDetector(_WindowDetector):
    capability = CapabilityManifest(
        identifier="test/status-window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=True,
        metadata={"score_direction": "higher", "resource_accounting": "none"},
    )

    def detect(self, text):
        marked = "MARK" in text
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme="test-window",
            status="detected" if marked else "not_detected",
            score=2.0 if marked else 0.0,
            threshold=1.0,
            details={"score_direction": "higher"},
        )


class _NativeDetector(_WindowDetector):
    capability = CapabilityManifest(
        identifier="test/native-window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=True,
        metadata={
            "score_direction": "higher",
            "resource_accounting": "none",
            "localization_calibrated": True,
            "localization_error_control": "familywise",
        },
    )

    def detect(self, text):
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme="test-window",
            status="detected",
            score=2.0,
            threshold=1.0,
            details={
                "score_direction": "higher",
                "localization": [
                    {"start": 4, "end": 12, "score": 2.5, "p_value": 0.001},
                    {"start": 10, "end": 16, "score": 2.0, "p_value": 0.002},
                ],
            },
        )


class _UncontrolledNativeDetector(_NativeDetector):
    capability = CapabilityManifest(
        identifier="test/uncontrolled-native-window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=True,
        metadata={"score_direction": "higher", "resource_accounting": "none"},
    )

    def detect(self, text):
        evidence = super().detect(text)
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme=evidence.scheme,
            status=evidence.status,
            score=evidence.score,
            threshold=evidence.threshold,
            details={
                "score_direction": "higher",
                "localization": [{"start": 4, "end": 12, "score": 2.5}],
            },
        )


class _InconclusiveWindowDetector(_WindowDetector):
    capability = CapabilityManifest(
        identifier="test/inconclusive-window-detector",
        kind="detector",
        schemes=("test-window",),
        metadata={"score_direction": "higher", "resource_accounting": "none"},
    )

    def detect(self, text):
        if len(text) > 64:
            return super().detect(text)
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme="test-window",
            status="detector_error",
            score=2.0,
            threshold=1.0,
            details={"score_direction": "higher", "p_value": 0.00001},
        )


class _UncalibratedWindowDetector(_WindowDetector):
    capability = CapabilityManifest(
        identifier="test/uncalibrated-window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=False,
        metadata={"score_direction": "higher", "resource_accounting": "none"},
    )


class _NegativeLowPDetector(_WindowDetector):
    def detect(self, text):
        if len(text) > 64:
            return super().detect(text)
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme="test-window",
            status="not_detected",
            score=0.0,
            threshold=1.0,
            details={"score_direction": "higher", "p_value": 0.000001},
        )


def test_window_localization_uses_multiplicity_corrected_p_values():
    text = "a" * 80 + "MARK" + "b" * 80
    session = DetectorSession(_WindowDetector(), max_queries=20)
    report = localize(text, session, window_characters=64, stride_characters=32)

    assert report.status == "localized"
    assert report.method == "bonferroni_windows"
    assert report.windows_scored == 5
    assert report.adjusted_window_alpha == pytest.approx(0.002)
    assert report.spans
    assert report.spans[0].start <= 80 < report.spans[0].end
    rendered = json.dumps(report.to_dict())
    assert "MARK" not in rendered
    assert len(report.text_sha256) == 64


def test_status_only_localization_is_explicitly_exploratory():
    text = "a" * 64 + "MARK" + "b" * 64
    report = localize(
        text,
        DetectorSession(_StatusOnlyDetector(), max_queries=20),
        window_characters=64,
        stride_characters=32,
    )
    assert report.status == "localized_exploratory"
    assert report.method == "exploratory_windows"
    assert report.reason_code == "window_p_values_unavailable"
    assert report.familywise_alpha is None


def test_native_detector_spans_are_preferred_and_merged_without_window_queries():
    session = DetectorSession(_NativeDetector(), max_queries=2)
    report = localize("x" * 80, session)
    assert report.status == "localized"
    assert report.method == "detector_attribution"
    assert report.windows_scored == 0
    assert report.spans[0].to_dict() == {
        "start": 4,
        "end": 16,
        "contributing_windows": 2,
        "smallest_p_value": 0.001,
    }
    assert session.queries_used == 1


def test_native_spans_without_calibrated_error_control_are_exploratory():
    report = localize("x" * 80, DetectorSession(_UncontrolledNativeDetector(), max_queries=2))

    assert report.status == "localized_exploratory"
    assert report.method == "detector_attribution"
    assert report.reason_code == "native_p_values_unavailable"
    assert report.spans
    _assert_public(report)

    promoted = report.to_dict()
    promoted["status"] = "localized"
    assert list(Draft202012Validator(localization_result_schema()).iter_errors(promoted))


def test_detector_cannot_enable_confirmatory_localization_during_detection():
    class DriftingNativeDetector:
        def __init__(self):
            self.capability = CapabilityManifest(
                identifier="test/drifting-native-window-detector",
                kind="detector",
                schemes=("test-window",),
                calibrated=True,
                metadata={"resource_accounting": "none"},
            )

        def available(self):
            return True

        def detect(self, _text):
            self.capability.metadata["localization_calibrated"] = True
            self.capability.metadata["localization_error_control"] = "familywise"
            return {
                "scheme": "test-window",
                "status": "detected",
                "score": 2.0,
                "threshold": 1.0,
                "score_direction": "higher",
                "localization": [{"start": 1, "end": 4, "p_value": 0.001}],
            }

    report = localize("x" * 80, DetectorSession(DriftingNativeDetector(), max_queries=2))

    assert report.status == "failed"
    assert report.reason_code == "detector_policy_drift"
    assert report.spans == ()
    _assert_public(report)


def test_native_localization_rejects_implementation_drift_during_detection():
    class DriftingNativeDetector(_NativeDetector):
        def detect(self, text, multiplier=1.0):
            type(self).detect.__defaults__ = (2.0,)
            evidence = _NativeDetector.detect(self, text)
            return DetectionEvidence(
                detector=evidence.detector,
                scheme=evidence.scheme,
                status=evidence.status,
                score=float(evidence.score or 0.0) * multiplier,
                threshold=evidence.threshold,
                details=evidence.details,
            )

    original_defaults = DriftingNativeDetector.detect.__defaults__
    try:
        report = localize("x" * 80, DetectorSession(DriftingNativeDetector(), max_queries=2))
    finally:
        DriftingNativeDetector.detect.__defaults__ = original_defaults

    assert report.status == "failed"
    assert report.reason_code == "detector_policy_drift"
    assert report.spans == ()
    _assert_public(report)


def test_reused_session_reports_policy_drift_instead_of_raising():
    detector = _WindowDetector()
    detector.capability = CapabilityManifest(
        identifier="test/window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=True,
        independent=False,
        metadata={
            "configuration_sha256": "a" * 64,
            "score_direction": "higher",
            "resource_accounting": "none",
        },
    )
    session = DetectorSession(detector, max_queries=4)
    session.score("MARK" + "x" * 80)
    detector.capability = CapabilityManifest(
        identifier="test/window-detector",
        kind="detector",
        schemes=("test-window",),
        calibrated=True,
        independent=False,
        metadata={
            "configuration_sha256": "f" * 64,
            "score_direction": "higher",
            "resource_accounting": "none",
        },
    )

    report = localize("MARK" + "x" * 80, session)

    assert report.status == "failed"
    assert report.reason_code == "detector_policy_drift"
    assert report.spans == ()


def test_full_document_negative_stops_before_window_scoring():
    session = DetectorSession(_WindowDetector(), max_queries=2)
    report = localize("ordinary unmarked text" * 10, session)
    assert report.status == "not_detected"
    assert report.windows_scored == 0
    assert session.queries_used == 1


def test_window_batch_refuses_partial_work_when_query_budget_is_too_small():
    session = DetectorSession(_WindowDetector(), max_queries=2)
    text = "MARK" + "x" * 300
    report = localize(text, session, window_characters=64, stride_characters=32)
    assert report.status == "failed"
    assert report.reason_code == "detector_query_budget_exhausted"
    assert session.queries_used == 1
    _assert_public(report)


def test_window_count_is_rejected_before_ranges_or_text_slices_are_allocated():
    session = DetectorSession(
        _WindowDetector(),
        config=DewatermarkConfig(
            max_input_chars=10_000,
            max_batch_items=10,
            max_detector_queries=64,
        ),
        max_queries=64,
    )
    report = localize("MARK" + "x" * 996, session, window_characters=32, stride_characters=1)

    assert report.status == "failed"
    assert report.reason_code == "window_batch_limit_exceeded"
    assert report.windows_scored == 0
    assert session.queries_used == 1
    _assert_public(report)


def test_overlapping_window_character_amplification_is_hard_bounded():
    session = DetectorSession(
        _WindowDetector(),
        config=DewatermarkConfig(
            max_input_chars=20_000,
            max_batch_items=20_000,
            max_detector_queries=20_000,
        ),
        max_queries=20_000,
    )
    report = localize(
        "MARK" + "x" * 19_996,
        session,
        window_characters=10_000,
        stride_characters=1,
    )

    assert report.status == "failed"
    assert report.reason_code == "window_character_budget_exhausted"
    assert report.windows_scored == 0
    assert session.queries_used == 1
    _assert_public(report)


def test_uncalibrated_p_values_never_produce_confirmatory_localization():
    text = "a" * 80 + "MARK" + "b" * 80
    report = localize(
        text,
        DetectorSession(_UncalibratedWindowDetector(), max_queries=20),
        window_characters=64,
        stride_characters=32,
    )

    assert report.status == "localized_exploratory"
    assert report.method == "exploratory_windows"
    assert report.reason_code == "detector_not_calibrated"
    assert report.familywise_alpha is None


def test_low_p_value_cannot_promote_a_not_detected_window():
    text = "a" * 80 + "MARK" + "b" * 80
    report = localize(
        text,
        DetectorSession(_NegativeLowPDetector(), max_queries=20),
        window_characters=64,
        stride_characters=32,
    )

    assert report.status == "not_localized"
    assert report.spans == ()


def test_inconclusive_window_cannot_be_promoted_by_a_low_p_value():
    text = "a" * 80 + "MARK" + "b" * 80
    report = localize(
        text,
        DetectorSession(_InconclusiveWindowDetector(), max_queries=20),
        window_characters=64,
        stride_characters=32,
    )
    assert report.status == "failed"
    assert report.method == "none"
    assert report.reason_code == "window_detector_inconclusive"
    assert report.spans == ()
    _assert_public(report)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"window_characters": 31}, "window_characters"),
        ({"stride_characters": 0}, "stride_characters"),
        ({"familywise_alpha": 1.0}, "familywise_alpha"),
    ],
)
def test_localization_rejects_invalid_bounds(kwargs, message):
    with pytest.raises(ValueError, match=message):
        localize("MARK" * 20, DetectorSession(_WindowDetector()), **kwargs)
