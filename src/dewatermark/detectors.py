"""Built-in assurance detectors and result normalization."""

from __future__ import annotations

import inspect
import math
from dataclasses import replace
from typing import Any, Mapping, Optional, cast

from .exceptions import ConfigurationError
from .extension_safety import require_extension, static_capability
from .models import CapabilityManifest, DetectionEvidence, DetectionStatus
from .request_context import (
    ResourceBudgetExceeded,
    begin_extension_usage,
    checkpoint,
    extension_usage_error,
    safe_error,
)
from .unicode import analyze

_PUBLIC_EVIDENCE_DETAIL_KEYS = {
    "configuration_sha256",
    "effective_tokens",
    "green_hits",
    "mean_g_value",
    "mismatch_fields",
    "p_value",
    "protocol_version",
    "reference_only",
    "reason_code",
    "reported_status",
    "score_direction",
    "total_flags",
    "vendor_equivalent",
    "z_score",
}
_GENERIC_UNSUPPORTED_REASON = "No public, independently usable detector is available."
_ANTHROPIC_UNSUPPORTED_REASON = (
    "Anthropic documents marking for supported models launched on or after "
    "2026-08-02 but has not published the detector, keys, threshold, or "
    "verification procedure."
)
_SYNTHID_UNSUPPORTED_REASON = (
    "Public SynthID-Text references do not provide Gemini production keys "
    "or a provider-authorized production detector."
)
_PUBLIC_UNSUPPORTED_REASONS = frozenset(
    {
        _GENERIC_UNSUPPORTED_REASON,
        _ANTHROPIC_UNSUPPORTED_REASON,
        _SYNTHID_UNSUPPORTED_REASON,
    }
)


def _public_evidence_details(details: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only documented evidence fields, never arbitrary detector payloads."""
    public: dict[str, Any] = {}
    for key, value in details.items():
        if key not in _PUBLIC_EVIDENCE_DETAIL_KEYS:
            continue
        if value is None or isinstance(value, (str, bool, int, float)):
            public[key] = value
        elif key == "mismatch_fields" and isinstance(value, (list, tuple)):
            allowed = {
                "configuration_sha256",
                "detector",
                "protocol_version",
                "scheme",
                "score_direction",
                "threshold",
                "tokenizer_revision",
            }
            public[key] = sorted({item for item in value if type(item) is str and item in allowed})
    return public


def _public_threshold(detector: Any) -> Optional[float]:
    """Read a literal finite threshold without invoking extension descriptors."""
    try:
        value = inspect.getattr_static(detector, "threshold")
    except Exception:
        return None
    if isinstance(value, bool) or type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _finite_number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _trusted_detector_reason(detector: Any, capability: CapabilityManifest) -> bool:
    from .reference_detectors import ReferenceStatisticalDetector

    return isinstance(
        detector,
        (UnsupportedDetector, UnicodeArtifactDetector, ReferenceStatisticalDetector),
    ) or bool(capability.metadata.get("command_protocol_version"))


class _UnsupportedDetectorFactory:
    """Callable factory whose capability can be inspected without construction."""

    def __init__(self, identifier: str, scheme: str, reason: str, **metadata: Any) -> None:
        self._reason = (
            reason if reason in _PUBLIC_UNSUPPORTED_REASONS else _GENERIC_UNSUPPORTED_REASON
        )
        self._scheme = scheme
        self.capability = CapabilityManifest(
            identifier=identifier,
            kind="detector",
            schemes=(scheme,),
            description=self._reason,
            calibrated=False,
            independent=False,
            metadata={"status": "unsupported_pending_spec", **metadata},
        )

    def __call__(self, _config: Any = None) -> "UnsupportedDetector":
        return UnsupportedDetector(
            self.capability.identifier,
            scheme=self._scheme,
            reason=self._reason,
            capability=self.capability,
        )


class UnsupportedDetector:
    """Explicit capability for a private or otherwise unavailable detector."""

    def __init__(
        self,
        identifier: str,
        *,
        scheme: Optional[str] = None,
        reason: str = _GENERIC_UNSUPPORTED_REASON,
        capability: Optional[CapabilityManifest] = None,
    ) -> None:
        self._reason = (
            reason if reason in _PUBLIC_UNSUPPORTED_REASONS else _GENERIC_UNSUPPORTED_REASON
        )
        self._scheme = scheme or identifier
        self.capability = capability or CapabilityManifest(
            identifier=identifier,
            kind="detector",
            schemes=(self._scheme,),
            description=self._reason,
            calibrated=False,
            independent=False,
            metadata={"status": "unsupported"},
        )

    def available(self) -> bool:
        return False

    def detect(self, text: str) -> DetectionEvidence:
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme=self._scheme,
            status="unsupported",
            text_characters=len(text),
            reason=self._reason,
        )


class UnicodeArtifactDetector:
    """Deterministic detector for the package's documented Unicode channel."""

    capability = CapabilityManifest(
        identifier="unicode-artifacts-v1",
        kind="detector",
        schemes=("unicode-artifacts",),
        description="Deterministic suspicious-Unicode artifact analysis.",
        calibrated=True,
        # The sanitizer and detector intentionally share one literal-codepoint
        # policy. This is exact policy verification, not an independent
        # statistical implementation.
        independent=False,
        metadata={
            "status": "deterministic_policy",
            "evidence_level": "same_policy",
            "verification_basis": "literal_codepoint_policy",
        },
    )

    def __init__(self, _config: Any = None) -> None:
        pass

    def available(self) -> bool:
        return True

    def detect(self, text: str) -> DetectionEvidence:
        report = analyze(text)
        total = int(report["unicode"]["total_flags"])
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme="unicode-artifacts",
            status="detected" if total else "not_detected",
            score=float(total),
            threshold=1.0,
            text_characters=len(text),
            details={"total_flags": total},
        )


def builtin_detector_factories() -> dict[str, Any]:
    from .reference_detectors import reference_detector_factories

    anthropic = _UnsupportedDetectorFactory(
        "anthropic-claude",
        "anthropic-claude",
        _ANTHROPIC_UNSUPPORTED_REASON,
        source="https://support.claude.com/en/articles/16266773-how-claude-marks-ai-generated-content",
        source_status="technical_detection_guidance_forthcoming",
    )
    synthid_production = _UnsupportedDetectorFactory(
        "synthid-production",
        "synthid-production",
        _SYNTHID_UNSUPPORTED_REASON,
        source="https://github.com/google-deepmind/synthid-text",
        source_status="reference_implementation_only",
    )
    factories = {
        "unicode": UnicodeArtifactDetector,
        "unicode-artifacts-v1": UnicodeArtifactDetector,
        "anthropic": anthropic,
        "anthropic-claude": anthropic,
        "claude": anthropic,
        "gemini": synthid_production,
        "gemini-production": synthid_production,
        "synthid-production": synthid_production,
    }
    factories.update(reference_detector_factories())
    return factories


def capability_of(detector: Any, fallback: str = "custom-detector") -> CapabilityManifest:
    try:
        return static_capability(detector, "detector")
    except ConfigurationError:
        return CapabilityManifest(identifier=fallback, kind="detector")


def normalize_detection(
    raw: DetectionEvidence | Mapping[str, Any] | float,
    detector: Any,
    text: str,
    *,
    fallback_name: str = "custom-detector",
) -> DetectionEvidence:
    """Normalize modern and legacy detector output without inventing certainty."""
    capability = capability_of(detector, fallback_name)
    if isinstance(raw, DetectionEvidence):
        scheme = raw.scheme if raw.scheme in capability.schemes else None
        if scheme is None and capability.schemes:
            scheme = capability.schemes[0]
        reason = raw.reason if _trusted_detector_reason(detector, capability) else None
        return replace(
            raw,
            detector=capability.identifier,
            scheme=scheme,
            text_characters=len(text),
            reason=reason,
            details=_public_evidence_details(raw.details),
        )
    if isinstance(raw, Mapping):
        status_value = raw.get("status", "insufficient_evidence")
        mapping_status = status_value if type(status_value) is str else "insufficient_evidence"
        allowed: tuple[DetectionStatus, ...] = (
            "detected",
            "not_detected",
            "insufficient_evidence",
            "unsupported",
            "configuration_mismatch",
            "detector_error",
        )
        if mapping_status not in allowed:
            mapping_status = "insufficient_evidence"
        score = raw.get("score")
        threshold = raw.get("threshold")
        reserved = {
            "detector",
            "status",
            "scheme",
            "score",
            "threshold",
            "text_characters",
            "reason",
            "schema_version",
        }
        raw_details = {key: value for key, value in raw.items() if key not in reserved}
        scheme_value = raw.get("scheme")
        scheme = (
            scheme_value
            if type(scheme_value) is str and scheme_value in capability.schemes
            else None
        )
        if scheme is None and capability.schemes:
            scheme = capability.schemes[0]
        return DetectionEvidence(
            detector=capability.identifier,
            status=cast(DetectionStatus, mapping_status),
            scheme=scheme,
            score=_finite_number(score),
            threshold=_finite_number(threshold),
            text_characters=len(text),
            reason=None,
            details=_public_evidence_details(raw_details),
        )
    numeric_score = _finite_number(raw)
    if numeric_score is None:
        raise TypeError("detector score must be a finite number") from None
    score = numeric_score
    threshold = _public_threshold(detector)
    if threshold is not None:
        legacy_status: DetectionStatus = "detected" if score >= threshold else "not_detected"
    else:
        legacy_status = "insufficient_evidence"
    return DetectionEvidence(
        detector=capability.identifier,
        scheme=capability.schemes[0] if capability.schemes else None,
        status=legacy_status,
        score=score,
        threshold=threshold,
        text_characters=len(text),
        reason=None if threshold is not None else "legacy detector did not declare a threshold",
    )


def run_detector(
    detector: Any,
    text: str,
    *,
    fallback_name: str = "custom-detector",
    config: Any = None,
) -> DetectionEvidence:
    checkpoint()
    try:
        capability = require_extension(detector, "detector", config)
    except PermissionError:
        capability = capability_of(detector, fallback_name)
        return DetectionEvidence(
            detector=capability.identifier,
            scheme=capability.schemes[0] if capability.schemes else None,
            status="configuration_mismatch",
            threshold=_public_threshold(detector),
            text_characters=len(text),
            reason="detector extension requirements are not explicitly permitted",
        )
    except ConfigurationError:
        return DetectionEvidence(
            detector=fallback_name,
            status="configuration_mismatch",
            text_characters=len(text),
            reason="detector has no valid static capability manifest",
        )
    if config is not None:
        if capability.network_required and not config.allow_remote_processing:
            return DetectionEvidence(
                detector=capability.identifier,
                scheme=capability.schemes[0] if capability.schemes else None,
                status="configuration_mismatch",
                threshold=_public_threshold(detector),
                text_characters=len(text),
                reason="detector requires explicit remote-processing consent",
            )
        if capability.model_download_possible and not config.allow_model_download:
            return DetectionEvidence(
                detector=capability.identifier,
                scheme=capability.schemes[0] if capability.schemes else None,
                status="configuration_mismatch",
                threshold=_public_threshold(detector),
                text_characters=len(text),
                reason="detector requires explicit model-download consent",
            )
    if len(text) < capability.minimum_characters:
        return DetectionEvidence(
            detector=capability.identifier,
            scheme=capability.schemes[0] if capability.schemes else None,
            status="insufficient_evidence",
            text_characters=len(text),
            reason=f"detector requires at least {capability.minimum_characters} characters",
        )
    try:
        usage_snapshot, accounting = begin_extension_usage(capability)
        if hasattr(detector, "available"):
            available = detector.available()
            if type(available) is not bool:
                raise TypeError("detector availability must be boolean")
        else:
            available = True
        if not available:
            # UnsupportedDetector carries the precise reason through detect().
            if isinstance(detector, UnsupportedDetector):
                return detector.detect(text)
            return DetectionEvidence(
                detector=capability.identifier,
                scheme=capability.schemes[0] if capability.schemes else None,
                status="unsupported",
                text_characters=len(text),
                reason="detector is unavailable in the active environment",
            )
        evidence = normalize_detection(
            detector.detect(text), detector, text, fallback_name=fallback_name
        )
        checkpoint()
        usage_error = extension_usage_error(
            usage_snapshot,
            network_required=capability.network_required,
            resource_accounting=accounting,
        )
        if usage_error is not None:
            return DetectionEvidence(
                detector=capability.identifier,
                scheme=capability.schemes[0] if capability.schemes else None,
                status="configuration_mismatch",
                threshold=_public_threshold(detector),
                text_characters=len(text),
                reason=usage_error,
            )
        return evidence
    except ResourceBudgetExceeded:
        raise
    except Exception as exc:
        return DetectionEvidence(
            detector=capability.identifier,
            scheme=capability.schemes[0] if capability.schemes else None,
            status="detector_error",
            text_characters=len(text),
            reason=safe_error("detector", exc),
        )
