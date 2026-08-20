"""Built-in assurance detectors and result normalization."""

from __future__ import annotations

import inspect
import math
import re
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
from .unicode import UNICODE_POLICY_SHA256, analyze

_PUBLIC_EVIDENCE_DETAIL_KEYS = {
    "configuration_sha256",
    "effective_tokens",
    "green_hits",
    "localization",
    "mean_g_value",
    "mismatch_fields",
    "p_value",
    "protocol_version",
    "reference_only",
    "reason_code",
    "reported_status",
    "score_direction",
    "threshold_operator",
    "total_flags",
    "vendor_equivalent",
    "z_score",
}
_GENERIC_UNSUPPORTED_REASON = "No public, independently usable detector is available."
_ANTHROPIC_UNSUPPORTED_REASON = (
    "Anthropic describes its supported Claude marking as a version of SynthID-Text "
    "but has not published the deployed configuration, keys, calibrated thresholds, "
    "or detector contract."
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
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PROTOCOL_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _public_evidence_details(
    details: Mapping[str, Any], *, text_characters: Optional[int] = None
) -> dict[str, Any]:
    """Keep only documented evidence fields, never arbitrary detector payloads."""
    public: dict[str, Any] = {}
    for key, value in details.items():
        if key not in _PUBLIC_EVIDENCE_DETAIL_KEYS:
            continue
        if key == "localization" and type(value) in (list, tuple):
            spans: list[dict[str, Any]] = []
            for item in value[:4096]:
                if type(item) is not dict:
                    continue
                start = item.get("start")
                end = item.get("end")
                if (
                    type(start) is not int
                    or type(end) is not int
                    or start < 0
                    or end <= start
                    or (text_characters is not None and end > text_characters)
                ):
                    continue
                span: dict[str, Any] = {"start": start, "end": end}
                for numeric_key in ("score", "p_value", "threshold"):
                    numeric = _finite_number(item.get(numeric_key))
                    if numeric is not None and (numeric_key != "p_value" or 0.0 <= numeric <= 1.0):
                        span[numeric_key] = numeric
                spans.append(span)
            public[key] = spans
        elif key == "mismatch_fields" and type(value) in (list, tuple):
            allowed = {
                "configuration_sha256",
                "detector",
                "protocol_version",
                "scheme",
                "score_direction",
                "threshold_operator",
                "threshold",
                "tokenizer_revision",
            }
            public[key] = sorted({item for item in value if type(item) is str and item in allowed})
        elif key == "configuration_sha256" and type(value) is str and _SHA256_RE.fullmatch(value):
            public[key] = value.lower()
        elif key in {"effective_tokens", "total_flags"} and type(value) is int and value >= 0:
            public[key] = value
        elif key in {"green_hits", "mean_g_value", "z_score"}:
            numeric = _finite_number(value)
            if numeric is not None:
                public[key] = numeric
        elif key == "p_value":
            numeric = _finite_number(value)
            if numeric is not None and 0.0 <= numeric <= 1.0:
                public[key] = numeric
        elif key in {"reference_only", "vendor_equivalent"} and type(value) is bool:
            public[key] = value
        elif key == "score_direction" and value in {"higher", "lower"}:
            public[key] = value
        elif key == "threshold_operator" and value in {">", ">=", "<", "<="}:
            public[key] = value
        elif key == "reported_status" and value in {
            "detected",
            "not_detected",
            "insufficient_evidence",
            "unsupported",
            "configuration_mismatch",
            "detector_error",
        }:
            public[key] = value
        elif key == "protocol_version" and type(value) is str and _PROTOCOL_RE.fullmatch(value):
            public[key] = value
        elif key == "reason_code" and type(value) is str and _REASON_CODE_RE.fullmatch(value):
            # Extension-provided reason strings can be derived from source
            # text. Preserve only a fixed host code in public evidence.
            public[key] = "detector_reported_reason"
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


def _decision_contract_mismatch(
    *,
    status: DetectionStatus,
    score: Optional[float],
    threshold: Optional[float],
    details: Mapping[str, Any],
    capability: CapabilityManifest,
) -> bool:
    """Reject self-contradictory or capability-drifting detector decisions."""
    declared_configuration = capability.metadata.get("configuration_sha256")
    reported_configuration = details.get("configuration_sha256")
    if reported_configuration is not None and reported_configuration != declared_configuration:
        return True

    declared_threshold = _finite_number(capability.metadata.get("threshold"))
    if declared_threshold is not None and threshold != declared_threshold:
        return True
    declared_direction = capability.metadata.get("score_direction")
    reported_direction = details.get("score_direction")
    if (
        type(declared_direction) is str
        and declared_direction in {"higher", "lower"}
        and reported_direction != declared_direction
    ):
        return True
    declared_operator = capability.metadata.get("threshold_operator")
    reported_operator = details.get("threshold_operator")
    if (
        type(declared_operator) is str
        and declared_operator in {">", ">=", "<", "<="}
        and reported_operator != declared_operator
    ):
        return True

    if status not in {"detected", "not_detected"} or score is None or threshold is None:
        return False
    if reported_direction not in {"higher", "lower"}:
        return False
    if reported_operator is None:
        reported_operator = ">=" if reported_direction == "higher" else "<="
    if reported_operator not in {">", ">=", "<", "<="}:
        return True
    if (reported_operator in {">", ">="}) != (reported_direction == "higher"):
        return True
    positive = {
        ">": score > threshold,
        ">=": score >= threshold,
        "<": score < threshold,
        "<=": score <= threshold,
    }[reported_operator]
    return (status == "detected") != positive


def _bind_declared_decision_details(
    details: Mapping[str, Any], capability: CapabilityManifest
) -> dict[str, Any]:
    """Project static decision fields into each normalized observation."""
    bound = dict(details)
    configuration = capability.metadata.get("configuration_sha256")
    if "configuration_sha256" not in bound and (
        type(configuration) is str and _SHA256_RE.fullmatch(configuration)
    ):
        bound["configuration_sha256"] = configuration.lower()
    direction = capability.metadata.get("score_direction")
    if (
        "score_direction" not in bound
        and type(direction) is str
        and direction in {"higher", "lower"}
    ):
        bound["score_direction"] = direction
    operator = capability.metadata.get("threshold_operator")
    if (
        "threshold_operator" not in bound
        and type(operator) is str
        and operator in {">", ">=", "<", "<="}
    ):
        bound["threshold_operator"] = operator
    return bound


def _configuration_mismatch(capability: CapabilityManifest, text: str) -> DetectionEvidence:
    return DetectionEvidence(
        detector=capability.identifier,
        status="configuration_mismatch",
        text_characters=len(text),
        reason="detector response contradicts its declared decision contract",
    )


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
            "configuration_sha256": UNICODE_POLICY_SHA256,
            "score_direction": "higher",
            "threshold": 1.0,
            "threshold_operator": ">=",
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
            details={
                "configuration_sha256": UNICODE_POLICY_SHA256,
                "score_direction": "higher",
                "threshold_operator": ">=",
                "total_flags": total,
            },
        )


def builtin_detector_factories() -> dict[str, Any]:
    from .reference_detectors import reference_detector_factories

    anthropic = _UnsupportedDetectorFactory(
        "anthropic-claude",
        "anthropic-claude",
        _ANTHROPIC_UNSUPPORTED_REASON,
        source="https://www.anthropic.com/news/claude-text-watermark",
        source_status="scheme_family_disclosed_detector_contract_pending",
        scheme_family="synthid-text",
        deployment_configuration_status="not_public",
        detector_api_status="forthcoming",
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
        if raw.status not in {
            "detected",
            "not_detected",
            "insufficient_evidence",
            "unsupported",
            "configuration_mismatch",
            "detector_error",
        }:
            return _configuration_mismatch(capability, text)
        if raw.scheme is not None and raw.scheme not in capability.schemes:
            return DetectionEvidence(
                detector=capability.identifier,
                status="configuration_mismatch",
                text_characters=len(text),
                reason="detector response scheme does not match its declared capability",
            )
        scheme = raw.scheme
        if scheme is None and capability.schemes:
            scheme = capability.schemes[0]
        public_details = _bind_declared_decision_details(
            _public_evidence_details(raw.details, text_characters=len(text)), capability
        )
        score = _finite_number(raw.score)
        threshold = _finite_number(raw.threshold)
        if (raw.score is not None and score is None) or (
            raw.threshold is not None and threshold is None
        ):
            return _configuration_mismatch(capability, text)
        if (
            "score_direction" in raw.details
            and raw.details.get("score_direction") not in {"higher", "lower"}
        ) or (
            "threshold_operator" in raw.details
            and raw.details.get("threshold_operator") not in {">", ">=", "<", "<="}
        ):
            return _configuration_mismatch(capability, text)
        if _decision_contract_mismatch(
            status=raw.status,
            score=score,
            threshold=threshold,
            details=public_details,
            capability=capability,
        ):
            return _configuration_mismatch(capability, text)
        reason = raw.reason if _trusted_detector_reason(detector, capability) else None
        return replace(
            raw,
            detector=capability.identifier,
            scheme=scheme,
            score=score,
            threshold=threshold,
            text_characters=len(text),
            reason=reason,
            details=public_details,
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
        if scheme_value is not None and (
            type(scheme_value) is not str or scheme_value not in capability.schemes
        ):
            return DetectionEvidence(
                detector=capability.identifier,
                status="configuration_mismatch",
                text_characters=len(text),
                reason="detector response scheme does not match its declared capability",
            )
        scheme = (
            scheme_value
            if type(scheme_value) is str and scheme_value in capability.schemes
            else None
        )
        if scheme is None and capability.schemes:
            scheme = capability.schemes[0]
        public_details = _bind_declared_decision_details(
            _public_evidence_details(raw_details, text_characters=len(text)), capability
        )
        public_score = _finite_number(score)
        public_threshold = _finite_number(threshold)
        if (score is not None and public_score is None) or (
            threshold is not None and public_threshold is None
        ):
            return _configuration_mismatch(capability, text)
        if (
            "score_direction" in raw_details
            and raw_details.get("score_direction") not in {"higher", "lower"}
        ) or (
            "threshold_operator" in raw_details
            and raw_details.get("threshold_operator") not in {">", ">=", "<", "<="}
        ):
            return _configuration_mismatch(capability, text)
        normalized_status = cast(DetectionStatus, mapping_status)
        if _decision_contract_mismatch(
            status=normalized_status,
            score=public_score,
            threshold=public_threshold,
            details=public_details,
            capability=capability,
        ):
            return _configuration_mismatch(capability, text)
        return DetectionEvidence(
            detector=capability.identifier,
            status=normalized_status,
            scheme=scheme,
            score=public_score,
            threshold=public_threshold,
            text_characters=len(text),
            reason=None,
            details=public_details,
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
        from .command_detector import CommandDetector

        if type(detector) is CommandDetector:
            available = CommandDetector.available(detector)
        else:
            try:
                detector_state = object.__getattribute__(detector, "__dict__")
            except Exception:
                detector_state = None
            if type(detector_state) is dict and any(
                name in detector_state for name in ("detect", "available")
            ):
                return DetectionEvidence(
                    detector=capability.identifier,
                    scheme=capability.schemes[0] if capability.schemes else None,
                    status="configuration_mismatch",
                    threshold=_public_threshold(detector),
                    text_characters=len(text),
                    reason="detector behavior cannot be supplied through instance shadowing",
                )
            available = detector.available() if hasattr(detector, "available") else True
        if type(available) is not bool:
            raise TypeError("detector availability must be boolean")
        if not available:
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
        raw_evidence = (
            CommandDetector.detect(detector, text)
            if type(detector) is CommandDetector
            else detector.detect(text)
        )
        evidence = normalize_detection(raw_evidence, detector, text, fallback_name=fallback_name)
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
