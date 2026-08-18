"""Public inspect, verify, and detector-scoped assurance helpers."""

from __future__ import annotations

import math
from typing import Any, Optional

from .config import DewatermarkConfig, resolve
from .detectors import UnicodeArtifactDetector, capability_of, run_detector
from .exceptions import ConfigurationError
from .extension_safety import (
    enforce_consent,
    manifests_match,
    safe_extension_config,
    static_capability,
)
from .models import DetectionEvidence, RemovalMode, VerificationEvidence, VerificationStatus
from .providers import detector_manifest, get_detector
from .request_context import (
    RequestContext,
    begin_extension_usage,
    current_request_context,
    request_scope,
)


def _finite_number(value: Any) -> Optional[float]:
    if type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _threshold_decision(score: float, threshold: float, operator: str) -> bool:
    if operator == ">":
        return score > threshold
    if operator == ">=":
        return score >= threshold
    if operator == "<":
        return score < threshold
    return score <= threshold


def resolve_detector(
    detector: str | Any | None, config: DewatermarkConfig
) -> tuple[Any | None, Optional[str]]:
    """Resolve a detector object without running detection or using the network."""
    selected = detector if detector is not None else getattr(config, "detector_provider", None)
    if selected is None:
        return None, None
    if not isinstance(selected, str):
        capability = static_capability(selected, "detector")
        if (
            capability.identifier == "unicode-artifacts-v1"
            and type(selected) is not UnicodeArtifactDetector
        ):
            raise ConfigurationError(
                "the canonical Unicode detector identifier is reserved for the built-in detector"
            )
        return selected, capability.identifier
    declared = detector_manifest(selected)
    if declared is None:
        raise ConfigurationError("detector must be explicitly loaded with a static manifest")
    enforce_consent(declared, config)
    begin_extension_usage(declared)
    factory = get_detector(selected)
    if declared.identifier == "unicode-artifacts-v1" and factory is not UnicodeArtifactDetector:
        raise ConfigurationError(
            "the canonical Unicode detector identifier is reserved for the built-in detector"
        )
    instance = factory(safe_extension_config(config))
    actual = static_capability(instance, "detector")
    if not manifests_match(declared, actual):
        raise ConfigurationError("detector factory and instance capability manifests differ")
    if (
        actual.identifier == "unicode-artifacts-v1"
        and type(instance) is not UnicodeArtifactDetector
    ):
        raise ConfigurationError(
            "the canonical Unicode detector identifier is reserved for the built-in detector"
        )
    return instance, actual.identifier


def inspect(
    text: str,
    detector: str | Any = "unicode",
    *,
    config: Optional[DewatermarkConfig] = None,
) -> DetectionEvidence:
    """Inspect text with one explicitly named detector, without changing it."""
    if not isinstance(text, str) or not text:
        raise ValueError("'text' must be a non-empty string.")
    cfg = resolve(config)

    def execute() -> DetectionEvidence:
        instance, name = resolve_detector(detector, cfg)
        assert instance is not None and name is not None
        return run_detector(instance, text, fallback_name=name, config=cfg)

    if current_request_context() is not None:
        return execute()
    with request_scope(RequestContext.from_config(cfg)):
        return execute()


def verify(
    source: str,
    candidate: str,
    detector: str | Any,
    *,
    config: Optional[DewatermarkConfig] = None,
) -> VerificationEvidence:
    """Verify a transformation against a named compatible detector."""
    if not source or not candidate:
        raise ValueError("source and candidate must be non-empty strings")
    cfg = resolve(config)

    def execute() -> VerificationEvidence:
        instance, name = resolve_detector(detector, cfg)
        assert instance is not None and name is not None
        before = run_detector(instance, source, fallback_name=name, config=cfg)
        after = run_detector(instance, candidate, fallback_name=name, config=cfg)
        return evaluate_verification(before, after, instance, detector_name=name)

    if current_request_context() is not None:
        return execute()
    with request_scope(RequestContext.from_config(cfg)):
        return execute()


def evaluate_verification(
    before: DetectionEvidence,
    after: DetectionEvidence,
    detector: Any,
    *,
    detector_name: Optional[str] = None,
) -> VerificationEvidence:
    """Conclude only what paired evidence from a declared detector supports."""
    capability = capability_of(detector, detector_name or before.detector)
    name = capability.identifier
    before_configuration = before.details.get("configuration_sha256")
    before_direction = before.details.get("score_direction")
    before_operator = before.details.get("threshold_operator")
    declared_configuration = capability.metadata.get("configuration_sha256")
    declared_direction = capability.metadata.get("score_direction")
    declared_operator = capability.metadata.get("threshold_operator")
    declared_threshold = capability.metadata.get("threshold")
    declared_threshold_number = _finite_number(declared_threshold)
    from .command_detector import CommandDetector

    command_contract_bound = not isinstance(detector, CommandDetector) or (
        type(detector) is CommandDetector and detector._contract.threshold_operator_explicit
    )
    before_score = _finite_number(before.score)
    after_score = _finite_number(after.score)
    threshold = _finite_number(before.threshold)
    after_threshold = _finite_number(after.threshold)
    decision_positive: Optional[tuple[bool, bool]] = None
    if (
        before_score is not None
        and after_score is not None
        and threshold is not None
        and type(before_operator) is str
        and before_operator in {">", ">=", "<", "<="}
    ):
        decision_positive = (
            _threshold_decision(before_score, threshold, before_operator),
            _threshold_decision(after_score, threshold, before_operator),
        )

    paired_contract_matches = (
        command_contract_bound
        and before.detector == after.detector == capability.identifier
        and bool(capability.schemes)
        and type(before.scheme) is str
        and bool(before.scheme)
        and type(after.scheme) is str
        and before.scheme == after.scheme
        and before.scheme in capability.schemes
        and threshold is not None
        and after_threshold is not None
        and threshold == after_threshold
        and type(before_configuration) is str
        and len(before_configuration) == 64
        and all(character in "0123456789abcdef" for character in before_configuration)
        and type(before_direction) is str
        and before_direction in {"higher", "lower"}
        and type(before_operator) is str
        and before_operator in {">", ">=", "<", "<="}
        and (before_operator in {">", ">="}) == (before_direction == "higher")
        and decision_positive
        == (
            before.status == "detected",
            after.status == "detected",
        )
        and type(declared_configuration) is str
        and len(declared_configuration) == 64
        and all(character in "0123456789abcdef" for character in declared_configuration)
        and before_configuration == declared_configuration
        and type(declared_direction) is str
        and declared_direction in {"higher", "lower"}
        and before_direction == declared_direction
        and type(declared_operator) is str
        and declared_operator in {">", ">=", "<", "<="}
        and before_operator == declared_operator
        and declared_threshold_number is not None
        and threshold == declared_threshold_number
        and all(
            before.details.get(field) == after.details.get(field)
            for field in (
                "configuration_sha256",
                "score_direction",
                "threshold_operator",
            )
        )
    )
    reserved_unicode_collision = (
        capability.identifier == "unicode-artifacts-v1"
        and type(detector) is not UnicodeArtifactDetector
    )
    deterministic_unicode_policy = (
        type(detector) is UnicodeArtifactDetector
        and capability.calibrated
        and capability.identifier == "unicode-artifacts-v1"
        and "unicode-artifacts" in capability.schemes
        and capability.metadata.get("verification_basis") == "literal_codepoint_policy"
    )
    status: VerificationStatus
    if before.status == "detector_error" or after.status == "detector_error":
        status = "failed"
        reason = "the named detector failed"
    elif not paired_contract_matches:
        status = "not_verifiable"
        reason = "paired detector evidence uses incompatible decision contracts"
    elif before.status == "detected" and after.status == "not_detected":
        if deterministic_unicode_policy or (
            capability.calibrated and capability.independent and not reserved_unicode_collision
        ):
            status = "verified_cleared"
            reason = None
        else:
            status = "not_verifiable"
            reason = (
                "the canonical Unicode detector identifier is reserved for the built-in detector"
                if reserved_unicode_collision
                else "detector is not declared calibrated and independent"
            )
    elif after.status == "detected":
        status = "residual"
        reason = "the named detector still reports evidence"
    else:
        status = "not_verifiable"
        reason = "verification requires compatible positive evidence before and none after"
    return VerificationEvidence(
        status=status,
        detector=name,
        before=before,
        after=after,
        reason=reason,
    )


def assure(
    text: str,
    *,
    mode: RemovalMode = "auto",
    detector: str | Any | None = None,
    config: Optional[DewatermarkConfig] = None,
    **options: Any,
):
    """Transform and return detector/quality evidence in one receipt-bearing result."""
    from .pipeline import remove

    return remove(text, mode=mode, detector=detector, config=config, **options)
