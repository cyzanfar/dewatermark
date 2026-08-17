"""Public inspect, verify, and detector-scoped assurance helpers."""

from __future__ import annotations

from typing import Any, Optional

from .config import DewatermarkConfig, resolve
from .detectors import capability_of, run_detector
from .exceptions import ConfigurationError
from .extension_safety import (
    enforce_consent,
    manifests_match,
    safe_extension_config,
    static_capability,
)
from .models import DetectionEvidence, RemovalMode, VerificationEvidence, VerificationStatus
from .providers import detector_manifest, get_detector


def resolve_detector(
    detector: str | Any | None, config: DewatermarkConfig
) -> tuple[Any | None, Optional[str]]:
    """Resolve a detector object without running detection or using the network."""
    selected = detector if detector is not None else getattr(config, "detector_provider", None)
    if selected is None:
        return None, None
    if not isinstance(selected, str):
        capability = static_capability(selected, "detector")
        return selected, capability.identifier
    declared = detector_manifest(selected)
    if declared is None:
        raise ConfigurationError(
            f"detector {selected!r} must be explicitly loaded with a static manifest"
        )
    enforce_consent(declared, config)
    factory = get_detector(selected)
    instance = factory(safe_extension_config(config))
    actual = static_capability(instance, "detector")
    if not manifests_match(declared, actual):
        raise ConfigurationError("detector factory and instance capability manifests differ")
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
    instance, name = resolve_detector(detector, cfg)
    assert instance is not None and name is not None
    return run_detector(instance, text, fallback_name=name, config=cfg)


def verify(
    source: str,
    candidate: str,
    detector: str | Any,
    *,
    config: Optional[DewatermarkConfig] = None,
) -> VerificationEvidence:
    """Verify a transformation against a calibrated, independent detector."""
    if not source or not candidate:
        raise ValueError("source and candidate must be non-empty strings")
    cfg = resolve(config)
    instance, name = resolve_detector(detector, cfg)
    assert instance is not None and name is not None
    before = run_detector(instance, source, fallback_name=name, config=cfg)
    after = run_detector(instance, candidate, fallback_name=name, config=cfg)
    return evaluate_verification(before, after, instance, detector_name=name)


def evaluate_verification(
    before: DetectionEvidence,
    after: DetectionEvidence,
    detector: Any,
    *,
    detector_name: Optional[str] = None,
) -> VerificationEvidence:
    """Conclude only what paired evidence from a declared detector supports."""
    capability = capability_of(detector, detector_name or before.detector)
    name = detector_name or capability.identifier
    if before.status == "detected" and after.status == "not_detected":
        if capability.calibrated and capability.independent:
            status: VerificationStatus = "verified_cleared"
            reason = None
        else:
            status = "not_verifiable"
            reason = "detector is not declared calibrated and independent"
    elif after.status == "detected":
        status = "residual"
        reason = "the named detector still reports evidence"
    elif before.status == "detector_error" or after.status == "detector_error":
        status = "failed"
        reason = "the named detector failed"
    else:
        status = "not_verifiable"
        reason = (
            "verification requires positive evidence before and no evidence after "
            "from a calibrated independent detector"
        )
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
