"""Quality-constrained text-watermark robustness research toolkit.

Two watermark families:

1. Unicode steganography (zero-width chars, variation selectors, Tags-block
   payloads, bidi controls, soft hyphens, exotic spaces, homoglyphs) — removed
   deterministically by :func:`sanitize`.
2. Statistical generation-time watermarks (KGW, Unigram, EXP, SynthID-style) —
   experimentally mitigated by rewriting, with removal claimed only when a
   named independent detector verifies the configured outcome.
"""

from __future__ import annotations

from ._version import __version__
from .assurance import assure, inspect, verify
from .assurance_api import (
    ConsentRequiredError,
    PlanMismatchError,
    apply_plan,
    create_plan,
    inspect_text,
    verify_text,
)
from .command_detector import (
    COMMAND_DETECTOR_PROTOCOL_VERSION,
    CommandDetector,
    CommandDetectorConformanceError,
    CommandDetectorContractError,
    CommandDetectorError,
    CommandDetectorExecutionError,
    CommandDetectorFactory,
    DetectorConformanceCase,
    DetectorConformanceReport,
    DetectorGoldenVector,
    assert_command_detector_conformance,
    command_detector_manifest,
    detector_configuration_sha256,
    make_command_detector_factory,
    run_command_detector_conformance,
)
from .config import DewatermarkConfig, configure, get_config, reset_config
from .detectors import UnicodeArtifactDetector, UnsupportedDetector
from .exceptions import (
    AdapterError,
    BackendUnavailableError,
    ConfigurationError,
    DewatermarkError,
    QualityRejectedError,
    RemoteProcessingDeniedError,
)
from .models import (
    BatchItemResult,
    CapabilityManifest,
    DetectionEvidence,
    DetectionStatus,
    EvidenceReceipt,
    ExecutionPlan,
    RemovalMode,
    RemovalReport,
    SanitizeProfile,
    StageResult,
    TransformationStatus,
    VerificationEvidence,
    VerificationStatus,
)
from .pipeline import RemovalResult
from .pipeline import aremove as _aremove
from .pipeline import remove as _remove
from .pipeline import remove_many as _remove_many
from .providers import (
    detector_errors,
    detector_manifest,
    get_detector,
    get_provider,
    list_detectors,
    list_providers,
    provider_errors,
    provider_manifest,
    register_detector,
    register_provider,
)
from .quality import QualityReport, evaluate_quality
from .runtime import capabilities, plan
from .scanner import (
    ScanEdit,
    ScanFinding,
    ScanReport,
    baseline_fingerprints,
    changed_lines_from_unified_diff,
    scan_paths,
    scan_text,
    to_sarif,
)
from .schemas import (
    command_detector_schema,
    detector_capability_schema,
    evidence_receipt_schema,
    public_schema,
    removal_result_schema,
)
from .scoring import ScorerUnavailable, clear_cache, self_information, surrogate_score
from .unicode import UNICODE_POLICY_VERSION, reverse_edits, sanitize_with_edits
from .unicode import analyze as _analyze
from .unicode import sanitize as _sanitize_with_report

__all__ = [
    "__version__",
    "AdapterError",
    "BackendUnavailableError",
    "BatchItemResult",
    "CapabilityManifest",
    "COMMAND_DETECTOR_PROTOCOL_VERSION",
    "CommandDetector",
    "CommandDetectorConformanceError",
    "CommandDetectorContractError",
    "CommandDetectorError",
    "CommandDetectorExecutionError",
    "CommandDetectorFactory",
    "ConfigurationError",
    "ConsentRequiredError",
    "DetectionEvidence",
    "DetectionStatus",
    "DetectorConformanceCase",
    "DetectorConformanceReport",
    "DetectorGoldenVector",
    "DewatermarkConfig",
    "Dewatermark",
    "DewatermarkError",
    "EvidenceReceipt",
    "ExecutionPlan",
    "RemovalMode",
    "RemovalReport",
    "RemovalResult",
    "RemoteProcessingDeniedError",
    "QualityRejectedError",
    "QualityReport",
    "ScorerUnavailable",
    "SanitizeProfile",
    "ScanEdit",
    "StageResult",
    "TransformationStatus",
    "UNICODE_POLICY_VERSION",
    "UnicodeArtifactDetector",
    "UnsupportedDetector",
    "VerificationEvidence",
    "VerificationStatus",
    "PlanMismatchError",
    "apply_plan",
    "assert_command_detector_conformance",
    "aremove",
    "analyze",
    "assure",
    "baseline_fingerprints",
    "capabilities",
    "clear_cache",
    "changed_lines_from_unified_diff",
    "command_detector_manifest",
    "command_detector_schema",
    "configure",
    "create_plan",
    "detector_errors",
    "detector_configuration_sha256",
    "detector_capability_schema",
    "detector_manifest",
    "evaluate_quality",
    "evidence_receipt_schema",
    "get_detector",
    "get_provider",
    "get_config",
    "inspect_text",
    "inspect",
    "list_detectors",
    "list_providers",
    "make_command_detector_factory",
    "plan",
    "provider_errors",
    "provider_manifest",
    "public_schema",
    "register_detector",
    "register_provider",
    "removal_result_schema",
    "remove",
    "remove_many",
    "reset_config",
    "reverse_edits",
    "run_command_detector_conformance",
    "sanitize",
    "sanitize_with_edits",
    "ScanFinding",
    "ScanReport",
    "scan_paths",
    "scan_text",
    "to_sarif",
    "verify_text",
    "verify",
    "self_information",
    "surrogate_score",
]


def sanitize(text: str, profile: SanitizeProfile = "safe") -> str:
    """Strip/normalize unicode steganography; returns just the cleaned string.

    The tuple-returning variant (cleaned_text, by_category_counts) is available
    as ``dewatermark.unicode.sanitize``.
    """
    return _sanitize_with_report(text, profile=profile)[0]


def analyze(text: str) -> dict:
    """Return a versioned forensic analysis without changing the source text."""
    return {"schema_version": "1.0", **_analyze(text)}


def remove(
    text: str,
    mode: RemovalMode = "auto",
    passes: int = 2,
    epsilon: float = 0.3,
    beta: float = 6.0,
    best_of: int = 3,
    detector: object | str | None = None,
    config: DewatermarkConfig | None = None,
) -> RemovalResult:
    """Run the full removal pipeline with the module-level (env) config."""
    return _remove(
        text,
        mode=mode,
        passes=passes,
        epsilon=epsilon,
        beta=beta,
        best_of=best_of,
        detector=detector,
        config=config,
    )


def remove_many(texts, mode: RemovalMode = "auto", config=None, **options):
    """Process multiple texts concurrently while preserving order."""
    return _remove_many(texts, mode=mode, config=config, **options)


async def aremove(text: str, mode: RemovalMode = "auto", config=None, **options):
    """Asynchronously process one text without blocking the event loop."""
    return await _aremove(text, mode=mode, config=config, **options)


class Dewatermark:
    """Convenience wrapper carrying an explicit :class:`DewatermarkConfig`."""

    def __init__(self, config: DewatermarkConfig | None = None):
        self.config = config

    def sanitize(self, text: str, profile: SanitizeProfile = "safe") -> str:
        return _sanitize_with_report(text, profile=profile)[0]

    def analyze(self, text: str) -> dict:
        return analyze(text)

    def inspect(self, text: str, detector: str = "unicode") -> dict:
        """Return a content-bound, non-mutating assurance inspection."""
        return inspect_text(text, detector, config=self.config)

    def create_plan(self, text: str, mode: RemovalMode = "auto", **options) -> dict:
        """Create a side-effect-free plan bound to this instance's config."""
        return create_plan(text, mode, config=self.config, **options)

    def apply_plan(
        self, text: str, plan_digest: str, mode: RemovalMode = "auto", **options
    ) -> dict:
        """Apply an exact reviewed plan with explicit consent options."""
        return apply_plan(text, plan_digest, mode, config=self.config, **options)

    def verify(
        self,
        source_text: str,
        candidate_text: str,
        detector: str = "unicode-artifacts-v1",
    ):
        """Verify a candidate using a named detector or explicitly abstain."""
        return verify_text(source_text, candidate_text, detector, config=self.config)

    def remove(
        self,
        text: str,
        mode: RemovalMode = "auto",
        passes: int = 2,
        epsilon: float = 0.3,
        beta: float = 6.0,
        best_of: int = 3,
        detector: object | str | None = None,
    ) -> RemovalResult:
        return _remove(
            text,
            mode=mode,
            passes=passes,
            epsilon=epsilon,
            beta=beta,
            best_of=best_of,
            detector=detector,
            config=self.config,
        )

    def assure(
        self,
        text: str,
        mode: RemovalMode = "auto",
        detector: object | str | None = None,
        **options,
    ):
        """Run detector-scoped transformation and return an evidence receipt."""
        return assure(text, mode=mode, detector=detector, config=self.config, **options)

    def surrogate_score(self, text: str) -> dict:
        return surrogate_score(text, config=self.config)

    def remove_many(self, texts, mode: RemovalMode = "auto", **options):
        return _remove_many(texts, mode=mode, config=self.config, **options)

    async def aremove(self, text: str, mode: RemovalMode = "auto", **options):
        return await _aremove(text, mode=mode, config=self.config, **options)

    def capabilities(self) -> dict:
        return capabilities(self.config)

    def plan(self, mode: RemovalMode = "auto") -> ExecutionPlan:
        return plan(mode, self.config)

    def close(self) -> None:
        clear_cache()

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
