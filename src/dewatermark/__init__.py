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

from typing import Sequence

from ._version import __version__
from .adapter_packs import adapter_pack_manifest, list_adapter_packs, materialize_adapter_pack
from .agent_skill import agent_skill_path, materialize_agent_skill
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
from .command_strategy import (
    COMMAND_STRATEGY_PROTOCOL_VERSION,
    CommandStrategy,
    CommandStrategyConsentError,
    CommandStrategyContractError,
    CommandStrategyError,
    CommandStrategyExecutionError,
    CommandStrategyFactory,
    command_strategy_manifest,
    make_command_strategy_factory,
    strategy_configuration_sha256,
)
from .config import DewatermarkConfig, configure, get_config, reset_config
from .detector_session import (
    DetectorObservation,
    DetectorPolicyDriftError,
    DetectorQueryBudgetExceeded,
    DetectorSession,
    DetectorSessionScopeError,
    SessionVerification,
    SignalSpan,
    VerifierObservation,
)
from .detector_tools import (
    DetectorDoctorCheck,
    DetectorDoctorReport,
    DetectorInventoryEntry,
    conform_reference_detectors,
    discover_detector_capabilities,
    doctor_detectors,
)
from .detectors import UnicodeArtifactDetector, UnsupportedDetector
from .exceptions import (
    AdapterError,
    BackendUnavailableError,
    ConfigurationError,
    DewatermarkError,
    QualityRejectedError,
    RemoteProcessingDeniedError,
)
from .localization import (
    LocalizationReport,
    LocalizedSignal,
    localize,
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
from .optimizer import (
    CandidateProposal,
    CandidateStrategy,
    DetectorFeedback,
    MitigationReceipt,
    MitigationResult,
    SearchLimits,
    SearchTraceEvent,
    StrategyBinding,
    StrategyContext,
    mitigate,
)
from .pipeline import RemovalResult
from .pipeline import aremove as _aremove
from .pipeline import remove as _remove
from .pipeline import remove_many as _remove_many
from .profiles import (
    MITIGATION_PROFILE_SCHEMA_VERSION,
    MitigationProfile,
    MitigationProfileConsentError,
    MitigationProfileError,
    build_mitigation_profile,
    inspect_mitigation_profile,
    load_mitigation_profile,
    mitigate_with_profile,
    mitigation_profile_sha256,
    quality_policy_manifest,
    quality_policy_sha256,
    validate_mitigation_profile,
)
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
from .quality import (
    QualityGateBinding,
    QualityGateDecision,
    QualityGateOutcome,
    QualityReport,
    evaluate_quality,
)
from .quality_gates import (
    AtomicClaimQAGate,
    BidirectionalNLIGate,
    CachedTransformersNLIAdapter,
    CitationGroundingGate,
    EntityLinkingGate,
    PairwiseAssessment,
    TaskContractGate,
    quality_gate_conformance,
)
from .reference_detectors import (
    REFERENCE_DETECTOR_PROTOCOL_VERSION,
    KGWReferenceDetector,
    ReferenceConformanceError,
    ReferenceConformanceReport,
    ReferenceGoldenVector,
    TournamentReferenceDetector,
    UnigramReferenceDetector,
    assert_reference_conformance,
    generate_reference_text,
    load_reference_golden_vectors,
    reference_configuration_sha256,
    reference_tokenize,
    run_reference_conformance,
)
from .runtime import capabilities, plan
from .scanner import (
    ScanEdit,
    ScanFinding,
    ScanReport,
    baseline_fingerprints,
    changed_lines_from_unified_diff,
    path_is_selected,
    scan_paths,
    scan_text,
    to_sarif,
)
from .scanner_config import (
    ScannerConfig,
    find_scanner_config,
    load_scanner_config,
    resolve_scanner_config,
)
from .schemas import (
    benchmark_comparator_registry_schema,
    benchmark_evidence_bundle_schema,
    benchmark_input_corpus_schema,
    benchmark_observation_set_schema,
    benchmark_protocol_manifest_schema,
    benchmark_replication_record_schema,
    benchmark_run_config_schema,
    benchmark_sample_registry_schema,
    command_detector_schema,
    command_strategy_schema,
    detector_capability_schema,
    evidence_receipt_schema,
    localization_result_schema,
    mitigation_profile_schema,
    mitigation_result_schema,
    openapi_document,
    public_schema,
    removal_result_schema,
)
from .scoring import ScorerUnavailable, clear_cache, self_information, surrogate_score
from .strategies import (
    ContextAwareMinimalEditStrategy,
    RegisteredProviderStrategy,
    context_aware_strategy,
    registered_strategy,
)
from .unicode import (
    UNICODE_POLICY_SHA256,
    UNICODE_POLICY_VERSION,
    reverse_edits,
    sanitize_with_edits,
)
from .unicode import analyze as _analyze
from .unicode import sanitize as _sanitize_with_report

__all__ = [
    "__version__",
    "AdapterError",
    "adapter_pack_manifest",
    "agent_skill_path",
    "AtomicClaimQAGate",
    "BackendUnavailableError",
    "BatchItemResult",
    "BidirectionalNLIGate",
    "CapabilityManifest",
    "CachedTransformersNLIAdapter",
    "COMMAND_DETECTOR_PROTOCOL_VERSION",
    "COMMAND_STRATEGY_PROTOCOL_VERSION",
    "CommandDetector",
    "CommandDetectorConformanceError",
    "CommandDetectorContractError",
    "CommandDetectorError",
    "CommandDetectorExecutionError",
    "CommandDetectorFactory",
    "CommandStrategy",
    "CommandStrategyConsentError",
    "CommandStrategyContractError",
    "CommandStrategyError",
    "CommandStrategyExecutionError",
    "CommandStrategyFactory",
    "ConfigurationError",
    "ConsentRequiredError",
    "ContextAwareMinimalEditStrategy",
    "CitationGroundingGate",
    "DetectionEvidence",
    "DetectionStatus",
    "DetectorFeedback",
    "DetectorObservation",
    "DetectorPolicyDriftError",
    "DetectorQueryBudgetExceeded",
    "DetectorSession",
    "DetectorSessionScopeError",
    "DetectorConformanceCase",
    "DetectorConformanceReport",
    "DetectorDoctorCheck",
    "DetectorDoctorReport",
    "DetectorGoldenVector",
    "DetectorInventoryEntry",
    "DewatermarkConfig",
    "Dewatermark",
    "DewatermarkError",
    "EntityLinkingGate",
    "EvidenceReceipt",
    "ExecutionPlan",
    "LocalizedSignal",
    "LocalizationReport",
    "MitigationReceipt",
    "MitigationResult",
    "MitigationProfile",
    "MitigationProfileConsentError",
    "MitigationProfileError",
    "MITIGATION_PROFILE_SCHEMA_VERSION",
    "RemovalMode",
    "RemovalReport",
    "RemovalResult",
    "RemoteProcessingDeniedError",
    "QualityRejectedError",
    "QualityGateBinding",
    "QualityGateDecision",
    "QualityGateOutcome",
    "QualityReport",
    "RegisteredProviderStrategy",
    "ScorerUnavailable",
    "SanitizeProfile",
    "SearchLimits",
    "SearchTraceEvent",
    "ScanEdit",
    "ScannerConfig",
    "StageResult",
    "StrategyBinding",
    "StrategyContext",
    "CandidateProposal",
    "CandidateStrategy",
    "SessionVerification",
    "SignalSpan",
    "TransformationStatus",
    "UNICODE_POLICY_VERSION",
    "UNICODE_POLICY_SHA256",
    "UnicodeArtifactDetector",
    "UnsupportedDetector",
    "VerificationEvidence",
    "VerificationStatus",
    "VerifierObservation",
    "PlanMismatchError",
    "PairwiseAssessment",
    "KGWReferenceDetector",
    "REFERENCE_DETECTOR_PROTOCOL_VERSION",
    "ReferenceConformanceError",
    "ReferenceConformanceReport",
    "ReferenceGoldenVector",
    "TournamentReferenceDetector",
    "TaskContractGate",
    "UnigramReferenceDetector",
    "apply_plan",
    "benchmark_evidence_bundle_schema",
    "benchmark_comparator_registry_schema",
    "benchmark_input_corpus_schema",
    "benchmark_observation_set_schema",
    "benchmark_protocol_manifest_schema",
    "benchmark_replication_record_schema",
    "benchmark_run_config_schema",
    "benchmark_sample_registry_schema",
    "assert_command_detector_conformance",
    "assert_reference_conformance",
    "aremove",
    "analyze",
    "assure",
    "baseline_fingerprints",
    "capabilities",
    "clear_cache",
    "changed_lines_from_unified_diff",
    "command_detector_manifest",
    "command_detector_schema",
    "command_strategy_manifest",
    "command_strategy_schema",
    "configure",
    "conform_reference_detectors",
    "context_aware_strategy",
    "create_plan",
    "detector_errors",
    "detector_configuration_sha256",
    "detector_capability_schema",
    "detector_manifest",
    "discover_detector_capabilities",
    "doctor_detectors",
    "evaluate_quality",
    "evidence_receipt_schema",
    "find_scanner_config",
    "get_detector",
    "get_provider",
    "get_config",
    "generate_reference_text",
    "inspect_text",
    "inspect",
    "list_detectors",
    "list_adapter_packs",
    "list_providers",
    "localization_result_schema",
    "localize",
    "load_reference_golden_vectors",
    "load_scanner_config",
    "make_command_detector_factory",
    "make_command_strategy_factory",
    "materialize_adapter_pack",
    "materialize_agent_skill",
    "mitigate",
    "mitigate_with_profile",
    "mitigation_profile_sha256",
    "build_mitigation_profile",
    "inspect_mitigation_profile",
    "load_mitigation_profile",
    "validate_mitigation_profile",
    "quality_policy_manifest",
    "quality_policy_sha256",
    "mitigation_result_schema",
    "mitigation_profile_schema",
    "openapi_document",
    "plan",
    "path_is_selected",
    "provider_errors",
    "provider_manifest",
    "public_schema",
    "quality_gate_conformance",
    "register_detector",
    "register_provider",
    "registered_strategy",
    "reference_configuration_sha256",
    "reference_tokenize",
    "removal_result_schema",
    "remove",
    "remove_many",
    "reset_config",
    "resolve_scanner_config",
    "reverse_edits",
    "run_command_detector_conformance",
    "run_reference_conformance",
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
    "strategy_configuration_sha256",
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

    def localize(
        self,
        text: str,
        detector: str | object,
        *,
        window_characters: int = 1200,
        stride_characters: int = 600,
        familywise_alpha: float = 0.01,
    ) -> LocalizationReport:
        """Locate detector evidence without retaining the text in the report."""
        session = DetectorSession(detector, config=self.config)
        return localize(
            text,
            session,
            window_characters=window_characters,
            stride_characters=stride_characters,
            familywise_alpha=familywise_alpha,
        )

    def mitigate(
        self,
        text: str,
        primary_detector: str | object,
        strategies: Sequence[object | StrategyBinding],
        *,
        verifier_detectors: Sequence[str | object] = (),
        limits: SearchLimits | None = None,
        source_localization: Sequence[SignalSpan | LocalizedSignal] = (),
    ) -> MitigationResult:
        """Run bounded detector-guided search and roll back unless verified."""
        return mitigate(
            text,
            primary_detector,
            strategies,
            verifier_detectors=verifier_detectors,
            config=self.config,
            limits=limits,
            source_localization=source_localization,
        )

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
