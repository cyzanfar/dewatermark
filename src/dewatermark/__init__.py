"""Quality-constrained text-watermark robustness research toolkit.

Two watermark families:

1. Unicode steganography (zero-width chars, variation selectors, Tags-block
   payloads, bidi controls, soft hyphens, exotic spaces, homoglyphs) — removed
   deterministically by :func:`sanitize`.
2. Statistical generation-time watermarks (KGW, Unigram, EXP, SynthID-style) —
   scrubbed by self-information-targeted rewriting via :func:`remove`.
"""

from __future__ import annotations

from ._version import __version__
from .config import DewatermarkConfig, configure, get_config, reset_config
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
    ExecutionPlan,
    RemovalMode,
    RemovalReport,
    SanitizeProfile,
    StageResult,
)
from .pipeline import RemovalResult
from .pipeline import aremove as _aremove
from .pipeline import remove as _remove
from .pipeline import remove_many as _remove_many
from .providers import get_provider, list_providers, provider_errors, register_provider
from .quality import QualityReport, evaluate_quality
from .runtime import capabilities, plan
from .scanner import ScanFinding, ScanReport, scan_paths, scan_text, to_sarif
from .schemas import removal_result_schema
from .scoring import ScorerUnavailable, clear_cache, self_information, surrogate_score
from .unicode import analyze as _analyze
from .unicode import sanitize as _sanitize_with_report

__all__ = [
    "__version__",
    "AdapterError",
    "BackendUnavailableError",
    "BatchItemResult",
    "ConfigurationError",
    "DewatermarkConfig",
    "Dewatermark",
    "DewatermarkError",
    "ExecutionPlan",
    "RemovalMode",
    "RemovalReport",
    "RemovalResult",
    "RemoteProcessingDeniedError",
    "QualityRejectedError",
    "QualityReport",
    "ScorerUnavailable",
    "SanitizeProfile",
    "StageResult",
    "aremove",
    "analyze",
    "capabilities",
    "clear_cache",
    "configure",
    "evaluate_quality",
    "get_provider",
    "get_config",
    "list_providers",
    "plan",
    "provider_errors",
    "register_provider",
    "removal_result_schema",
    "remove",
    "remove_many",
    "reset_config",
    "sanitize",
    "ScanFinding",
    "ScanReport",
    "scan_paths",
    "scan_text",
    "to_sarif",
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
    config: DewatermarkConfig | None = None,
) -> RemovalResult:
    """Run the full removal pipeline with the module-level (env) config."""
    return _remove(
        text, mode=mode, passes=passes, epsilon=epsilon, beta=beta, best_of=best_of, config=config
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

    def remove(
        self,
        text: str,
        mode: RemovalMode = "auto",
        passes: int = 2,
        epsilon: float = 0.3,
        beta: float = 6.0,
        best_of: int = 3,
    ) -> RemovalResult:
        return _remove(
            text,
            mode=mode,
            passes=passes,
            epsilon=epsilon,
            beta=beta,
            best_of=best_of,
            config=self.config,
        )

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
