"""Side-effect-free capability discovery, planning, and event emission."""

from __future__ import annotations

import logging
from importlib.util import find_spec
from typing import Any, Optional

from .config import DewatermarkConfig, assert_remote_allowed, resolve
from .models import SCHEMA_VERSION, ExecutionPlan, RemovalMode
from .providers import (
    detector_errors,
    detector_manifest,
    list_detectors,
    list_providers,
    provider_errors,
    provider_manifest,
)
from .request_context import current_request_context
from .scoring import cache_info, model_cached

logger = logging.getLogger(__name__)
_PARAPHRASE_CALLS = (1, 2, 3, 1, 1, 1, 1)


def _paraphrase_calls(passes: int) -> int:
    return sum(_PARAPHRASE_CALLS[index % len(_PARAPHRASE_CALLS)] for index in range(passes))


def emit(config: DewatermarkConfig, event: str, **payload: Any) -> None:
    """Deliver a metadata-only event; source text is never included."""
    context = current_request_context()
    if context is not None and event == "provider.usage":
        context.record_usage(payload)
    if config.event_handler:
        try:
            config.event_handler({"event": event, "schema_version": SCHEMA_VERSION, **payload})
        except Exception as exc:
            logger.warning(
                "dewatermark event handler failed for %s (%s); details redacted",
                event,
                type(exc).__name__,
            )


def capabilities(config: Optional[DewatermarkConfig] = None) -> dict[str, Any]:
    """Describe installed functionality without loading models or using network."""
    cfg = resolve(config)
    remote_allowed = False
    remote_url = (
        cfg.fireworks_base_url if cfg.resolved_lm_backend == "fireworks" else cfg.llm_base_url
    )
    try:
        assert_remote_allowed(remote_url, cfg)
        remote_allowed = True
    except PermissionError:
        pass
    detector_capabilities = []
    for name in list_detectors():
        manifest = detector_manifest(name)
        detector_capabilities.append(
            {
                "registered_name": name,
                **(
                    manifest.to_dict()
                    if manifest is not None
                    else {
                        "identifier": name,
                        "kind": "detector",
                        "status": "entry_point_not_loaded",
                    }
                ),
            }
        )
    provider_capabilities = []
    for name in list_providers():
        manifest = provider_manifest(name)
        provider_capabilities.append(
            {
                "registered_name": name,
                **(
                    manifest.to_dict()
                    if manifest is not None
                    else {
                        "identifier": name,
                        "kind": "transformer",
                        "status": "entry_point_not_loaded_or_manifest_missing",
                    }
                ),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "unicode": True,
        "local_dependencies": bool(find_spec("torch") and find_spec("transformers")),
        "local_model": cfg.local_lm,
        "local_model_cached": model_cached(cfg.local_lm),
        "loaded_models": cache_info()["models"],
        "model_download_allowed": cfg.allow_model_download,
        "remote_processing_allowed": remote_allowed,
        "llm_configured": bool(cfg.llm_api_key),
        "fireworks_configured": bool(cfg.fireworks_api_key),
        "resolved_backend": cfg.resolved_lm_backend,
        "provider_plugins": list(list_providers()),
        "provider_capabilities": provider_capabilities,
        "provider_errors": provider_errors(),
        "detector_plugins": list(list_detectors()),
        "detector_capabilities": detector_capabilities,
        "detector_errors": detector_errors(),
        "assurance": {
            "operations": ["inspect", "plan", "apply", "verify"],
            "detection_states": [
                "detected",
                "not_detected",
                "insufficient_evidence",
                "unsupported",
                "configuration_mismatch",
                "detector_error",
            ],
            "transformation_states": [
                "unchanged",
                "unicode_sanitized",
                "mitigation_verified",
                "mitigation_unverified",
                "unsupported_scheme",
                "rejected_quality",
                "failed",
            ],
            "verification_states": [
                "verified_cleared",
                "residual",
                "not_verifiable",
                "failed",
            ],
            "schemas": [
                "removal-result",
                "evidence-receipt",
                "detector-capability",
                "command-detector",
            ],
        },
        "modes": [
            "auto",
            "sanitize",
            "paraphrase",
            "full",
            "sira",
            "bias_inversion",
            "adversarial",
        ],
    }


def plan(
    mode: RemovalMode = "auto",
    config: Optional[DewatermarkConfig] = None,
    *,
    passes: int = 2,
    best_of: int = 3,
) -> ExecutionPlan:
    """Describe requirements for a call without loading a model or sending text."""
    cfg = resolve(config)
    limits = {
        "max_input_chars": cfg.max_input_chars,
        "max_remote_calls": cfg.max_remote_calls,
        "max_output_tokens": cfg.max_output_tokens,
    }
    if mode == "sanitize":
        return ExecutionPlan(mode, "unicode", False, False, True, limits=limits)
    if cfg.rewriter_provider:
        manifest = provider_manifest(cfg.rewriter_provider)
        if manifest is None:
            return ExecutionPlan(
                mode,
                cfg.rewriter_provider,
                True,
                True,
                False,
                "provider requires an already-loaded static transformer manifest",
                limits=limits,
            )
        permission_ready = (
            (not manifest.network_required or cfg.allow_remote_processing)
            and (not manifest.model_download_possible or cfg.allow_model_download)
            and not manifest.requires_secret
        )
        return ExecutionPlan(
            mode,
            cfg.rewriter_provider,
            manifest.network_required,
            manifest.model_download_possible,
            permission_ready,
            None if permission_ready else "provider requirements are not explicitly permitted",
            limits=limits,
        )
    if cfg.resolved_lm_backend == "fireworks":
        allowed = bool(cfg.fireworks_api_key and capabilities(cfg)["remote_processing_allowed"])
        estimated = (
            cfg.max_remote_calls
            if mode == "auto"
            else (
                4
                if mode == "bias_inversion"
                else (
                    3
                    if mode == "sira"
                    else (3 * best_of if mode == "adversarial" else _paraphrase_calls(passes))
                )
            )
        )
        return ExecutionPlan(
            mode,
            "fireworks",
            True,
            False,
            allowed,
            None if allowed else "remote backend is unavailable or denied",
            estimated_remote_calls=estimated,
            limits=limits,
        )
    deps = bool(find_spec("torch") and find_spec("transformers"))
    local_usable = deps and (cfg.allow_model_download or model_cached(cfg.local_lm))
    scorer_usable = local_usable
    if cfg.scorer_provider:
        scorer_manifest = provider_manifest(cfg.scorer_provider, kind="scorer")
        scorer_usable = bool(
            scorer_manifest
            and (not scorer_manifest.network_required or cfg.allow_remote_processing)
            and (not scorer_manifest.model_download_possible or cfg.allow_model_download)
            and not scorer_manifest.requires_secret
        )
    llm_allowed = False
    try:
        assert_remote_allowed(cfg.llm_base_url, cfg)
        llm_allowed = bool(cfg.llm_api_key)
    except PermissionError:
        pass
    if mode in ("paraphrase", "full"):
        return ExecutionPlan(
            mode,
            "llm",
            True,
            False,
            llm_allowed,
            None if llm_allowed else "LLM backend is unavailable or remote processing is denied",
            estimated_remote_calls=_paraphrase_calls(passes),
            limits=limits,
        )
    if mode in ("sira", "adversarial"):
        ready = scorer_usable and llm_allowed
        return ExecutionPlan(
            mode,
            "local+llm",
            True,
            cfg.allow_model_download,
            ready,
            None if ready else "SIRA requires an available scorer and rewrite LLM",
            estimated_remote_calls=2 * best_of if mode == "adversarial" else 2,
            limits=limits,
        )
    if mode == "auto" and not local_usable and llm_allowed:
        return ExecutionPlan(
            mode,
            "llm",
            True,
            False,
            True,
            estimated_remote_calls=_paraphrase_calls(passes),
            limits=limits,
        )
    return ExecutionPlan(
        mode,
        "local",
        False,
        cfg.allow_model_download,
        local_usable,
        None
        if local_usable
        else (
            "install dewatermark[local]"
            if not deps
            else "model is not cached; run dewatermark download-model or opt into downloads"
        ),
        limits=limits,
    )
