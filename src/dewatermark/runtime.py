"""Side-effect-free capability discovery, planning, and event emission."""

from __future__ import annotations

import logging
from importlib.util import find_spec
from typing import Any, Optional

from .config import DewatermarkConfig, assert_remote_allowed, resolve
from .models import SCHEMA_VERSION, ExecutionPlan, RemovalMode
from .providers import list_providers, provider_errors
from .scoring import cache_info, model_cached

logger = logging.getLogger(__name__)
_PARAPHRASE_CALLS = (1, 2, 3, 1, 1, 1, 1)


def _paraphrase_calls(passes: int) -> int:
    return sum(_PARAPHRASE_CALLS[index % len(_PARAPHRASE_CALLS)] for index in range(passes))


def emit(config: DewatermarkConfig, event: str, **payload: Any) -> None:
    """Deliver a metadata-only event; source text is never included."""
    if config.event_handler:
        try:
            config.event_handler({"event": event, "schema_version": SCHEMA_VERSION, **payload})
        except Exception as exc:
            logger.warning("dewatermark event handler failed for %s: %s", event, exc)


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
        "provider_errors": provider_errors(),
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
        available = cfg.rewriter_provider in list_providers()
        return ExecutionPlan(
            mode,
            cfg.rewriter_provider,
            False,
            False,
            available,
            None if available else "provider is not installed",
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
    scorer_usable = local_usable or bool(
        cfg.scorer_provider and cfg.scorer_provider in list_providers()
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
