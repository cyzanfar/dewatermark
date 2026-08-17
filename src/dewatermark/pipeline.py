"""Removal pipeline orchestration.

`auto` is the recommended one-click mode: it sanitizes, then picks the best
statistical scrub the environment can actually run (local BIRA > remote
paraphrase > sanitize-only). sanitize/paraphrase/full are the simple modes;
sira/bias_inversion/adversarial are the explicit self-information scrubbers
(see docs/STEP_FUNCTION_PLAN.md).
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from threading import Event
from typing import Any, Iterable, Optional

from . import bira, scoring, sira
from .config import DewatermarkConfig, assert_remote_allowed, resolve
from .models import BatchItemResult, RemovalMode, RemovalReport, ResultStatus, StageResult
from .paraphraser import recursive_paraphrase
from .providers import get_provider
from .runtime import emit
from .unicode import analyze, sanitize

VALID_MODES = ("auto", "sanitize", "paraphrase", "full", "sira", "bias_inversion", "adversarial")
_SANITIZE_WRAPPED = ("auto", "sanitize", "full", "sira", "bias_inversion", "adversarial")
_STATISTICAL = ("auto", "paraphrase", "full", "sira", "bias_inversion", "adversarial")
_VERIFY_WRAPPED = ("auto", "full", "sira", "bias_inversion", "adversarial")


@dataclass
class RemovalResult:
    """Outcome of :func:`remove`: the cleaned text plus per-stage details."""

    cleaned_text: str
    report: RemovalReport
    stages: list[StageResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "cleaned_text": self.cleaned_text,
            "stages": [stage.to_dict() for stage in self.stages],
            "report": self.report.to_dict(),
        }


def _stage_result(raw: dict, source: str, current: str) -> StageResult:
    raw = dict(raw)
    name = str(raw.pop("stage", "unknown"))
    warning = raw.pop("warning", None)
    error = raw.pop("error", None)
    accepted = not bool(error or warning)
    if name == "sanitize":
        changed = bool(raw.get("removed"))
    elif name == "verify":
        changed = False
    else:
        changed = source != current and not bool(error)
    status: ResultStatus = (
        "failed" if error else ("partial" if warning else ("success" if changed else "unchanged"))
    )
    return StageResult(
        name=name,
        status=status,
        changed=changed,
        accepted=accepted,
        backend=raw.pop("backend", None),
        fallback_reason=raw.pop("fallback", None),
        warning=warning,
        error=error,
        details=raw,
    )


def _validate(text, mode, passes, epsilon, beta, best_of):
    if not isinstance(text, str) or not text:
        raise ValueError("'text' must be a non-empty string.")
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode {mode!r}. Must be one of {VALID_MODES}.")
    if not isinstance(passes, int) or not 1 <= passes <= 5:
        raise ValueError("'passes' must be an integer between 1 and 5.")
    if not isinstance(epsilon, (int, float)) or not 0.05 <= epsilon <= 0.9:
        raise ValueError("'epsilon' must be a number between 0.05 and 0.9.")
    if not isinstance(beta, (int, float)) or not 0.0 <= beta <= 20.0:
        raise ValueError("'beta' must be a number between 0 and 20.")
    if not isinstance(best_of, int) or not 1 <= best_of <= 6:
        raise ValueError("'best_of' must be an integer between 1 and 6.")


def _run_sanitize(text, profile):
    cleaned, by_category = sanitize(text, profile=profile)
    return cleaned, sum(by_category.values()), by_category


def _auto_scrub(text, beta, passes, cfg):
    """Pick the strongest statistical scrub the environment supports.

    Local model available -> BIRA (best; also what SIRA needs for scoring). No
    local model but an LLM key -> remote recursive paraphrase. Neither -> nothing
    (sanitize already ran). Returns (text, [stage_detail...], selected)."""
    remote_rewrite_ready = False
    if cfg.resolved_lm_backend == "fireworks" and cfg.fireworks_api_key:
        try:
            assert_remote_allowed(cfg.fireworks_base_url, cfg)
            remote_rewrite_ready = True
        except PermissionError:
            pass
    elif cfg.llm_api_key:
        try:
            assert_remote_allowed(cfg.llm_base_url, cfg)
            remote_rewrite_ready = True
        except PermissionError:
            pass
    if scoring.available(cfg):
        out, detail = bira.bira_rewrite(text, beta, config=cfg)
        if out != text and "warning" not in detail and "error" not in detail:
            return out, [{**detail, "auto_selected": "bias_inversion"}], "bias_inversion"
        stages = [
            {
                **detail,
                "auto_selected": "bias_inversion",
                "fallback": "paraphrase" if remote_rewrite_ready else "sanitize_only",
            }
        ]
        if remote_rewrite_ready:
            consumed = (
                1 + len(detail.get("attempts", [])) if cfg.resolved_lm_backend == "fireworks" else 0
            )
            remaining = cfg.max_remote_calls - consumed
            if remaining <= 0:
                return text, stages, "sanitize_only"
            out, para_stages = recursive_paraphrase(
                text, passes, config=replace(cfg, max_remote_calls=remaining)
            )
            for stage in para_stages:
                stage["auto_selected"] = "paraphrase_fallback"
            return out, stages + para_stages, "paraphrase_fallback"
        return text, stages, "sanitize_only"
    if remote_rewrite_ready:
        out, para_stages = recursive_paraphrase(text, passes, config=cfg)
        for stage in para_stages:
            stage["auto_selected"] = "paraphrase"
        return out, para_stages, "paraphrase"
    return (
        text,
        [
            {
                "stage": "auto",
                "selected": "sanitize_only",
                "auto_selected": "sanitize_only",
                "reason": "no local rewriter and no LLM key configured",
            }
        ],
        "sanitize_only",
    )


def _adversarial_best_of(text, best_of, epsilon, cfg):
    """Surrogate-guided best-of-N: generate N SIRA candidates at varied epsilon,
    keep the one with the lowest reference-free surrogate greenness."""
    detail = {"stage": "adversarial", "candidates": best_of, "epsilon": epsilon}
    best_text, best_score, tried = text, None, []
    uses_remote = bool(cfg.llm_api_key or cfg.resolved_lm_backend == "fireworks")
    calls_per_candidate = 3 if cfg.resolved_lm_backend == "fireworks" else 2
    affordable = (
        min(best_of, cfg.max_remote_calls // calls_per_candidate) if uses_remote else best_of
    )
    if affordable < 1:
        detail["error"] = "remote-call budget is too small for a SIRA candidate"
        return text, detail
    for i in range(affordable):
        eps = min(0.6, epsilon + 0.1 * i)
        cand, cand_detail = sira.sira_rewrite(text, eps, config=cfg)
        surrogate = scoring.surrogate_score(cand, config=cfg)
        score = surrogate.get("mean_surprisal_bits") if surrogate.get("available") else None
        tried.append(
            {
                "epsilon": round(eps, 3),
                "surrogate": score,
                "ok": "error" not in cand_detail and "warning" not in cand_detail,
            }
        )
        if score is not None and (best_score is None or score < best_score):
            best_text, best_score = cand, score
        elif best_score is None and cand != text:
            best_text = cand  # no surrogate available: take first real rewrite
    detail["chosen_surrogate"] = best_score
    detail["attempts"] = tried
    detail["candidates_attempted"] = affordable
    return best_text, detail


def remove(
    text: str,
    mode: RemovalMode = "auto",
    passes: int = 2,
    epsilon: float = 0.3,
    beta: float = 6.0,
    best_of: int = 3,
    config: Optional[DewatermarkConfig] = None,
    _cancel_event: Optional[Event] = None,
) -> RemovalResult:
    """Strip unicode steganography and scrub statistical watermarks from `text`.

    Pipeline: sanitize first (wrapped modes) -> statistical scrub per mode ->
    re-sanitize + verify (scrubbing modes). Statistical modes also record a
    reference-free surrogate score before and after. Raises ValueError on
    invalid parameters.
    """
    _validate(text, mode, passes, epsilon, beta, best_of)
    cfg = resolve(config)
    if len(text) > cfg.max_input_chars:
        raise ValueError(f"text exceeds max_input_chars={cfg.max_input_chars}")
    if _cancel_event and _cancel_event.is_set():
        raise asyncio.CancelledError
    started = time.monotonic()
    emit(cfg, "pipeline.started", mode=mode, characters=len(text))

    stages = []
    chars_before = len(text)
    current = text
    total_removed = 0

    surrogate_before = (
        scoring.surrogate_score(current, config=cfg) if mode in _STATISTICAL else None
    )

    # 1. Unicode sanitize (front of the pipeline for every wrapped mode).
    if mode in _SANITIZE_WRAPPED:
        current, removed, by_category = _run_sanitize(current, cfg.sanitize_profile)
        total_removed += removed
        stages.append(
            {"stage": "sanitize", "removed": removed, "detail": {"by_category": by_category}}
        )

    # 2. Statistical scrub.
    if _cancel_event and _cancel_event.is_set():
        raise asyncio.CancelledError
    auto_selected = None
    if mode != "sanitize" and cfg.rewriter_provider:
        provider = get_provider(cfg.rewriter_provider)(cfg)
        if not provider.available():
            stages.append(
                {
                    "stage": "provider",
                    "backend": cfg.rewriter_provider,
                    "error": "configured provider is unavailable",
                }
            )
        else:
            current, detail = provider.rewrite(
                current, mode=mode, passes=passes, epsilon=epsilon, beta=beta, best_of=best_of
            )
            stages.append({"stage": "provider", "backend": cfg.rewriter_provider, **dict(detail)})
    elif mode == "auto":
        current, auto_stages, auto_selected = _auto_scrub(current, beta, passes, cfg)
        stages.extend(auto_stages)
    elif mode in ("paraphrase", "full"):
        current, para_stages = recursive_paraphrase(current, passes, config=cfg)
        stages.extend(para_stages)
    elif mode == "sira":
        current, detail = sira.sira_rewrite(current, epsilon, config=cfg)
        stages.append(detail)
    elif mode == "bias_inversion":
        current, detail = bira.bira_rewrite(current, beta, config=cfg)
        stages.append(detail)
    elif mode == "adversarial":
        current, detail = _adversarial_best_of(current, best_of, epsilon, cfg)
        stages.append(detail)

    # 3. Re-sanitize + verify for every scrubbing mode (a rewrite can reintroduce
    #    exotic characters, and we assert the Unicode channel is clean at the end).
    if mode in _VERIFY_WRAPPED:
        current, re_by_category = sanitize(current, profile=cfg.sanitize_profile)
        total_removed += sum(re_by_category.values())
        remaining = analyze(current)["unicode"]["total_flags"]
        stages.append({"stage": "verify", "remaining_flags": remaining})

    metadata: dict[str, Any] = {
        "paraphrase_passes": passes if mode in ("paraphrase", "full") else 0,
        "latency_ms": round((time.monotonic() - started) * 1000, 3),
    }
    if auto_selected is not None:
        metadata["auto_selected"] = auto_selected
        if auto_selected in ("sanitize_only", "paraphrase_fallback"):
            emit(cfg, "pipeline.fallback", mode=mode, selected=auto_selected)
    if mode in _STATISTICAL:
        metadata["surrogate_before"] = surrogate_before
        metadata["surrogate_after"] = scoring.surrogate_score(current, config=cfg)

    typed_stages = [_stage_result(stage, text, current) for stage in stages]
    for stage in typed_stages:
        emit(
            cfg,
            "stage.finished",
            stage=stage.name,
            status=stage.status,
            changed=stage.changed,
            accepted=stage.accepted,
            backend=stage.backend,
        )
    warnings = tuple(stage.warning for stage in typed_stages if stage.warning)
    errors = [stage for stage in typed_stages if stage.error]
    status: ResultStatus = (
        "failed"
        if errors and current == text
        else ("partial" if errors or warnings else ("success" if current != text else "unchanged"))
    )
    fallback_value = metadata.get("auto_selected")
    fallback_reason = fallback_value if fallback_value == "sanitize_only" else None
    report = RemovalReport(
        mode=mode,
        status=status,
        changed=current != text,
        char_count_before=chars_before,
        char_count_after=len(current),
        chars_removed=total_removed,
        sanitize_profile=cfg.sanitize_profile,
        backend="unicode"
        if mode == "sanitize"
        else (cfg.rewriter_provider or cfg.resolved_lm_backend),
        fallback_reason=fallback_reason,
        warnings=warnings,
        metadata=metadata,
    )
    emit(
        cfg,
        "pipeline.finished",
        mode=mode,
        status=status,
        changed=current != text,
        latency_ms=metadata["latency_ms"],
    )
    return RemovalResult(cleaned_text=current, stages=typed_stages, report=report)


def remove_many(
    texts: Iterable[str],
    *,
    mode: RemovalMode = "auto",
    config: Optional[DewatermarkConfig] = None,
    max_workers: Optional[int] = None,
    **options,
) -> list[BatchItemResult]:
    """Process a batch concurrently, preserving order and per-item failures."""
    cfg = resolve(config)
    workers = max_workers or cfg.max_concurrency
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dewatermark") as pool:
        futures = [pool.submit(remove, text, mode=mode, config=cfg, **options) for text in texts]
        outcomes = []
        for index, future in enumerate(futures):
            try:
                outcomes.append(BatchItemResult(index=index, result=future.result()))
            except Exception as exc:
                outcomes.append(BatchItemResult(index=index, error=str(exc)))
        return outcomes


async def aremove(
    text: str,
    *,
    mode: RemovalMode = "auto",
    config: Optional[DewatermarkConfig] = None,
    **options,
) -> RemovalResult:
    """Cancellation-aware asynchronous wrapper around the synchronous pipeline."""
    cancellation = Event()
    task = asyncio.create_task(
        asyncio.to_thread(
            remove, text, mode=mode, config=config, _cancel_event=cancellation, **options
        )
    )
    try:
        return await task
    except asyncio.CancelledError:
        cancellation.set()
        raise
