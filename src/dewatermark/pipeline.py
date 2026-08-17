"""Removal pipeline orchestration.

`auto` is the recommended one-click mode: it sanitizes, then picks the best
statistical scrub the environment can actually run (local BIRA > remote
paraphrase > sanitize-only). sanitize/paraphrase/full are the simple modes;
sira/bias_inversion/adversarial are the explicit self-information scrubbers
(see docs/STEP_FUNCTION_PLAN.md).
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import math
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from threading import Event
from typing import Any, Iterable, Mapping, Optional

from . import bira, scoring, sira
from ._version import __version__
from .assurance import evaluate_verification, resolve_detector
from .config import DewatermarkConfig, assert_remote_allowed, resolve
from .detectors import UnicodeArtifactDetector, capability_of, run_detector
from .extension_safety import (
    enforce_consent,
    manifests_match,
    safe_extension_config,
    static_capability,
)
from .models import (
    BatchItemResult,
    DetectionEvidence,
    DetectionStatus,
    EvidenceReceipt,
    RemovalMode,
    RemovalReport,
    ResultStatus,
    StageResult,
    TransformationStatus,
    VerificationStatus,
)
from .paraphraser import recursive_paraphrase
from .providers import get_provider, provider_manifest
from .quality import QualityReport, evaluate_candidate
from .request_context import (
    RequestContext,
    checkpoint,
    current_request_context,
    request_scope,
    safe_error,
)
from .runtime import emit
from .unicode import UNICODE_POLICY_VERSION, sanitize

VALID_MODES = ("auto", "sanitize", "paraphrase", "full", "sira", "bias_inversion", "adversarial")
_SANITIZE_WRAPPED = ("auto", "sanitize", "full", "sira", "bias_inversion", "adversarial")
_STATISTICAL = ("auto", "paraphrase", "full", "sira", "bias_inversion", "adversarial")
_SURROGATE_MODES = ("auto", "sira", "bias_inversion", "adversarial")
_VERIFY_WRAPPED = _STATISTICAL

_PROTECTED_DETAIL_FIELDS = {
    "introduced_dates",
    "introduced_emails",
    "introduced_entities",
    "introduced_modalities",
    "introduced_negations",
    "introduced_numbers",
    "introduced_quotes",
    "introduced_units",
    "introduced_urls",
    "missing_dates",
    "missing_emails",
    "missing_entities",
    "missing_modalities",
    "missing_negations",
    "missing_numbers",
    "missing_quotes",
    "missing_units",
    "missing_urls",
}
_PRIVATE_DETAIL_KEYS = {
    "api_key",
    "authorization",
    "body",
    "candidate",
    "content",
    "credential",
    "error",
    "headers",
    "input",
    "output",
    "password",
    "private_key",
    "prompt",
    "response",
    "secret",
    "source_text",
    "text",
    "token",
}


def _private_detail_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _PRIVATE_DETAIL_KEYS or normalized.endswith(
        ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
    )


def _public_stage_details(value: Any, *, key: str = "") -> Any:
    """Remove source spans and credentials from report/receipt metadata."""
    normalized = key.lower().replace("-", "_")
    if normalized in _PROTECTED_DETAIL_FIELDS:
        return {"redacted_count": len(value) if isinstance(value, (list, tuple)) else 0}
    if _private_detail_key(normalized):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {
            str(item_key): _public_stage_details(item, key=str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_public_stage_details(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def _public_quality(report: QualityReport) -> dict[str, Any]:
    return _public_stage_details(report.to_dict())


def _type_identifier(value: Any) -> Optional[str]:
    if value is None:
        return None
    kind = value if isinstance(value, type) else type(value)
    return f"{kind.__module__}.{kind.__qualname__}"


def _model_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _receipt_policy(cfg: DewatermarkConfig) -> dict[str, Any]:
    """Return consequential, credential-free policy for a reproducible receipt."""
    return {
        "sanitize_profile": cfg.sanitize_profile,
        "allow_remote_processing": cfg.allow_remote_processing,
        "allow_model_download": cfg.allow_model_download,
        "require_verified": cfg.require_verified,
        "request_timeout_seconds": cfg.request_timeout,
        "max_remote_calls": cfg.max_remote_calls,
        "max_output_tokens": cfg.max_output_tokens,
        "max_chunk_chars": cfg.max_chunk_chars,
        "quality_min_length_ratio": cfg.quality_min_length_ratio,
        "quality_max_length_ratio": cfg.quality_max_length_ratio,
        "quality_min_semantic_score": cfg.quality_min_semantic_score,
        "quality_gate": _type_identifier(cfg.quality_gate),
        "semantic_scorer": _type_identifier(cfg.semantic_scorer),
    }


_CAPABILITY_METADATA_KEYS = {
    "calibration",
    "configuration_sha256",
    "evidence_level",
    "license",
    "minimum_effective_tokens",
    "score_direction",
    "source",
    "source_status",
    "status",
    "threat_models",
    "threshold",
    "tokenizer_revision",
}


def _receipt_capability(detector: Any, fallback_name: str) -> dict[str, Any]:
    capability = capability_of(detector, fallback_name)
    public_metadata = capability.to_dict()["metadata"]
    return {
        "identifier": capability.identifier,
        "version": capability.version,
        "schemes": list(capability.schemes),
        "calibrated": capability.calibrated,
        "independent": capability.independent,
        "network_required": capability.network_required,
        "model_download_possible": capability.model_download_possible,
        "minimum_characters": capability.minimum_characters,
        "metadata": {
            key: value for key, value in public_metadata.items() if key in _CAPABILITY_METADATA_KEYS
        },
    }


def _receipt_provenance(
    cfg: DewatermarkConfig,
    mode: RemovalMode,
    detector: Any,
    detector_name: str,
) -> dict[str, Any]:
    policy = _receipt_policy(cfg)
    fingerprint_input = {
        "mode": mode,
        "policy": policy,
        "random_seed": cfg.random_seed,
        "local_model_sha256": _model_sha256(cfg.local_lm),
        "fireworks_model_sha256": _model_sha256(cfg.fireworks_model),
        "llm_model_sha256": _model_sha256(cfg.llm_model),
        "detector": _receipt_capability(detector, detector_name),
    }
    encoded = json.dumps(
        fingerprint_input,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("ascii")
    return {
        "package_version": __version__,
        "transform_revision": f"dewatermark/{__version__}",
        "unicode_policy_version": UNICODE_POLICY_VERSION,
        "random_seed": cfg.random_seed,
        "config_sha256": hashlib.sha256(encoded).hexdigest(),
        "detector_capability": fingerprint_input["detector"],
        "model_identifiers": {
            "local_sha256": fingerprint_input["local_model_sha256"],
            "fireworks_sha256": fingerprint_input["fireworks_model_sha256"],
            "llm_sha256": fingerprint_input["llm_model_sha256"],
        },
    }


def _claim_scope(
    transformation: TransformationStatus,
    verification: VerificationStatus,
    detector_name: str,
) -> str:
    if transformation == "mitigation_verified" and verification == "verified_cleared":
        return (
            f"The accepted candidate cleared only detector {detector_name!r} at its "
            "recorded configuration and quality policy; this is not authorship evidence."
        )
    if transformation == "unicode_sanitized":
        return (
            "Only literal Unicode artifacts covered by unicode-artifacts-v1 were "
            "cleared; no statistical or vendor watermark claim is made."
        )
    if transformation == "unsupported_scheme":
        return (
            f"Detector {detector_name!r} could not verify the requested scheme; no "
            "removal claim is made."
        )
    if transformation == "mitigation_unverified":
        return (
            "Text changed and passed configured quality gates, but no compatible "
            "independent detector verified statistical mitigation."
        )
    if transformation == "rejected_quality":
        return "Generated candidates failed configured quality gates and were not accepted."
    return (
        f"Evidence is limited to detector {detector_name!r} and the recorded policy; "
        "no authorship or universal watermark inference is made."
    )


@dataclass
class RemovalResult:
    """Outcome of :func:`remove`: the cleaned text plus per-stage details."""

    cleaned_text: str
    report: RemovalReport
    stages: list[StageResult] = field(default_factory=list)
    receipt: Optional[EvidenceReceipt] = None

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "cleaned_text": self.cleaned_text,
            "stages": [stage.to_dict() for stage in self.stages],
            "report": self.report.to_dict(),
            "receipt": self.receipt.to_dict() if self.receipt is not None else None,
        }


def _stage_result(raw: dict, source: str, current: str) -> StageResult:
    raw = dict(raw)
    name = str(raw.pop("stage", "unknown"))
    warning = raw.pop("warning", None)
    reported_error = raw.pop("error", None)
    error = "stage reported an error; backend detail was redacted" if reported_error else None
    accepted = bool(raw.pop("_accepted", not bool(error or warning)))
    explicit_changed = raw.pop("_changed", None)
    if name == "sanitize":
        changed = bool(raw.get("removed"))
    elif name == "verify":
        changed = False
    else:
        changed = bool(
            explicit_changed if explicit_changed is not None else source != current and not error
        )
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
        details=_public_stage_details(raw),
    )


_PROVIDER_RESERVED = {
    "stage",
    "name",
    "status",
    "changed",
    "accepted",
    "backend",
    "fallback",
    "fallback_reason",
    "warning",
    "error",
    "latency_ms",
    "details",
}


def _provider_stage(name: str, detail: Mapping[str, Any]) -> dict[str, Any]:
    """Accept provider metadata without allowing it to forge pipeline fields."""
    safe: dict[str, Any] = {}
    for key, value in detail.items():
        if key in _PROVIDER_RESERVED:
            continue
        if (
            value is None
            or isinstance(value, (bool, int))
            or (isinstance(value, float) and math.isfinite(value))
        ):
            safe[key] = value
        elif (
            key in {"strategy", "implementation", "method"}
            and isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value)
        ):
            safe[key] = value
        else:
            safe[key] = "<redacted>"
    reserved = sorted(key for key in detail if key in _PROVIDER_RESERVED)
    if reserved:
        safe["ignored_reserved_fields"] = reserved
    stage: dict[str, Any] = {"stage": "provider", "backend": name, **safe}
    if detail.get("error"):
        stage["error"] = "provider reported an error; provider message was redacted"
    elif detail.get("warning"):
        stage["warning"] = "provider reported a warning; provider message was redacted"
    return stage


def _public_detector_name(value: Any) -> str:
    """Return a stable label without invoking extension string methods."""
    if type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        return value
    return "custom-detector"


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
            context = current_request_context()
            remaining = context.remaining_remote_calls() if context else cfg.max_remote_calls
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
    valid_candidates = 0
    uses_remote = bool(cfg.llm_api_key or cfg.resolved_lm_backend == "fireworks")
    calls_per_candidate = 3 if cfg.resolved_lm_backend == "fireworks" else 2
    affordable = (
        min(best_of, cfg.max_remote_calls // calls_per_candidate) if uses_remote else best_of
    )
    if affordable < 1:
        detail["error"] = "remote-call budget is too small for a SIRA candidate"
        return text, detail
    for i in range(affordable):
        checkpoint()
        eps = min(0.6, epsilon + 0.1 * i)
        cand, cand_detail = sira.sira_rewrite(text, eps, config=cfg)
        surrogate = scoring.surrogate_score(cand, config=cfg)
        score = surrogate.get("mean_surprisal_bits") if surrogate.get("available") else None
        ok = (
            "error" not in cand_detail
            and "warning" not in cand_detail
            and isinstance(cand, str)
            and cand != text
        )
        tried.append(
            {
                "epsilon": round(eps, 3),
                "surrogate": score,
                "ok": ok,
            }
        )
        if not ok:
            continue
        valid_candidates += 1
        if score is not None and (best_score is None or score < best_score):
            best_text, best_score = cand, score
        elif best_score is None and cand != text:
            best_text = cand  # no surrogate available: take first real rewrite
    detail["chosen_surrogate"] = best_score
    detail["attempts"] = tried
    detail["candidates_attempted"] = affordable
    detail["valid_candidates"] = valid_candidates
    if not valid_candidates:
        detail["warning"] = "no adversarial candidate passed its backend quality checks"
    return best_text, detail


def _quality_report(source: str, candidate: str, cfg: DewatermarkConfig) -> QualityReport:
    try:
        checkpoint()
        report = evaluate_candidate(source, candidate, cfg)
        checkpoint()
        return report
    except Exception as exc:
        source_words = max(1, len(source.split()))
        return QualityReport(
            passed=False,
            length_ratio=round(len(candidate.split()) / source_words, 4),
            distinct_1_ratio=0.0,
            reasons=[safe_error("quality gate", exc)],
        )


def _surrogate(text: str, cfg: DewatermarkConfig) -> dict[str, Any]:
    try:
        return scoring.surrogate_score(text, config=cfg)
    except Exception as exc:
        return {"available": False, "reason": safe_error("surrogate scorer", exc)}


def _detector_failure(name: str, text: str, exc: BaseException) -> DetectionEvidence:
    return DetectionEvidence(
        detector=name,
        status="detector_error",
        text_characters=len(text),
        reason=safe_error("detector", exc),
    )


def remove(
    text: str,
    mode: RemovalMode = "auto",
    passes: int = 2,
    epsilon: float = 0.3,
    beta: float = 6.0,
    best_of: int = 3,
    detector: str | Any | None = None,
    config: Optional[DewatermarkConfig] = None,
    _cancel_event: Optional[Event] = None,
) -> RemovalResult:
    """Transform text, centrally quality-gate it, and return scoped evidence.

    ``status='success'`` remains for v1 compatibility. Callers should use the
    explicit detection/transformation/verification fields for assurance logic.
    """
    _validate(text, mode, passes, epsilon, beta, best_of)
    cfg = resolve(config)
    if len(text) > cfg.max_input_chars:
        raise ValueError(f"text exceeds max_input_chars={cfg.max_input_chars}")
    context = RequestContext.from_config(cfg, _cancel_event)
    with request_scope(context):
        return _remove_scoped(
            text,
            mode=mode,
            passes=passes,
            epsilon=epsilon,
            beta=beta,
            best_of=best_of,
            detector=detector,
            cfg=cfg,
            context=context,
        )


def _remove_scoped(
    text: str,
    *,
    mode: RemovalMode,
    passes: int,
    epsilon: float,
    beta: float,
    best_of: int,
    detector: str | Any | None,
    cfg: DewatermarkConfig,
    context: RequestContext,
) -> RemovalResult:
    checkpoint()
    started = time.monotonic()
    emit(cfg, "pipeline.started", mode=mode, characters=len(text))

    stages: list[dict[str, Any]] = []
    chars_before = len(text)
    current = text
    front_removed = 0
    post_removed = 0
    quality_rejected = False
    unsupported_scheme = False
    transform_attempted = False
    transform_failed = False
    central_quality: Optional[QualityReport] = None

    unicode_detector = UnicodeArtifactDetector(cfg)
    unicode_before = run_detector(unicode_detector, text, config=cfg)

    detector_instance: Any | None = None
    detector_name: Optional[str] = None
    detector_before: Optional[DetectionEvidence] = None
    detector_is_unicode = False
    selected_detector = (
        detector if detector is not None else getattr(cfg, "detector_provider", None)
    )
    if selected_detector is not None:
        try:
            detector_instance, detector_name = resolve_detector(selected_detector, cfg)
            if detector_instance is not None and detector_name is not None:
                detector_capability = capability_of(detector_instance, detector_name)
                detector_is_unicode = (
                    "unicode-artifacts" in detector_capability.schemes
                    or detector_capability.identifier.startswith("unicode-artifact")
                )
                detector_before = run_detector(
                    detector_instance, text, fallback_name=detector_name, config=cfg
                )
        except Exception as exc:
            detector_name = _public_detector_name(selected_detector)
            detector_before = _detector_failure(detector_name, text, exc)

    uses_surrogate = mode in _SURROGATE_MODES and not cfg.rewriter_provider
    surrogate_before = _surrogate(current, cfg) if uses_surrogate else None

    # 1. Unicode sanitize (front of the pipeline for every wrapped mode).
    if mode in _SANITIZE_WRAPPED:
        current, removed, by_category = _run_sanitize(current, cfg.sanitize_profile)
        front_removed += removed
        stages.append(
            {
                "stage": "sanitize",
                "removed": removed,
                "detail": {"by_category": by_category},
                "_changed": bool(removed),
            }
        )

    # 2. Statistical scrub.
    checkpoint()
    rewrite_source = current
    candidate = current
    auto_selected = None
    try:
        if mode != "sanitize" and cfg.rewriter_provider:
            transform_attempted = True
            declared = provider_manifest(cfg.rewriter_provider)
            if declared is None:
                raise TypeError("provider requires a registered static transformer manifest")
            enforce_consent(declared, cfg)
            provider_factory = get_provider(cfg.rewriter_provider)
            provider = provider_factory(safe_extension_config(cfg))
            actual = static_capability(provider, "transformer")
            if not manifests_match(declared, actual):
                raise TypeError("provider instance capability does not match its static manifest")
            if not provider.available():
                transform_failed = True
                stages.append(
                    {
                        "stage": "provider",
                        "backend": cfg.rewriter_provider,
                        "error": "configured provider is unavailable",
                    }
                )
            else:
                raw_candidate, detail = provider.rewrite(
                    rewrite_source,
                    mode=mode,
                    passes=passes,
                    epsilon=epsilon,
                    beta=beta,
                    best_of=best_of,
                )
                if not isinstance(raw_candidate, str) or not isinstance(detail, Mapping):
                    raise TypeError("provider returned an invalid rewrite contract")
                candidate = raw_candidate
                stages.append(_provider_stage(cfg.rewriter_provider, detail))
        elif mode == "auto":
            transform_attempted = True
            candidate, auto_stages, auto_selected = _auto_scrub(rewrite_source, beta, passes, cfg)
            stages.extend(auto_stages)
        elif mode in ("paraphrase", "full"):
            transform_attempted = True
            candidate, para_stages = recursive_paraphrase(rewrite_source, passes, config=cfg)
            stages.extend(para_stages)
        elif mode == "sira":
            transform_attempted = True
            candidate, detail = sira.sira_rewrite(rewrite_source, epsilon, config=cfg)
            stages.append(detail)
        elif mode == "bias_inversion":
            transform_attempted = True
            candidate, detail = bira.bira_rewrite(rewrite_source, beta, config=cfg)
            stages.append(detail)
        elif mode == "adversarial":
            transform_attempted = True
            candidate, detail = _adversarial_best_of(rewrite_source, best_of, epsilon, cfg)
            stages.append(detail)
    except Exception as exc:
        transform_failed = True
        candidate = rewrite_source
        stages.append(
            {
                "stage": "transform",
                "error": safe_error("transform", exc),
                "_accepted": False,
            }
        )

    # Every built-in and third-party candidate crosses the same whole-document
    # gate. Backend-internal gates are useful retry signals, never final authority.
    if transform_attempted and not transform_failed:
        central_quality = _quality_report(rewrite_source, candidate, cfg)
        accepted = central_quality.passed
        stages.append(
            {
                "stage": "quality_gate",
                "quality": _public_quality(central_quality),
                "scope": "whole_document",
                "_accepted": accepted,
                "_changed": False,
                **({} if accepted else {"warning": "candidate rejected by central quality gate"}),
            }
        )
        if accepted:
            current = candidate
        else:
            current = rewrite_source
            quality_rejected = candidate != rewrite_source

    # 3. Re-sanitize + verify for every scrubbing mode (a rewrite can reintroduce
    #    exotic characters, and we assert the Unicode channel is clean at the end).
    if mode in _VERIFY_WRAPPED:
        resanitized, re_by_category = sanitize(current, profile=cfg.sanitize_profile)
        candidate_removed = sum(re_by_category.values())
        if resanitized != current:
            post_quality = _quality_report(rewrite_source, resanitized, cfg)
            stages.append(
                {
                    "stage": "post_sanitize_quality_gate",
                    "quality": _public_quality(post_quality),
                    "scope": "whole_document",
                    "_accepted": post_quality.passed,
                    "_changed": False,
                    **(
                        {}
                        if post_quality.passed
                        else {"warning": "post-sanitize candidate rejected by quality gate"}
                    ),
                }
            )
            if post_quality.passed:
                current = resanitized
                post_removed = candidate_removed
                central_quality = post_quality
            else:
                current = rewrite_source
                quality_rejected = True
                post_removed = 0

    statistical_changed = transform_attempted and current != rewrite_source
    detector_after: Optional[DetectionEvidence] = None
    statistical_verification: VerificationStatus = "not_verifiable"
    verification_reason = "no independent named detector was configured"
    if detector_instance is not None and detector_name is not None and detector_before is not None:
        detector_after = run_detector(
            detector_instance, current, fallback_name=detector_name, config=cfg
        )
        paired = evaluate_verification(
            detector_before,
            detector_after,
            detector_instance,
            detector_name=detector_name,
        )
        statistical_verification = paired.status
        verification_reason = paired.reason or "named detector cleared"
        if transform_attempted and detector_is_unicode:
            statistical_verification = "not_verifiable"
            verification_reason = (
                "the Unicode artifact detector cannot verify a statistical mitigation"
            )

    if (
        statistical_changed
        and getattr(cfg, "require_verified", False)
        and statistical_verification != "verified_cleared"
    ):
        evidence_statuses = {
            item.status for item in (detector_before, detector_after) if item is not None
        }
        unsupported_scheme = (
            detector_instance is None
            or detector_is_unicode
            or bool(
                evidence_statuses
                & {"unsupported", "configuration_mismatch", "insufficient_evidence"}
            )
        )
        current = rewrite_source
        statistical_changed = False
        post_removed = 0
        stages.append(
            {
                "stage": "verification_gate",
                "warning": "candidate rejected because verified mitigation was required",
                "reason": verification_reason,
                "_accepted": False,
                "_changed": False,
            }
        )
        if detector_instance is not None and detector_name is not None:
            detector_after = run_detector(
                detector_instance, current, fallback_name=detector_name, config=cfg
            )
            if detector_before is not None:
                paired = evaluate_verification(
                    detector_before,
                    detector_after,
                    detector_instance,
                    detector_name=detector_name,
                )
                statistical_verification = paired.status
                verification_reason = paired.reason or verification_reason
                if detector_is_unicode:
                    statistical_verification = "not_verifiable"
                    verification_reason = (
                        "the Unicode artifact detector cannot verify a statistical mitigation"
                    )

    unicode_after = run_detector(unicode_detector, current, config=cfg)
    unicode_paired = evaluate_verification(
        unicode_before,
        unicode_after,
        unicode_detector,
        detector_name=unicode_detector.capability.identifier,
    )
    if mode in _VERIFY_WRAPPED:
        stages.append(
            {
                "stage": "verify",
                "remaining_flags": int(unicode_after.details.get("total_flags", 0)),
                "detector": unicode_detector.capability.identifier,
                "verification_status": unicode_paired.status,
                "_changed": False,
            }
        )

    if unsupported_scheme:
        transformation_status: TransformationStatus = "unsupported_scheme"
    elif quality_rejected:
        transformation_status = "rejected_quality"
    elif transform_failed:
        transformation_status = "failed"
    elif (
        statistical_changed
        and not detector_is_unicode
        and statistical_verification == "verified_cleared"
    ):
        transformation_status = "mitigation_verified"
    elif statistical_changed:
        transformation_status = "mitigation_unverified"
    elif current != text and unicode_paired.status == "verified_cleared":
        transformation_status = "unicode_sanitized"
    else:
        transformation_status = "unchanged"

    if detector_before is not None:
        detection_status: DetectionStatus = (
            detector_before.status if detector_before is not None else "unsupported"
        )
        verification_status = statistical_verification
        outcome_detector = detector_name
    else:
        detection_status = unicode_before.status
        verification_status = unicode_paired.status
        outcome_detector = unicode_detector.capability.identifier

    metadata: dict[str, Any] = {
        "paraphrase_passes": passes if mode in ("paraphrase", "full") else 0,
        "latency_ms": round((time.monotonic() - started) * 1000, 3),
    }
    if auto_selected is not None:
        metadata["auto_selected"] = auto_selected
        if auto_selected in ("sanitize_only", "paraphrase_fallback"):
            emit(cfg, "pipeline.fallback", mode=mode, selected=auto_selected)
    if uses_surrogate:
        metadata["surrogate_before"] = surrogate_before
        metadata["surrogate_after"] = _surrogate(current, cfg)

    metadata["channels"] = {
        "unicode": {
            "before": unicode_before.to_dict(),
            "after": unicode_after.to_dict(),
            "verification_status": unicode_paired.status,
        },
        "statistical": {
            "before": detector_before.to_dict() if detector_before else None,
            "after": detector_after.to_dict() if detector_after else None,
            "verification_status": statistical_verification,
            "reason": verification_reason,
        },
    }

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
    if transformation_status == "failed" and current == text:
        status: ResultStatus = "failed"
    elif transformation_status in (
        "mitigation_unverified",
        "rejected_quality",
        "unsupported_scheme",
    ):
        status = "partial"
    elif errors and current == text:
        status = "failed"
    elif errors or warnings:
        status = "partial"
    elif current != text:
        status = "success"
    else:
        status = "unchanged"
    fallback_value = metadata.get("auto_selected")
    fallback_reason = fallback_value if fallback_value == "sanitize_only" else None
    total_removed = front_removed + post_removed
    receipt_detector = (
        detector_instance
        if detector_instance is not None
        else (unicode_detector if detector_before is None else None)
    )
    receipt_detector_name = outcome_detector or unicode_detector.capability.identifier
    receipt_policy = _receipt_policy(cfg)
    receipt_resources = context.ledger()
    receipt_resources["latency_ms"] = metadata["latency_ms"]
    receipt = EvidenceReceipt(
        input_sha256=hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
        output_sha256=hashlib.sha256(current.encode("utf-8", "surrogatepass")).hexdigest(),
        mode=mode,
        detection=detection_status,
        transformation=transformation_status,
        verification=verification_status,
        changed=current != text,
        detector=outcome_detector,
        detector_before=detector_before if detector_before is not None else unicode_before,
        detector_after=(
            detector_after
            if detector_after is not None
            else (unicode_after if detector_before is None else None)
        ),
        quality=_public_quality(central_quality) if central_quality is not None else {},
        resources=receipt_resources,
        provenance=_receipt_provenance(
            cfg,
            mode,
            receipt_detector,
            receipt_detector_name,
        ),
        policy=receipt_policy,
        warnings=warnings,
        claim_scope=_claim_scope(
            transformation_status,
            verification_status,
            receipt_detector_name,
        ),
    )
    metadata["assurance"] = receipt.to_dict()
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
        detection_status=detection_status,
        transformation_status=transformation_status,
        verification_status=verification_status,
        detector=outcome_detector,
    )
    emit(
        cfg,
        "pipeline.finished",
        mode=mode,
        status=status,
        changed=current != text,
        latency_ms=metadata["latency_ms"],
    )
    return RemovalResult(cleaned_text=current, stages=typed_stages, report=report, receipt=receipt)


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
    limit = getattr(cfg, "max_batch_items", 1000)
    items = list(itertools.islice(iter(texts), limit + 1))
    if len(items) > limit:
        raise ValueError(f"batch exceeds max_batch_items={limit}")
    if max_workers is not None and max_workers < 1:
        raise ValueError("max_workers must be positive")
    workers = min(max_workers or cfg.max_concurrency, cfg.max_concurrency)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dewatermark") as pool:
        futures = [pool.submit(remove, text, mode=mode, config=cfg, **options) for text in items]
        outcomes = []
        for index, future in enumerate(futures):
            try:
                outcomes.append(BatchItemResult(index=index, result=future.result()))
            except Exception as exc:
                outcomes.append(BatchItemResult(index=index, error=safe_error("batch item", exc)))
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
