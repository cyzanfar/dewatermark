"""Shared two-phase API for agents and local transports.

Planning is side-effect free. Applying a plan requires the exact digest and an
explicit consent bit, preventing an agent from silently broadening a reviewed
request. The digest is an integrity binding, not an authentication signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import replace
from typing import Any, Mapping, Optional

from .assurance import inspect as detector_inspect
from .assurance import verify as detector_verify
from .config import DewatermarkConfig, get_config
from .extension_safety import extension_identity
from .pipeline import VALID_MODES, remove
from .providers import detector_identity, detector_manifest, provider_identity, provider_manifest
from .runtime import plan
from .unicode import analyze

PLAN_SCHEMA_VERSION = "1.0"
VERIFY_SCHEMA_VERSION = "1.0"
_OPTION_NAMES = {"passes", "epsilon", "beta", "best_of"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PUBLIC_CAPABILITY_METADATA = {
    "calibration",
    "command_protocol_version",
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


class PlanMismatchError(ValueError):
    """The supplied digest does not describe the requested application."""


class ConsentRequiredError(PermissionError):
    """A transformation was requested without explicit per-call consent."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _request_config(
    allow_network: bool,
    allow_model_download: bool,
    require_verified: bool = False,
    config: Optional[DewatermarkConfig] = None,
) -> DewatermarkConfig:
    base = config if config is not None else get_config()
    return replace(
        base,
        fireworks_api_key=base.fireworks_api_key if allow_network else None,
        llm_api_key=base.llm_api_key if allow_network else None,
        allow_remote_processing=bool(allow_network),
        allow_model_download=bool(allow_model_download),
        require_verified=bool(require_verified),
    )


def local_only_config(config: Optional[DewatermarkConfig] = None) -> DewatermarkConfig:
    """Return an explicit no-network, no-download config for compatibility APIs."""
    return replace(
        _request_config(False, False, False, config),
        scorer_provider=None,
        detector_provider=None,
        rewriter_provider=None,
        semantic_scorer=None,
        quality_gate=None,
        chunker=None,
    )


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a registered identifier")
    return value


def _safe_config_identifier(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if _IDENTIFIER.fullmatch(value) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value
    ):
        return value
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _type_identifier(value: Any) -> Optional[str]:
    if value is None:
        return None
    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if isinstance(module, str) and isinstance(qualname, str):
        return f"{module}.{qualname}"
    kind = type(value)
    return f"{kind.__module__}.{kind.__qualname__}"


def _detector_policy(identifier: str, cfg: DewatermarkConfig) -> dict[str, Any]:
    capability = detector_manifest(identifier)
    registration = detector_identity(identifier)
    if capability is None or registration is None:
        raise ValueError(
            f"detector {identifier!r} has no loaded static capability manifest; "
            "explicitly load or register the trusted detector before planning"
        )
    public_metadata = capability.to_dict()["metadata"]
    raw_status = public_metadata.get("status")
    status = (
        raw_status
        if isinstance(raw_status, str) and _IDENTIFIER.fullmatch(raw_status)
        else "registered"
    )
    return {
        "identifier": capability.identifier,
        "version": capability.version,
        "schemes": list(capability.schemes),
        "network_required": capability.network_required,
        "model_download_possible": capability.model_download_possible,
        "requires_secret": capability.requires_secret,
        "minimum_characters": capability.minimum_characters,
        "calibrated": capability.calibrated,
        "independent": capability.independent,
        "available": not status.startswith("unsupported"),
        "status": status,
        "metadata": {
            key: value
            for key, value in public_metadata.items()
            if key in _PUBLIC_CAPABILITY_METADATA
        },
        "registration": registration,
    }


def _policy(
    cfg: DewatermarkConfig,
    require_verified: bool,
    detector: str,
    mode: str,
) -> dict[str, Any]:
    """Redacted consequential config bound into every plan digest."""
    transformer: Optional[dict[str, Any]] = None
    uses_transformer = mode != "sanitize" and bool(cfg.rewriter_provider)
    if uses_transformer and cfg.rewriter_provider:
        manifest = provider_manifest(cfg.rewriter_provider)
        if manifest is None:
            raise ValueError(
                f"provider {cfg.rewriter_provider!r} has no loaded static transformer "
                "manifest; explicitly load or register the trusted provider before planning"
            )
        transformer_registration = provider_identity(cfg.rewriter_provider)
        if transformer_registration is None:
            raise ValueError("provider has no immutable registration identity")
        transformer = {
            **transformer_registration["capability"],
            "registration": {
                key: value for key, value in transformer_registration.items() if key != "capability"
            },
        }
    scorer: Optional[dict[str, Any]] = None
    uses_scorer = (
        not uses_transformer
        and mode in {"auto", "sira", "bias_inversion", "adversarial"}
        and bool(cfg.scorer_provider)
    )
    if uses_scorer and cfg.scorer_provider:
        scorer_manifest = provider_manifest(cfg.scorer_provider, kind="scorer")
        if scorer_manifest is None:
            raise ValueError(
                f"scorer {cfg.scorer_provider!r} has no loaded static scorer manifest; "
                "explicitly load or register the trusted scorer before planning"
            )
        scorer_registration = provider_identity(cfg.scorer_provider, kind="scorer")
        if scorer_registration is None:
            raise ValueError("scorer has no immutable registration identity")
        scorer = {
            **scorer_registration["capability"],
            "registration": {
                key: value for key, value in scorer_registration.items() if key != "capability"
            },
        }
    quality_gate = None
    if mode != "sanitize" and cfg.quality_gate is not None:
        quality_gate = extension_identity(cfg.quality_gate, "quality_gate", instance_sensitive=True)
    semantic_scorer = None
    if (
        mode != "sanitize"
        and cfg.quality_gate is None
        and cfg.semantic_scorer is not None
        and cfg.quality_min_semantic_score is not None
    ):
        semantic_scorer = extension_identity(
            cfg.semantic_scorer, "semantic_scorer", instance_sensitive=True
        )
    chunker = None
    if (
        mode != "sanitize"
        and not uses_transformer
        and mode in {"auto", "sira", "bias_inversion", "adversarial"}
        and cfg.chunker is not None
    ):
        chunker = extension_identity(cfg.chunker, "chunker", instance_sensitive=True)
    public = {
        "sanitize_profile": cfg.sanitize_profile,
        "resolved_lm_backend": cfg.resolved_lm_backend,
        "local_model": _safe_config_identifier(cfg.local_lm),
        "fireworks_model": _safe_config_identifier(cfg.fireworks_model),
        "llm_model": _safe_config_identifier(cfg.llm_model),
        "scorer_provider": (_safe_config_identifier(cfg.scorer_provider) if uses_scorer else None),
        "scorer_capability": scorer,
        "rewriter_provider": (
            _safe_config_identifier(cfg.rewriter_provider) if uses_transformer else None
        ),
        "rewriter_capability": transformer,
        "local_lm_enabled": cfg.local_lm_enabled,
        "random_seed": cfg.random_seed,
        "request_retries": cfg.request_retries,
        "request_timeout": cfg.request_timeout,
        "max_input_chars": cfg.max_input_chars,
        "max_remote_calls": cfg.max_remote_calls,
        "max_output_tokens": cfg.max_output_tokens,
        "max_concurrency": cfg.max_concurrency,
        "model_cache_size": cfg.model_cache_size,
        "max_chunk_chars": cfg.max_chunk_chars,
        "fireworks_endpoint_sha256": hashlib.sha256(
            cfg.fireworks_base_url.encode("utf-8")
        ).hexdigest(),
        "llm_endpoint_sha256": hashlib.sha256(cfg.llm_base_url.encode("utf-8")).hexdigest(),
        "quality_min_length_ratio": cfg.quality_min_length_ratio,
        "quality_max_length_ratio": cfg.quality_max_length_ratio,
        "quality_min_semantic_score": cfg.quality_min_semantic_score,
        "quality_gate": quality_gate,
        "semantic_scorer": semantic_scorer,
        "chunker": chunker,
        "require_verified": bool(require_verified),
        "detector": _detector_policy(detector, cfg),
    }
    digest = hashlib.sha256(_canonical_json(public).encode("utf-8")).hexdigest()
    return {
        "require_verified": bool(require_verified),
        "detector": public["detector"],
        "config": public,
        "config_sha256": digest,
    }


def _bind_extension_requirements(
    execution: dict[str, Any], policy: Mapping[str, Any], cfg: DewatermarkConfig
) -> None:
    public = policy["config"]
    capabilities: list[Mapping[str, Any]] = [public["detector"]]
    for key in (
        "rewriter_capability",
        "scorer_capability",
        "quality_gate",
        "semantic_scorer",
        "chunker",
    ):
        value = public.get(key)
        if not isinstance(value, Mapping):
            continue
        nested = value.get("capability")
        capabilities.append(nested if isinstance(nested, Mapping) else value)
    needs_network = any(bool(item.get("network_required")) for item in capabilities)
    needs_download = any(bool(item.get("model_download_possible")) for item in capabilities)
    needs_secret = any(bool(item.get("requires_secret")) for item in capabilities)
    execution["network_required"] = bool(execution.get("network_required") or needs_network)
    execution["model_download_possible"] = bool(
        execution.get("model_download_possible") or needs_download
    )
    permitted = (
        (not needs_network or cfg.allow_remote_processing)
        and (not needs_download or cfg.allow_model_download)
        and not needs_secret
    )
    if not permitted:
        execution["available"] = False
        execution["reason"] = (
            "an active extension requires a scoped secret channel that is unavailable"
            if needs_secret
            else "active extension requirements are not explicitly permitted"
        )


def _validate_text(text: Any, cfg: DewatermarkConfig, name: str = "text") -> str:
    if not isinstance(text, str) or not text:
        raise ValueError(f"{name} must be a non-empty string")
    if len(text) > cfg.max_input_chars:
        raise ValueError(f"{name} exceeds max_input_chars={cfg.max_input_chars}")
    return text


def _options(value: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    options = dict(value or {})
    unknown = sorted(set(options) - _OPTION_NAMES)
    if unknown:
        raise ValueError("request contains an unsupported removal option")
    return options


def inspect_text(
    text: str,
    detector: str = "unicode",
    *,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Inspect without transforming, loading a model, or using the network."""
    cfg = local_only_config(config)
    text = _validate_text(text, cfg)
    detector = _identifier(detector, "detector")
    _detector_policy(detector, cfg)
    report = analyze(text)
    evidence = detector_inspect(text, detector, config=cfg).to_dict()
    return {
        "schema_version": "1.0",
        "input_sha256": _sha256_text(text),
        "detector_evidence": evidence,
        **report,
    }


def create_plan(
    text: str,
    mode: str = "auto",
    *,
    detector: str = "unicode",
    allow_network: bool = False,
    allow_model_download: bool = False,
    require_verified: bool = False,
    options: Optional[Mapping[str, Any]] = None,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Create a content-bound, side-effect-free transformation plan."""
    if mode not in VALID_MODES:
        raise ValueError("mode is not supported")
    detector = _identifier(detector, "detector")
    if allow_model_download and not allow_network:
        raise ValueError("allow_model_download=true requires allow_network=true")
    normalized_options = _options(options)
    cfg = _request_config(allow_network, allow_model_download, require_verified, config)
    text = _validate_text(text, cfg)
    policy = _policy(cfg, require_verified, detector, mode)
    execution = plan(
        mode,  # type: ignore[arg-type]
        cfg,
        passes=int(normalized_options.get("passes", 2)),
        best_of=int(normalized_options.get("best_of", 3)),
    ).to_dict()
    execution["backend"] = _safe_config_identifier(str(execution["backend"]))
    _bind_extension_requirements(execution, policy, cfg)
    binding = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "input_sha256": _sha256_text(text),
        "mode": mode,
        "detector": detector,
        "options": normalized_options,
        "permissions": {
            "allow_network": bool(allow_network),
            "allow_model_download": bool(allow_model_download),
        },
        "policy": policy,
        "execution": execution,
    }
    digest = hashlib.sha256(_canonical_json(binding).encode("utf-8")).hexdigest()
    return {
        **binding,
        "plan_digest": digest,
        "digest_algorithm": "sha256",
        "consent_required": True,
        "digest_is_authentication": False,
    }


def apply_plan(
    text: str,
    plan_digest: str,
    mode: str = "auto",
    *,
    detector: str = "unicode",
    consent: bool = False,
    allow_network: bool = False,
    allow_model_download: bool = False,
    require_verified: bool = False,
    options: Optional[Mapping[str, Any]] = None,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Apply exactly the reviewed plan and return an auditable envelope."""
    if not consent:
        raise ConsentRequiredError("apply requires explicit consent=true")
    reviewed = create_plan(
        text,
        mode,
        detector=detector,
        allow_network=allow_network,
        allow_model_download=allow_model_download,
        require_verified=require_verified,
        options=options,
        config=config,
    )
    if not isinstance(plan_digest, str) or not hmac.compare_digest(
        plan_digest, reviewed["plan_digest"]
    ):
        raise PlanMismatchError(
            "plan digest does not match text, detector, mode, options, permissions, or policy"
        )
    cfg = _request_config(allow_network, allow_model_download, require_verified, config)
    result = remove(
        text,
        mode=mode,  # type: ignore[arg-type]
        detector=detector,
        config=cfg,
        **_options(options),
    )
    return {
        "schema_version": "1.0",
        "operation": "apply",
        "plan_digest": reviewed["plan_digest"],
        "input_sha256": reviewed["input_sha256"],
        "output_sha256": _sha256_text(result.cleaned_text),
        "consent": {
            "transformation": True,
            "network": bool(allow_network),
            "model_download": bool(allow_model_download),
        },
        "policy": reviewed["policy"],
        "result": result.to_dict(),
    }


def verify_text(
    source_text: str,
    candidate_text: str,
    detector: str = "unicode-artifacts-v1",
    *,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Verify a candidate with a named local detector or explicitly abstain."""
    cfg = local_only_config(config)
    source_text = _validate_text(source_text, cfg, "source_text")
    candidate_text = _validate_text(candidate_text, cfg, "candidate_text")
    detector = _identifier(detector, "detector")
    base = {
        "schema_version": VERIFY_SCHEMA_VERSION,
        "detector": detector,
        "source_sha256": _sha256_text(source_text),
        "candidate_sha256": _sha256_text(candidate_text),
    }
    selected = "unicode-artifacts-v1" if detector == "unicode-policy-v1" else detector
    _detector_policy(selected, cfg)
    evidence = detector_verify(source_text, candidate_text, selected, config=cfg).to_dict()
    before = evidence.get("before", {})
    after = evidence.get("after", {})
    return {
        **base,
        "detector": evidence.get("detector", selected),
        "detection_status": before.get("status", "insufficient_evidence"),
        "verification_status": evidence["status"],
        "before": before,
        "after": after,
        "reason": evidence.get("reason"),
        "claim_scope": (
            "Verification is limited to the named detector and configuration; "
            "it is not an authorship classification."
        ),
    }
