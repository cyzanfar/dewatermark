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
from .exceptions import ConfigurationError
from .extension_safety import (
    ReviewedExtensionMismatch,
    extension_identity,
    reviewed_extension_scope,
)
from .pipeline import VALID_MODES, remove
from .providers import detector_identity, detector_manifest, provider_identity, provider_manifest
from .quality import QualityGateBinding
from .runtime import plan
from .unicode import analyze

PLAN_SCHEMA_VERSION = "1.0"
VERIFY_SCHEMA_VERSION = "1.0"
_OPTION_NAMES = {"passes", "epsilon", "beta", "best_of"}
_OPTION_DEFAULTS: dict[str, int | float] = {
    "passes": 2,
    "epsilon": 0.3,
    "beta": 6.0,
    "best_of": 3,
}
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
_CAPABILITY_FIELDS = {
    "identifier",
    "kind",
    "version",
    "schemes",
    "description",
    "network_required",
    "model_download_possible",
    "requires_secret",
    "minimum_characters",
    "calibrated",
    "independent",
    "metadata",
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
        quality_gates=(),
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


def _detector_policy(identifier: str, cfg: DewatermarkConfig) -> dict[str, Any]:
    capability = detector_manifest(identifier)
    registration = detector_identity(identifier)
    if capability is None or registration is None:
        raise ValueError(
            "detector has no loaded static capability manifest; "
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
                "provider has no loaded static transformer "
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
                "scorer has no loaded static scorer manifest; "
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
    quality_gates: list[dict[str, Any]] = []
    if mode != "sanitize":
        for item in cfg.quality_gates:
            binding = item if type(item) is QualityGateBinding else QualityGateBinding(item)
            quality_gates.append(
                {
                    "required": binding.required,
                    **extension_identity(
                        binding.gate,
                        "quality_gate",
                        instance_sensitive=True,
                    ),
                }
            )
    semantic_scorer = None
    if (
        mode != "sanitize"
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
        "quality_gates": quality_gates,
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
        "quality_gates",
        "semantic_scorer",
        "chunker",
    ):
        value = public.get(key)
        if isinstance(value, list):
            for item in value:
                if not isinstance(item, Mapping):
                    continue
                nested = item.get("capability")
                capabilities.append(nested if isinstance(nested, Mapping) else item)
            continue
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


def _registration_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    registration = value.get("registration")
    if not isinstance(registration, Mapping):
        raise PlanMismatchError("reviewed extension registration is incomplete")
    capability = {key: value[key] for key in _CAPABILITY_FIELDS if key in value}
    return {"capability": capability, **dict(registration)}


def _reviewed_extensions(
    cfg: DewatermarkConfig,
    detector: str,
    policy: Mapping[str, Any],
) -> tuple[list[tuple[Any, Mapping[str, Any]]], dict[tuple[str, str], Mapping[str, Any]]]:
    public = policy.get("config")
    if not isinstance(public, Mapping):
        raise PlanMismatchError("reviewed extension policy is incomplete")
    targets: list[tuple[Any, Mapping[str, Any]]] = []
    registrations: dict[tuple[str, str], Mapping[str, Any]] = {}

    detector_policy = public.get("detector")
    if not isinstance(detector_policy, Mapping):
        raise PlanMismatchError("reviewed detector policy is incomplete")
    detector_registration = detector_policy.get("registration")
    if not isinstance(detector_registration, Mapping):
        raise PlanMismatchError("reviewed detector registration is incomplete")
    registrations[("detector", detector.strip().lower())] = detector_registration

    for name, policy_key in (
        (cfg.rewriter_provider, "rewriter_capability"),
        (cfg.scorer_provider, "scorer_capability"),
    ):
        value = public.get(policy_key)
        if name and isinstance(value, Mapping):
            registrations[("provider", name.strip().lower())] = _registration_identity(value)

    for target, policy_key in (
        (cfg.quality_gate, "quality_gate"),
        (cfg.semantic_scorer, "semantic_scorer"),
        (cfg.chunker, "chunker"),
    ):
        value = public.get(policy_key)
        if target is not None and isinstance(value, Mapping):
            targets.append((target, value))

    configured_gates = list(cfg.quality_gates)
    reviewed_gates = public.get("quality_gates")
    if reviewed_gates:
        if not isinstance(reviewed_gates, list) or len(reviewed_gates) != len(configured_gates):
            raise PlanMismatchError("reviewed quality-gate policy is incomplete")
        for configured, reviewed in zip(configured_gates, reviewed_gates):
            if not isinstance(reviewed, Mapping):
                raise PlanMismatchError("reviewed quality-gate policy is incomplete")
            binding = (
                configured
                if type(configured) is QualityGateBinding
                else QualityGateBinding(configured)
            )
            targets.append(
                (
                    binding.gate,
                    {key: value for key, value in reviewed.items() if key != "required"},
                )
            )
    return targets, registrations


def _validate_text(text: Any, cfg: DewatermarkConfig, name: str = "text") -> str:
    if not isinstance(text, str) or not text:
        raise ValueError(f"{name} must be a non-empty string")
    if len(text) > cfg.max_input_chars:
        raise ValueError(f"{name} exceeds max_input_chars={cfg.max_input_chars}")
    return text


def _options(value: Optional[dict[str, Any]]) -> dict[str, Any]:
    if value is not None and type(value) is not dict:
        raise ValueError("options must be an object")
    options: dict[str, Any] = {}
    if value is not None:
        # Iterate an exact built-in dict and validate each key before lookup.
        # This keeps side-effect-free planning from invoking custom Mapping,
        # key hashing, conversion, or representation hooks.
        for key in value:
            if type(key) is not str or key not in _OPTION_NAMES:
                raise ValueError("request contains an unsupported removal option")
            options[key] = dict.__getitem__(value, key)
    normalized = {**_OPTION_DEFAULTS, **options}
    passes = normalized["passes"]
    epsilon = normalized["epsilon"]
    beta = normalized["beta"]
    best_of = normalized["best_of"]
    if type(passes) is not int or not 1 <= passes <= 5:
        raise ValueError("passes must be an integer between 1 and 5")
    if type(epsilon) not in (int, float) or not 0.05 <= epsilon <= 0.9:
        raise ValueError("epsilon must be a number between 0.05 and 0.9")
    if type(beta) not in (int, float) or not 0.0 <= beta <= 20.0:
        raise ValueError("beta must be a number between 0 and 20")
    if type(best_of) is not int or not 1 <= best_of <= 6:
        raise ValueError("best_of must be an integer between 1 and 6")
    return {
        "passes": passes,
        "epsilon": float(epsilon),
        "beta": 0.0 if beta == 0 else float(beta),
        "best_of": best_of,
    }


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
    options: Optional[dict[str, Any]] = None,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Create a content-bound, side-effect-free transformation plan."""
    if type(mode) is not str or mode not in VALID_MODES:
        raise ValueError("mode is not supported")
    for name, value in (
        ("allow_network", allow_network),
        ("allow_model_download", allow_model_download),
        ("require_verified", require_verified),
    ):
        if type(value) is not bool:
            raise ValueError(f"{name} must be a boolean")
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
        passes=normalized_options["passes"],
        best_of=normalized_options["best_of"],
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
    options: Optional[dict[str, Any]] = None,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Apply exactly the reviewed plan and return an auditable envelope."""
    if not consent:
        raise ConsentRequiredError("apply requires explicit consent=true")
    try:
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
    except ConfigurationError:
        raise PlanMismatchError("reviewed extension policy is no longer available") from None
    if not isinstance(plan_digest, str) or not hmac.compare_digest(
        plan_digest, reviewed["plan_digest"]
    ):
        raise PlanMismatchError(
            "plan digest does not match text, detector, mode, options, permissions, or policy"
        )
    cfg = _request_config(allow_network, allow_model_download, require_verified, config)
    targets, registrations = _reviewed_extensions(cfg, detector, reviewed["policy"])
    try:
        with reviewed_extension_scope(targets, registrations):
            result = remove(
                text,
                mode=mode,  # type: ignore[arg-type]
                detector=detector,
                config=cfg,
                **reviewed["options"],
            )
    except ReviewedExtensionMismatch:
        raise PlanMismatchError("reviewed extension identity changed before execution") from None
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
