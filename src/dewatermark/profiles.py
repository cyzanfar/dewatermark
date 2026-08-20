"""Content-addressed, operator-scoped mitigation profiles.

Profiles bind an exact primary detector, held-out verifier portfolio, strategy
portfolio, quality policy, random seed, and search limits.  They contain only
public identifiers and digests: operator keys, credentials, filesystem paths,
and source text are deliberately outside this contract.

Loading and inspecting a profile never imports plugin code, starts a command,
loads a model, opens a socket, or reads an operator secret.  Execution is a
separate, explicit-consent boundary that resolves the already declared
components and delegates final acceptance to :func:`dewatermark.mitigate`.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence, cast

from .command_safety import command_code_identities_sha256, validate_public_json
from .config import DewatermarkConfig, resolve
from .exceptions import ConfigurationError
from .extension_safety import (
    ReviewedExtensionMismatch,
    enforce_consent,
    extension_identity,
    manifest_sha256,
    manifests_match,
    reviewed_extension_scope,
    safe_extension_config,
    static_capability,
)
from .models import CapabilityManifest, _public_identifier
from .optimizer import (
    MitigationResult,
    SearchLimits,
    SignalSpan,
    StrategyBinding,
    mitigate,
)
from .providers import (
    detector_binding_identity,
    detector_manifest,
    get_detector,
    get_provider,
    provider_identity,
    provider_manifest,
)
from .quality import QualityGateBinding
from .strategies import context_aware_strategy

MITIGATION_PROFILE_SCHEMA_VERSION = "1.0"
_MAX_PROFILE_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_COMPONENT_FIELDS = {
    "name",
    "capability_sha256",
    "implementation_sha256",
    "static_state_sha256",
}
_COMMAND_COMPONENT_FIELDS = _COMPONENT_FIELDS | {
    "command_code_sha256",
    "command_code_raw_sha256",
    "external_implementation_sha256",
}
_STRATEGY_FIELDS = _COMPONENT_FIELDS | {"options"}
_SEARCH_FIELDS = {
    "max_rounds",
    "beam_width",
    "max_candidates",
    "max_transform_calls",
    "max_detector_queries",
    "max_candidate_characters",
    "max_verification_candidates",
}
_PROFILE_FIELDS = {
    "schema_version",
    "profile_id",
    "classification",
    "scheme",
    "watermark_target_sha256",
    "key_id",
    "primary",
    "verifiers",
    "strategies",
    "quality_policy",
    "random_seed",
    "search_limits",
    "evidence",
    "profile_sha256",
}
_CONTEXT_AWARE_STRATEGY = "context-aware-minimal-edit-v1"


class MitigationProfileError(ValueError):
    """A profile is malformed, unavailable, or no longer matches its components."""


class MitigationProfileConsentError(PermissionError):
    """Executing a profile requires explicit caller consent."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _freeze_json(value: Any) -> Any:
    """Return an immutable tree made only from already-validated JSON values."""
    if type(value) is dict:
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    """Detach an immutable profile tree for serialization or caller mutation."""
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _public_profile_tree(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        public = validate_public_json(value, source="mitigation profile")
    except (TypeError, ValueError):
        raise MitigationProfileError("mitigation profile contains unsafe public metadata") from None
    if not isinstance(public, dict):
        raise MitigationProfileError("mitigation profile must be a plain JSON object")

    def reject_surrogates(item: Any) -> None:
        if type(item) is str:
            try:
                item.encode("utf-8", "strict")
            except UnicodeError:
                raise MitigationProfileError(
                    "mitigation profile contains invalid Unicode"
                ) from None
        elif type(item) is dict:
            for key, nested in item.items():
                reject_surrogates(key)
                reject_surrogates(nested)
        elif type(item) is list:
            for nested in item:
                reject_surrogates(nested)

    reject_surrogates(public)
    if len(_canonical_json(public)) > _MAX_PROFILE_BYTES:
        raise MitigationProfileError("mitigation profile exceeds the size limit")
    return public


def mitigation_profile_sha256(value: Mapping[str, Any]) -> str:
    """Return the canonical profile digest, excluding ``profile_sha256`` itself."""
    if type(value) is not dict:
        raise MitigationProfileError("mitigation profile must be a plain JSON object")
    projected = {key: item for key, item in value.items() if key != "profile_sha256"}
    public = _public_profile_tree(projected)
    return hashlib.sha256(_canonical_json(public)).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MitigationProfileError("mitigation profile contains duplicate JSON keys")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise MitigationProfileError("mitigation profile numbers must be finite")


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise MitigationProfileError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not _PUBLIC_ID.fullmatch(value)
        or _public_identifier(value) != value
    ):
        raise MitigationProfileError(f"{label} must be a safe public identifier")
    return value


def _component(value: Any, label: str, *, strategy: bool = False) -> dict[str, Any]:
    expected_fields = (
        (_STRATEGY_FIELDS,)
        if strategy
        else (
            _COMPONENT_FIELDS,
            _COMMAND_COMPONENT_FIELDS,
        )
    )
    if type(value) is not dict or set(value) not in expected_fields:
        raise MitigationProfileError(f"{label} fields do not match profile v1")
    result: dict[str, Any] = {
        "name": _identifier(value.get("name"), f"{label} name"),
        "capability_sha256": _sha256(value.get("capability_sha256"), f"{label} capability_sha256"),
        "implementation_sha256": _sha256(
            value.get("implementation_sha256"), f"{label} implementation_sha256"
        ),
        "static_state_sha256": _sha256(
            value.get("static_state_sha256"), f"{label} static_state_sha256"
        ),
    }
    if strategy:
        options = value.get("options")
        if type(options) is not dict:
            raise MitigationProfileError("strategy options must be one plain public object")
        try:
            normalized = validate_public_json(options, source="strategy options")
        except (TypeError, ValueError):
            raise MitigationProfileError(
                "strategy options contain unsafe public metadata"
            ) from None
        assert isinstance(normalized, dict)
        result["options"] = normalized
    elif set(value) == _COMMAND_COMPONENT_FIELDS:
        result["command_code_sha256"] = _sha256(
            value.get("command_code_sha256"), f"{label} command_code_sha256"
        )
        result["command_code_raw_sha256"] = _sha256(
            value.get("command_code_raw_sha256"), f"{label} command_code_raw_sha256"
        )
        result["external_implementation_sha256"] = _sha256(
            value.get("external_implementation_sha256"),
            f"{label} external_implementation_sha256",
        )
    return result


def _detector_distinctness_fields(value: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """Project the same effective identities used by ``DetectorSession``.

    Native detectors use their Python implementation for both behavior and code
    identity. Exact command factories instead use the separately reviewed
    external implementation commitment and semantic executable/script digest;
    their shared host wrapper is still profile-bound but cannot manufacture an
    alias or prevent genuinely distinct commands from being paired. The exact
    raw digest is a drift pin, not evidence of methodological independence.
    """
    external = value.get("external_implementation_sha256")
    command_code = value.get("command_code_sha256")
    implementation = str(value["implementation_sha256"])
    return (
        str(value["capability_sha256"]),
        str(external) if type(external) is str else implementation,
        str(value["static_state_sha256"]),
        str(command_code) if type(command_code) is str else implementation,
    )


def _search_limits(value: Any) -> dict[str, int]:
    if type(value) is not dict or set(value) != _SEARCH_FIELDS:
        raise MitigationProfileError("search_limits fields do not match profile v1")
    try:
        limits = SearchLimits(**value)
    except (TypeError, ValueError):
        raise MitigationProfileError("search_limits are outside the supported bounds") from None
    return {
        "max_rounds": limits.max_rounds,
        "beam_width": limits.beam_width,
        "max_candidates": limits.max_candidates,
        "max_transform_calls": limits.max_transform_calls,
        "max_detector_queries": limits.max_detector_queries,
        "max_candidate_characters": limits.max_candidate_characters,
        "max_verification_candidates": limits.max_verification_candidates,
    }


def _evidence(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise MitigationProfileError("evidence must be one plain object")
    if set(value) != {"status", "protocol_sha256"}:
        raise MitigationProfileError("protocol-only evidence fields do not match profile v1")
    if value.get("status") != "protocol_only_no_results":
        raise MitigationProfileError("mitigation profiles support protocol-only evidence")
    return {
        "status": "protocol_only_no_results",
        "protocol_sha256": _sha256(value.get("protocol_sha256"), "protocol_sha256"),
    }


@dataclass(frozen=True, repr=False)
class MitigationProfile:
    """Validated immutable public profile."""

    value: Mapping[str, Any]

    def __post_init__(self) -> None:
        # A public constructor must not bypass validation or retain a caller's
        # mutable nested dictionaries after the profile has been reviewed.
        normalized = _validated_profile_value(self.value)
        object.__setattr__(self, "value", _freeze_json(normalized))

    def __repr__(self) -> str:
        return "<dewatermark mitigation profile; public identifiers and digests>"

    @property
    def profile_id(self) -> str:
        return str(self.value["profile_id"])

    @property
    def profile_sha256(self) -> str:
        return str(self.value["profile_sha256"])

    def to_dict(self) -> dict[str, Any]:
        detached = _thaw_json(self.value)
        assert type(detached) is dict
        return detached


def _validated_profile_value(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return one detached normalized v1 profile value."""
    if type(value) is not dict or set(value) != _PROFILE_FIELDS:
        raise MitigationProfileError("mitigation profile fields do not match profile v1")
    public = _public_profile_tree(value)
    if public.get("schema_version") != MITIGATION_PROFILE_SCHEMA_VERSION:
        raise MitigationProfileError("unsupported mitigation profile schema_version")
    if public.get("classification") != "operator_scoped_detector_profile":
        raise MitigationProfileError("mitigation profile classification is invalid")
    profile_id = _identifier(public.get("profile_id"), "profile_id")
    scheme = _identifier(public.get("scheme"), "scheme")
    target = _sha256(public.get("watermark_target_sha256"), "watermark_target_sha256")
    key_id = _identifier(public.get("key_id"), "key_id")
    primary = _component(public.get("primary"), "primary detector")
    raw_verifiers = public.get("verifiers")
    if type(raw_verifiers) is not list or not 1 <= len(raw_verifiers) <= 8:
        raise MitigationProfileError("profiles require between one and eight held-out verifiers")
    verifiers = [
        _component(item, f"verifier {index}") for index, item in enumerate(raw_verifiers, 1)
    ]
    raw_strategies = public.get("strategies")
    if type(raw_strategies) is not list or not 1 <= len(raw_strategies) <= 32:
        raise MitigationProfileError("profiles require between one and 32 strategies")
    strategies = [
        _component(item, f"strategy {index}", strategy=True)
        for index, item in enumerate(raw_strategies, 1)
    ]
    if len({primary["name"], *(item["name"] for item in verifiers)}) != 1 + len(verifiers):
        raise MitigationProfileError("primary and verifier names must be distinct")
    detector_bindings = [primary, *verifiers]
    distinctness = [_detector_distinctness_fields(item) for item in detector_bindings]
    if any(len({item[index] for item in distinctness}) != len(distinctness) for index in range(4)):
        raise MitigationProfileError("primary and verifier implementations must be distinct")
    if len({item["name"] for item in strategies}) != len(strategies):
        raise MitigationProfileError("strategy names must be distinct")
    policy = public.get("quality_policy")
    if type(policy) is not dict or set(policy) != {"policy_id", "policy_sha256"}:
        raise MitigationProfileError("quality_policy fields do not match profile v1")
    quality_policy = {
        "policy_id": _identifier(policy.get("policy_id"), "quality policy id"),
        "policy_sha256": _sha256(policy.get("policy_sha256"), "quality policy sha256"),
    }
    if quality_policy["policy_id"] != "deterministic-required-gates-v1":
        raise MitigationProfileError("quality policy id is unsupported")
    random_seed = public.get("random_seed")
    if type(random_seed) is not int or not 0 <= random_seed <= 2**63 - 1:
        raise MitigationProfileError("random_seed must be a non-negative signed 64-bit integer")
    normalized: dict[str, Any] = {
        "schema_version": MITIGATION_PROFILE_SCHEMA_VERSION,
        "profile_id": profile_id,
        "classification": "operator_scoped_detector_profile",
        "scheme": scheme,
        "watermark_target_sha256": target,
        "key_id": key_id,
        "primary": primary,
        "verifiers": verifiers,
        "strategies": strategies,
        "quality_policy": quality_policy,
        "random_seed": random_seed,
        "search_limits": _search_limits(public.get("search_limits")),
        "evidence": _evidence(public.get("evidence")),
        "profile_sha256": _sha256(public.get("profile_sha256"), "profile_sha256"),
    }
    expected = mitigation_profile_sha256(normalized)
    if normalized["profile_sha256"] != expected:
        raise MitigationProfileError("mitigation profile content digest does not match")
    return normalized


def validate_mitigation_profile(value: Mapping[str, Any]) -> MitigationProfile:
    """Validate one public v1 profile without resolving or importing components."""
    return MitigationProfile(value)


def load_mitigation_profile(path: Path | str) -> MitigationProfile:
    """Read one bounded regular JSON profile without following a final symlink."""
    selected = Path(path)
    descriptor = -1
    try:
        # Reject FIFOs and other special files before open, which could block
        # indefinitely. The descriptor check below closes the replacement race.
        before = os.lstat(selected)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_PROFILE_BYTES:
            raise MitigationProfileError("mitigation profile must be a bounded regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(selected, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_PROFILE_BYTES:
            raise MitigationProfileError("mitigation profile must be a bounded regular file")
        blocks: list[bytes] = []
        remaining = _MAX_PROFILE_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            blocks.append(block)
            remaining -= len(block)
        raw = b"".join(blocks)
        if len(raw) > _MAX_PROFILE_BYTES:
            raise MitigationProfileError("mitigation profile exceeds the size limit")
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except MitigationProfileError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise MitigationProfileError(
            "mitigation profile is not readable strict UTF-8 JSON"
        ) from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if type(value) is not dict:
        raise MitigationProfileError("mitigation profile must contain one JSON object")
    return validate_mitigation_profile(value)


def _quality_identity(value: Any, kind: str) -> Optional[dict[str, str]]:
    if value is None:
        return None
    try:
        # Profiles must survive serialization and reconstruction in another
        # process. The capability, effective implementation, and complete
        # observable static state already form the public content commitment;
        # a process-local instance token would make an equal reconstruction
        # impossible to match.
        identity = extension_identity(value, kind, instance_sensitive=False)
        return {
            "capability_sha256": _sha256(
                identity.get("capability_sha256"), "quality capability_sha256"
            ),
            "implementation_sha256": _sha256(
                identity.get("implementation_sha256"), "quality implementation_sha256"
            ),
            "static_state_sha256": _sha256(
                identity.get("static_state_sha256"), "quality static_state_sha256"
            ),
        }
    except Exception:
        raise MitigationProfileError("quality policy contains an invalid extension") from None


def _reviewed_quality_targets(
    config: DewatermarkConfig,
) -> list[tuple[Any, str, Mapping[str, Any]]]:
    """Snapshot the exact quality objects that may receive candidate text."""
    declared: list[tuple[Any, str]] = []
    if config.semantic_scorer is not None:
        declared.append((config.semantic_scorer, "semantic_scorer"))
    if config.quality_gate is not None:
        declared.append((config.quality_gate, "quality_gate"))
    for item in config.quality_gates:
        binding = item if type(item) is QualityGateBinding else QualityGateBinding(item)
        declared.append((binding.gate, "quality_gate"))
    reviewed: list[tuple[Any, str, Mapping[str, Any]]] = []
    seen: set[int] = set()
    for target, kind in declared:
        if id(target) in seen:
            continue
        seen.add(id(target))
        try:
            identity = extension_identity(target, kind, instance_sensitive=True)
        except Exception:
            raise MitigationProfileError("quality policy contains an invalid extension") from None
        reviewed.append((target, kind, identity))
    return reviewed


def _quality_targets_unchanged(
    reviewed: Sequence[tuple[Any, str, Mapping[str, Any]]],
) -> bool:
    try:
        return all(
            extension_identity(target, kind, instance_sensitive=True) == identity
            for target, kind, identity in reviewed
        )
    except Exception:
        return False


def quality_policy_manifest(config: Optional[DewatermarkConfig] = None) -> dict[str, Any]:
    """Return the public, credential-free quality policy used for acceptance."""
    cfg = resolve(config)
    gates: list[dict[str, Any]] = []
    for item in cfg.quality_gates:
        binding = item if type(item) is QualityGateBinding else QualityGateBinding(item)
        identity = _quality_identity(binding.gate, "quality_gate")
        assert identity is not None
        gates.append({**identity, "required": binding.required})
    value = {
        "policy_version": "1.0",
        "quality_min_length_ratio": float(cfg.quality_min_length_ratio),
        "quality_max_length_ratio": float(cfg.quality_max_length_ratio),
        "quality_min_semantic_score": (
            float(cfg.quality_min_semantic_score)
            if cfg.quality_min_semantic_score is not None
            else None
        ),
        "semantic_scorer": _quality_identity(cfg.semantic_scorer, "semantic_scorer"),
        "legacy_quality_gate": _quality_identity(cfg.quality_gate, "quality_gate"),
        "quality_gates": gates,
    }
    try:
        public = validate_public_json(value, source="quality policy")
    except (TypeError, ValueError):
        raise MitigationProfileError("quality policy is not safely publishable") from None
    assert isinstance(public, dict)
    return public


def quality_policy_sha256(config: Optional[DewatermarkConfig] = None) -> str:
    """Return the stable public digest of the configured candidate-acceptance policy."""
    return hashlib.sha256(_canonical_json(quality_policy_manifest(config))).hexdigest()


def _identity_binding(
    name: str, *, kind: str, options: Optional[Mapping[str, Any]] = None
) -> dict[str, str]:
    capability: Optional[CapabilityManifest] = None
    identity: Optional[dict[str, Any]] = None
    try:
        if kind == "transformer" and name == _CONTEXT_AWARE_STRATEGY:
            instance = context_aware_strategy(**dict(options or {}))
            capability = static_capability(instance, "transformer")
            # The built-in is reconstructed from its profile options at each
            # boundary. Its complete configuration is already part of the
            # capability and static-state commitments, so an ephemeral
            # per-instance identity token would make an otherwise immutable
            # profile impossible to inspect or replay.
            identity = extension_identity(instance, "transformer", instance_sensitive=False)
        elif kind == "detector":
            capability = detector_manifest(name)
            identity = detector_binding_identity(name)
        else:
            capability = provider_manifest(name, kind="transformer")
            identity = provider_identity(name, kind="transformer")
    except ConfigurationError:
        raise MitigationProfileError("profile component is not registered") from None
    if capability is None or identity is None:
        raise MitigationProfileError("profile component is discoverable but not statically loaded")
    binding = {
        "name": name,
        "capability_sha256": manifest_sha256(capability),
        "implementation_sha256": _sha256(
            identity.get("implementation_sha256"), "component implementation_sha256"
        ),
        "static_state_sha256": _sha256(
            identity.get("static_state_sha256"), "component static_state_sha256"
        ),
    }
    command_code = identity.get("command_code_sha256")
    command_code_raw = identity.get("command_code_raw_sha256")
    external_implementation = identity.get("external_implementation_sha256")
    if (
        command_code is not None
        or command_code_raw is not None
        or external_implementation is not None
    ):
        binding["command_code_sha256"] = _sha256(command_code, "component command_code_sha256")
        binding["command_code_raw_sha256"] = _sha256(
            command_code_raw, "component command_code_raw_sha256"
        )
        binding["external_implementation_sha256"] = _sha256(
            external_implementation,
            "component external_implementation_sha256",
        )
    return binding


def build_mitigation_profile(
    profile_id: str,
    *,
    scheme: str,
    watermark_target_sha256: str,
    key_id: str,
    primary_detector: str,
    verifier_detectors: Sequence[str],
    strategies: Sequence[str | tuple[str, Mapping[str, Any]]],
    protocol_sha256: str,
    config: Optional[DewatermarkConfig] = None,
    limits: Optional[SearchLimits] = None,
) -> MitigationProfile:
    """Build a profile from statically registered components without executing them."""
    cfg = resolve(config)
    selected_limits = limits or SearchLimits(
        max_candidates=cfg.max_search_candidates,
        max_transform_calls=cfg.max_search_candidates,
        max_detector_queries=cfg.max_detector_queries,
        max_candidate_characters=cfg.max_input_chars,
    )
    strategy_bindings: list[dict[str, Any]] = []
    for item in strategies:
        name: str
        options: Mapping[str, Any]
        if type(item) is str:
            name, options = item, {}
        elif type(item) is tuple and len(item) == 2 and type(item[0]) is str:
            name, options = item
        else:
            raise MitigationProfileError("strategy declarations are invalid")
        binding: dict[str, Any] = _identity_binding(name, kind="transformer", options=options)
        binding["options"] = dict(options)
        strategy_bindings.append(binding)
    evidence: dict[str, Any] = {
        "status": "protocol_only_no_results",
        "protocol_sha256": protocol_sha256,
    }
    value: dict[str, Any] = {
        "schema_version": MITIGATION_PROFILE_SCHEMA_VERSION,
        "profile_id": profile_id,
        "classification": "operator_scoped_detector_profile",
        "scheme": scheme,
        "watermark_target_sha256": watermark_target_sha256,
        "key_id": key_id,
        "primary": _identity_binding(primary_detector, kind="detector"),
        "verifiers": [_identity_binding(name, kind="detector") for name in verifier_detectors],
        "strategies": strategy_bindings,
        "quality_policy": {
            "policy_id": "deterministic-required-gates-v1",
            "policy_sha256": quality_policy_sha256(cfg),
        },
        "random_seed": cfg.random_seed,
        "search_limits": {
            field: getattr(selected_limits, field) for field in sorted(_SEARCH_FIELDS)
        },
        "evidence": evidence,
    }
    value["profile_sha256"] = mitigation_profile_sha256(value)
    return validate_mitigation_profile(value)


def _selected_profile(
    profile: MitigationProfile | Mapping[str, Any],
) -> MitigationProfile:
    # Exact type checking prevents a subclass from overriding access to the
    # immutable payload after validation.
    if type(profile) is MitigationProfile:
        return profile
    return validate_mitigation_profile(cast(Mapping[str, Any], profile))


def _component_check(
    expected: Mapping[str, Any],
    *,
    kind: str,
    scheme: str,
    target: str,
    config: DewatermarkConfig,
) -> dict[str, Any]:
    name = str(expected["name"])
    try:
        options = expected.get("options") if kind == "transformer" else None
        actual = _identity_binding(name, kind=kind, options=options)
        if kind == "detector":
            capability = detector_manifest(name)
        elif name == _CONTEXT_AWARE_STRATEGY:
            capability = static_capability(
                context_aware_strategy(**dict(options or {})), "transformer"
            )
        else:
            capability = provider_manifest(name, kind="transformer")
    except MitigationProfileError as exc:
        reason = "component_not_loaded" if "discoverable" in str(exc) else "component_unavailable"
        return {"name": name, "kind": kind, "status": reason}
    identity_fields = _COMPONENT_FIELDS | {
        field
        for field in (
            "command_code_sha256",
            "command_code_raw_sha256",
            "external_implementation_sha256",
        )
        if field in expected or field in actual
    }
    mismatches = [
        field
        for field in sorted(identity_fields - {"name"})
        if actual.get(field) != expected.get(field)
    ]
    if capability is None:
        return {"name": name, "kind": kind, "status": "component_unavailable"}
    if kind == "detector":
        if scheme not in capability.schemes:
            mismatches.append("scheme")
        if capability.metadata.get("watermark_target_sha256") != target:
            mismatches.append("watermark_target_sha256")
        if capability.calibrated is not True:
            mismatches.append("calibrated")
    if capability.network_required and not config.allow_remote_processing:
        mismatches.append("remote_processing_consent")
    if capability.model_download_possible and not config.allow_model_download:
        mismatches.append("model_download_consent")
    if capability.requires_secret and not (
        capability.kind == "detector"
        and capability.metadata.get("secret_binding") == "operator_managed_file"
    ):
        mismatches.append("secret_binding")
    return {
        "name": name,
        "kind": kind,
        "status": "matched" if not mismatches else "mismatch",
        "mismatch_fields": sorted(set(mismatches)),
    }


def inspect_mitigation_profile(
    profile: MitigationProfile | Mapping[str, Any],
    *,
    config: Optional[DewatermarkConfig] = None,
) -> dict[str, Any]:
    """Audit static bindings without importing plugins or touching text/secrets."""
    selected = _selected_profile(profile)
    value = selected.value
    scheme = str(value["scheme"])
    target = str(value["watermark_target_sha256"])
    cfg = resolve(config)
    primary = value["primary"]
    verifiers = value["verifiers"]
    strategies = value["strategies"]
    assert isinstance(primary, Mapping)
    assert type(verifiers) is tuple
    assert type(strategies) is tuple
    checks = [
        _component_check(
            primary,
            kind="detector",
            scheme=scheme,
            target=target,
            config=cfg,
        )
    ]
    for item in verifiers:
        assert isinstance(item, Mapping)
        check = _component_check(
            item,
            kind="detector",
            scheme=scheme,
            target=target,
            config=cfg,
        )
        name = str(item["name"])
        try:
            capability = detector_manifest(name)
        except ConfigurationError:
            capability = None
        if capability is not None and capability.independent is not True:
            check["status"] = "mismatch"
            check["mismatch_fields"] = sorted(
                set(check.get("mismatch_fields", [])) | {"independent"}
            )
        checks.append(check)
    for item in strategies:
        assert isinstance(item, Mapping)
        checks.append(
            _component_check(
                item,
                kind="transformer",
                scheme=scheme,
                target=target,
                config=cfg,
            )
        )
    policy = value["quality_policy"]
    assert isinstance(policy, Mapping)
    policy_match = quality_policy_sha256(cfg) == policy["policy_sha256"]
    checks.append(
        {
            "name": str(policy["policy_id"]),
            "kind": "quality_policy",
            "status": "matched" if policy_match else "mismatch",
            "mismatch_fields": [] if policy_match else ["policy_sha256"],
        }
    )
    components_ready = all(check["status"] == "matched" for check in checks)
    evidence = value["evidence"]
    assert isinstance(evidence, Mapping)
    evidence_status = str(evidence["status"])
    return {
        "schema_version": MITIGATION_PROFILE_SCHEMA_VERSION,
        "profile_id": selected.profile_id,
        "profile_sha256": selected.profile_sha256,
        "side_effect_free": True,
        "static_bindings_ready": components_ready,
        "runtime_availability": "not_checked",
        "evidence_status": evidence_status,
        "claim_scope": "named_configuration_only",
        "checks": checks,
    }


def _assert_runtime_caps(profile: MitigationProfile, config: DewatermarkConfig) -> SearchLimits:
    raw = profile.value["search_limits"]
    assert isinstance(raw, Mapping)
    limits = SearchLimits(**dict(raw))
    if (
        limits.max_candidates > config.max_search_candidates
        or limits.max_detector_queries > config.max_detector_queries
        or limits.max_candidate_characters > config.max_input_chars
    ):
        raise MitigationProfileError("runtime configuration cannot satisfy profile limits")
    return limits


def _target_binding(name: str, target: Any, *, kind: str) -> dict[str, str]:
    identity = extension_identity(target, kind, instance_sensitive=False)
    binding = {
        "name": name,
        "capability_sha256": manifest_sha256(static_capability(target, kind)),
        "implementation_sha256": _sha256(
            identity.get("implementation_sha256"), "component implementation_sha256"
        ),
        "static_state_sha256": _sha256(
            identity.get("static_state_sha256"), "component static_state_sha256"
        ),
    }
    if kind == "detector":
        from .command_detector import CommandDetectorFactory, _contract_from_manifest

        if type(target) is CommandDetectorFactory:
            capability = static_capability(target, "detector")
            try:
                contract = _contract_from_manifest(capability)
                command = object.__getattribute__(target, "command")
                command_code, command_code_raw = command_code_identities_sha256(command)
            except Exception:
                raise MitigationProfileError(
                    "command detector assurance identity could not be established"
                ) from None
            binding["command_code_sha256"] = _sha256(command_code, "component command_code_sha256")
            binding["command_code_raw_sha256"] = _sha256(
                command_code_raw, "component command_code_raw_sha256"
            )
            binding["external_implementation_sha256"] = _sha256(
                contract.implementation_sha256,
                "component external_implementation_sha256",
            )
    return binding


def _binding_matches(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    expected_command = all(
        field in expected
        for field in (
            "command_code_sha256",
            "command_code_raw_sha256",
            "external_implementation_sha256",
        )
    )
    actual_command = all(
        field in actual
        for field in (
            "command_code_sha256",
            "command_code_raw_sha256",
            "external_implementation_sha256",
        )
    )
    fields = _COMMAND_COMPONENT_FIELDS if expected_command and actual_command else _COMPONENT_FIELDS
    return expected_command == actual_command and all(
        expected.get(field) == actual.get(field) for field in fields
    )


class _PinnedProviderStrategy:
    """Adapter over an already-constructed, identity-checked provider instance."""

    def __init__(self, provider: Any, capability: CapabilityManifest) -> None:
        self._provider_instance = provider
        self._provider_identity = extension_identity(
            provider, "transformer", instance_sensitive=True
        )
        self._identity_violation = False
        self.capability = capability

    def __repr__(self) -> str:
        return "<dewatermark pinned provider strategy; details redacted>"

    def _assert_pinned(self) -> None:
        if (
            extension_identity(self._provider_instance, "transformer", instance_sensitive=True)
            != self._provider_identity
        ):
            self._identity_violation = True
            raise ReviewedExtensionMismatch("profile provider identity changed before execution")

    def available(self) -> bool:
        self._assert_pinned()
        if inspect.getattr_static(self._provider_instance, "available", None) is None:
            return True
        value = self._provider_instance.available()
        if type(value) is not bool:
            raise TypeError("provider availability must be boolean")
        return value

    def generate(self, text: str, *, context: Any, **options: Any) -> Sequence[Any]:
        self._assert_pinned()
        provider = self._provider_instance
        if inspect.getattr_static(provider, "generate", None) is not None:
            value = provider.generate(text, context=context, **options)
            if type(value) not in (list, tuple):
                raise TypeError("provider generate result must be a list or tuple")
            return value
        if inspect.getattr_static(provider, "transform", None) is not None:
            value = provider.transform(text, **options)
        elif inspect.getattr_static(provider, "rewrite", None) is not None:
            value = provider.rewrite(text, **options)
        else:
            raise TypeError("provider must implement generate, transform, or rewrite")
        if type(value) is not tuple or len(value) != 2 or type(value[1]) is not dict:
            raise TypeError("provider returned an invalid rewrite contract")
        return (value[0],)


def _pin_detector(expected: Mapping[str, Any], config: DewatermarkConfig) -> Any:
    name = str(expected["name"])
    try:
        from .command_detector import CommandDetector, CommandDetectorFactory

        factory = get_detector(name)
        declared = static_capability(factory, "detector")
        if not _binding_matches(expected, _target_binding(name, factory, kind="detector")):
            raise MitigationProfileError("runtime components do not match mitigation profile")
        enforce_consent(declared, config)
        instance = factory(safe_extension_config(config))
        exact_command_factory = type(factory) is CommandDetectorFactory
        if exact_command_factory and type(instance) is CommandDetector:
            expected_code_raw = _sha256(
                expected.get("command_code_raw_sha256"),
                "component command_code_raw_sha256",
            )
            CommandDetector._bind_profile_command_code_raw_sha256(instance, expected_code_raw)
        actual = static_capability(instance, "detector")
        if (
            exact_command_factory
            and type(instance) is not CommandDetector
            or not manifests_match(declared, actual)
            or not _binding_matches(expected, _target_binding(name, factory, kind="detector"))
        ):
            raise MitigationProfileError("runtime components do not match mitigation profile")
        return instance
    except MitigationProfileError:
        raise
    except Exception:
        raise MitigationProfileError("runtime detector could not be pinned safely") from None


def _pin_strategy(expected: Mapping[str, Any], config: DewatermarkConfig) -> Any:
    name = str(expected["name"])
    options = expected.get("options")
    assert isinstance(options, Mapping)
    if name == _CONTEXT_AWARE_STRATEGY:
        try:
            instance = context_aware_strategy(**dict(options))
            if not _binding_matches(
                expected,
                _identity_binding(name, kind="transformer", options=options),
            ):
                raise MitigationProfileError("runtime components do not match mitigation profile")
            return instance
        except MitigationProfileError:
            raise
        except Exception:
            raise MitigationProfileError("runtime strategy could not be pinned safely") from None
    try:
        factory = get_provider(name)
        declared = static_capability(factory, "transformer")
        if not _binding_matches(expected, _target_binding(name, factory, kind="transformer")):
            raise MitigationProfileError("runtime components do not match mitigation profile")
        enforce_consent(declared, config)
        provider = factory(safe_extension_config(config))
        actual = static_capability(provider, "transformer")
        if not manifests_match(declared, actual) or not _binding_matches(
            expected, _target_binding(name, factory, kind="transformer")
        ):
            raise MitigationProfileError("runtime components do not match mitigation profile")
        return _PinnedProviderStrategy(provider, actual)
    except MitigationProfileError:
        raise
    except Exception:
        raise MitigationProfileError("runtime strategy could not be pinned safely") from None


def mitigate_with_profile(
    text: str,
    profile: MitigationProfile | Mapping[str, Any],
    *,
    consent: bool,
    config: Optional[DewatermarkConfig] = None,
    source_localization: Sequence[SignalSpan] = (),
) -> MitigationResult:
    """Execute an exact profile; changed text still requires central verification."""
    if consent is not True:
        raise MitigationProfileConsentError("mitigation profile execution requires consent")
    if type(text) is not str or not text:
        raise ValueError("text must be a non-empty string")
    if type(source_localization) is not tuple or source_localization:
        raise MitigationProfileError(
            "source localization cannot override an immutable mitigation profile"
        )
    selected = _selected_profile(profile)
    cfg = resolve(config)
    limits = _assert_runtime_caps(selected, cfg)
    if len(text) > min(cfg.max_input_chars, limits.max_candidate_characters):
        raise ValueError("text exceeds the configured input limit")
    if quality_policy_sha256(cfg) != selected.value["quality_policy"]["policy_sha256"]:
        raise MitigationProfileError("runtime quality policy does not match mitigation profile")
    reviewed_quality_targets = _reviewed_quality_targets(cfg)
    cfg = replace(cfg, random_seed=int(selected.value["random_seed"]))

    # This is the explicit component-load boundary.  All profile and input
    # validation must happen before these calls.
    primary = selected.value["primary"]
    verifiers = selected.value["verifiers"]
    strategies = selected.value["strategies"]
    assert isinstance(primary, Mapping)
    assert type(verifiers) is tuple
    assert type(strategies) is tuple
    get_detector(str(primary["name"]))
    for item in verifiers:
        assert isinstance(item, Mapping)
        get_detector(str(item["name"]))
    for item in strategies:
        assert isinstance(item, Mapping)
        if item["name"] != _CONTEXT_AWARE_STRATEGY:
            get_provider(str(item["name"]))

    report = inspect_mitigation_profile(selected, config=cfg)
    if any(check.get("status") != "matched" for check in report["checks"]):
        raise MitigationProfileError("runtime components do not match mitigation profile")
    pinned_primary = _pin_detector(primary, cfg)
    pinned_verifiers: list[Any] = []
    for item in verifiers:
        assert isinstance(item, Mapping)
        pinned_verifiers.append(_pin_detector(item, cfg))
    bindings: list[StrategyBinding] = []
    reviewed_targets: list[tuple[Any, Mapping[str, Any]]] = [
        (target, identity) for target, _kind, identity in reviewed_quality_targets
    ]
    for item in strategies:
        assert isinstance(item, Mapping)
        strategy = _pin_strategy(item, cfg)
        detached_options = _thaw_json(item["options"])
        assert type(detached_options) is dict
        options = {} if item["name"] == _CONTEXT_AWARE_STRATEGY else detached_options
        bindings.append(StrategyBinding(strategy, options=options))
        reviewed_targets.append(
            (
                strategy,
                extension_identity(strategy, "transformer", instance_sensitive=True),
            )
        )
    try:
        with reviewed_extension_scope(reviewed_targets, {}):
            result = mitigate(
                text,
                pinned_primary,
                bindings,
                verifier_detectors=pinned_verifiers,
                config=cfg,
                limits=limits,
                source_localization=(),
            )
        if not _quality_targets_unchanged(reviewed_quality_targets):
            raise MitigationProfileError(
                "runtime quality policy identity changed during profile execution"
            )
        if any(
            isinstance(binding.strategy, _PinnedProviderStrategy)
            and binding.strategy._identity_violation
            for binding in bindings
        ):
            raise MitigationProfileError(
                "runtime component identity changed before profile execution"
            )
    except ReviewedExtensionMismatch:
        raise MitigationProfileError(
            "runtime component identity changed before profile execution"
        ) from None
    bound_receipt = replace(
        result.receipt,
        profile_id=selected.profile_id,
        profile_sha256=selected.profile_sha256,
    )
    return replace(result, receipt=bound_receipt)


__all__ = [
    "MITIGATION_PROFILE_SCHEMA_VERSION",
    "MitigationProfile",
    "MitigationProfileConsentError",
    "MitigationProfileError",
    "build_mitigation_profile",
    "inspect_mitigation_profile",
    "load_mitigation_profile",
    "mitigate_with_profile",
    "mitigation_profile_sha256",
    "quality_policy_manifest",
    "quality_policy_sha256",
    "validate_mitigation_profile",
]
