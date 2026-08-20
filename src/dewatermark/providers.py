"""Thread-safe provider registry with Python entry-point discovery."""

from __future__ import annotations

import re
from importlib import metadata
from threading import RLock
from typing import Any, Callable

from .exceptions import ConfigurationError
from .extension_safety import (
    extension_identity,
    manifests_match,
    static_capability,
    validate_reviewed_registration,
)
from .models import CapabilityManifest

ProviderFactory = Callable[..., Any]
ENTRY_POINT_GROUP = "dewatermark.providers"
DETECTOR_ENTRY_POINT_GROUP = "dewatermark.detectors"
_lock = RLock()
_providers: dict[str, ProviderFactory] = {}
_provider_manifests: dict[str, CapabilityManifest] = {}
_provider_identities: dict[str, dict[str, Any]] = {}
_provider_revisions: dict[str, int] = {}
_provider_errors: dict[str, str] = {}
_provider_entry_points: dict[str, Any] | None = None
_detectors: dict[str, ProviderFactory] = {}
_detector_manifests: dict[str, CapabilityManifest] = {}
_detector_identities: dict[str, dict[str, Any]] = {}
_detector_revisions: dict[str, int] = {}
_detector_errors: dict[str, str] = {}
_detector_entry_points: dict[str, Any] | None = None
_PUBLIC_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _entry_points(group: str) -> dict[str, Any]:
    failed = False
    entries: dict[str, Any] = {}
    try:
        eps: Any = metadata.entry_points()
        selected = eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])
        for entry_point in selected:
            name = entry_point.name
            if type(name) is str and _PUBLIC_NAME.fullmatch(name.strip()):
                normalized = name.strip().lower()
                if normalized in entries:
                    raise ConfigurationError("duplicate normalized extension entry-point name")
                entries[normalized] = entry_point
    except Exception:
        failed = True
    if failed:
        raise ConfigurationError("extension entry-point discovery failed") from None
    return entries


def _name(value: Any, kind: str) -> str:
    if type(value) is not str or not _PUBLIC_NAME.fullmatch(value.strip()):
        raise ConfigurationError(f"{kind} name must be a registered identifier")
    return value.strip().lower()


def _provider_entries() -> dict[str, Any]:
    global _provider_entry_points
    with _lock:
        if _provider_entry_points is None:
            _provider_entry_points = _entry_points(ENTRY_POINT_GROUP)
        return dict(_provider_entry_points)


def _seed_detector_builtins() -> None:
    """Register built-ins only for an explicit load/discovery operation."""
    with _lock:
        from .detectors import builtin_detector_factories

        for name, factory in builtin_detector_factories().items():
            if name not in _detectors:
                register_detector(name, factory)


def _builtin_detector_factories() -> dict[str, ProviderFactory]:
    """Return static built-ins without mutating the active registry."""
    from .detectors import builtin_detector_factories

    return builtin_detector_factories()


def _detector_entries() -> dict[str, Any]:
    global _detector_entry_points
    with _lock:
        if _detector_entry_points is None:
            _detector_entry_points = _entry_points(DETECTOR_ENTRY_POINT_GROUP)
        return dict(_detector_entry_points)


def register_provider(name: str, factory: ProviderFactory, *, replace: bool = False) -> None:
    """Register an extension factory under a stable, case-insensitive name."""
    key = _name(name, "provider")
    if not callable(factory):
        raise ConfigurationError("provider factory must be callable")
    capability = static_capability(factory, ("transformer", "scorer"))
    with _lock:
        if key in _providers and not replace:
            raise ConfigurationError("provider name is already registered")
        revision = _provider_revisions.get(key, 0) + 1
        identity = extension_identity(factory, ("transformer", "scorer"), revision=revision)
        _provider_revisions[key] = revision
        _providers[key] = factory
        _provider_manifests[key] = capability
        _provider_identities[key] = identity


def _registered_provider(
    key: str,
) -> tuple[ProviderFactory, CapabilityManifest, dict[str, Any]] | None:
    """Return a registration only while its side-effect-free identity is unchanged."""
    with _lock:
        factory = _providers.get(key)
        capability = _provider_manifests.get(key)
        identity = _provider_identities.get(key)
        revision = _provider_revisions.get(key)
    if factory is None or capability is None or identity is None or revision is None:
        return None
    current_capability = static_capability(factory, ("transformer", "scorer"))
    current_identity = extension_identity(
        factory,
        ("transformer", "scorer"),
        revision=revision,
    )
    validate_reviewed_registration("provider", key, current_identity)
    if not manifests_match(capability, current_capability) or current_identity != identity:
        raise ConfigurationError(
            "registered provider identity changed; explicitly replace the registration"
        )
    return factory, capability, dict(identity)


def discover_providers() -> dict[str, ProviderFactory]:
    """Explicitly load installed providers; listing alone never executes plugins."""
    for name in _provider_entries():
        try:
            get_provider(name)
        except ConfigurationError:
            pass
    with _lock:
        return dict(_providers)


def get_provider(name: str) -> ProviderFactory:
    key = _name(name, "provider")
    registered = _registered_provider(key)
    if registered is not None:
        validate_reviewed_registration("provider", key, registered[2])
        return registered[0]
    entry_point = _provider_entries().get(key)
    if entry_point is None:
        raise ConfigurationError("unknown provider; call list_providers() for available names")
    factory: Any = None
    failed = False
    try:
        factory = entry_point.load()
        register_provider(key, factory)
    except Exception:
        with _lock:
            _provider_errors[key] = "entry_point_load_failed"
        failed = True
    if failed:
        raise ConfigurationError("provider entry point could not be loaded") from None
    return factory


def provider_manifest(name: str, *, kind: str = "transformer") -> CapabilityManifest | None:
    """Return an already-registered static manifest without loading plugins."""
    key = _name(name, "provider")
    registered = _registered_provider(key)
    if registered is None:
        if key in _provider_entries():
            return None
        raise ConfigurationError("unknown provider; call list_providers() for available names")
    _, capability, _ = registered
    if isinstance(capability, CapabilityManifest) and capability.kind == kind:
        return capability
    return None


def provider_identity(name: str, *, kind: str = "transformer") -> dict[str, Any] | None:
    """Return the immutable registration identity without loading entry points."""
    key = _name(name, "provider")
    registered = _registered_provider(key)
    if registered is None:
        if key in _provider_entries():
            return None
        raise ConfigurationError("unknown provider; call list_providers() for available names")
    _, capability, identity = registered
    return identity if capability.kind == kind else None


def list_providers() -> tuple[str, ...]:
    with _lock:
        registered = set(_providers)
    return tuple(sorted(registered | set(_provider_entries())))


def provider_errors() -> dict[str, str]:
    """Return entry-point load failures without failing unrelated providers."""
    with _lock:
        return dict(_provider_errors)


def unregister_provider(name: str) -> None:
    """Remove an in-process registration; primarily useful in tests."""
    key = _name(name, "provider")
    with _lock:
        _providers.pop(key, None)
        _provider_manifests.pop(key, None)
        _provider_identities.pop(key, None)


def register_detector(name: str, factory: ProviderFactory, *, replace: bool = False) -> None:
    """Register a named detector factory under ``dewatermark.detectors``."""
    key = _name(name, "detector")
    if not callable(factory):
        raise ConfigurationError("detector factory must be callable")
    capability = static_capability(factory, "detector")
    with _lock:
        if key in _detectors and not replace:
            raise ConfigurationError("detector name is already registered")
        revision = _detector_revisions.get(key, 0) + 1
        identity = extension_identity(factory, "detector", revision=revision)
        _detector_revisions[key] = revision
        _detectors[key] = factory
        _detector_manifests[key] = capability
        _detector_identities[key] = identity


def _registered_detector(
    key: str,
) -> tuple[ProviderFactory, CapabilityManifest, dict[str, Any]] | None:
    """Return a detector registration only while its static identity is unchanged."""
    with _lock:
        factory = _detectors.get(key)
        capability = _detector_manifests.get(key)
        identity = _detector_identities.get(key)
        revision = _detector_revisions.get(key)
    if factory is None or capability is None or identity is None or revision is None:
        return None
    current_capability = static_capability(factory, "detector")
    current_identity = extension_identity(factory, "detector", revision=revision)
    validate_reviewed_registration("detector", key, current_identity)
    if not manifests_match(capability, current_capability) or current_identity != identity:
        raise ConfigurationError(
            "registered detector identity changed; explicitly replace the registration"
        )
    return factory, capability, dict(identity)


def discover_detectors() -> dict[str, ProviderFactory]:
    """Explicitly load detector plugins; listing alone never executes them."""
    _seed_detector_builtins()
    for name in _detector_entries():
        try:
            get_detector(name)
        except ConfigurationError:
            pass
    with _lock:
        return dict(_detectors)


def get_detector(name: str) -> ProviderFactory:
    _seed_detector_builtins()
    key = _name(name, "detector")
    registered = _registered_detector(key)
    if registered is not None:
        validate_reviewed_registration("detector", key, registered[2])
        return registered[0]
    entry_point = _detector_entries().get(key)
    if entry_point is None:
        raise ConfigurationError("unknown detector; call list_detectors() for available names")
    factory: Any = None
    failed = False
    try:
        factory = entry_point.load()
        register_detector(key, factory)
    except Exception:
        with _lock:
            _detector_errors[key] = "entry_point_load_failed"
        failed = True
    if failed:
        raise ConfigurationError("detector entry point could not be loaded") from None
    return factory


def detector_manifest(name: str) -> CapabilityManifest | None:
    """Return an already-registered static manifest without loading plugin code.

    Entry-point names remain discoverable through :func:`list_detectors`, but a
    content-bound plan deliberately refuses to import them. Applications that
    trust a plugin can load/register it explicitly before planning.
    """
    key = _name(name, "detector")
    registered = _registered_detector(key)
    if registered is None:
        factory = _builtin_detector_factories().get(key)
        if factory is not None:
            return static_capability(factory, "detector")
        if key in _detector_entries():
            return None
        raise ConfigurationError("unknown detector; call list_detectors() for available names")
    _, capability, _ = registered
    if isinstance(capability, CapabilityManifest) and capability.kind == "detector":
        return capability
    return None


def detector_identity(name: str) -> dict[str, Any] | None:
    """Return a registered detector identity without importing an entry point."""
    key = _name(name, "detector")
    registered = _registered_detector(key)
    with _lock:
        next_revision = _detector_revisions.get(key, 0) + 1
    if registered is not None:
        return registered[2]
    builtin = _builtin_detector_factories().get(key)
    if builtin is not None:
        return extension_identity(builtin, "detector", revision=next_revision)
    if key in _detector_entries() or key in _detectors:
        return None
    raise ConfigurationError("unknown detector; call list_detectors() for available names")


def detector_binding_identity(name: str) -> dict[str, Any] | None:
    """Return the static detector identity used by mitigation profiles.

    Exact command-detector factories need three commitments beyond the generic
    Python extension identity: the manifest's externally reviewed
    implementation digest, a semantic executable/script identity for held-out
    distinctness, and an exact raw identity for drift. Computing those digests
    reads only bounded public command code. It never constructs a detector,
    starts a process, imports an unloaded entry point, or reads an
    operator-managed secret argument.
    """
    key = _name(name, "detector")
    registered = _registered_detector(key)
    if registered is not None:
        factory, capability, identity = registered
    else:
        builtin_factory = _builtin_detector_factories().get(key)
        if builtin_factory is None:
            if key in _detector_entries() or key in _detectors:
                return None
            raise ConfigurationError("unknown detector; call list_detectors() for available names")
        factory = builtin_factory
        capability = static_capability(factory, "detector")
        with _lock:
            next_revision = _detector_revisions.get(key, 0) + 1
        identity = extension_identity(factory, "detector", revision=next_revision)

    from .command_detector import CommandDetectorFactory, _contract_from_manifest
    from .command_safety import command_code_identities_sha256

    result = dict(identity)
    if type(factory) is not CommandDetectorFactory:
        return result
    try:
        contract = _contract_from_manifest(capability)
        implementation = contract.implementation_sha256
        command = object.__getattribute__(factory, "command")
        command_code, command_code_raw = command_code_identities_sha256(command)
    except Exception:
        raise ConfigurationError(
            "command detector assurance identity could not be established"
        ) from None
    if (
        type(implementation) is not str
        or re.fullmatch(r"[0-9a-f]{64}", implementation) is None
        or type(command_code) is not str
        or re.fullmatch(r"[0-9a-f]{64}", command_code) is None
        or type(command_code_raw) is not str
        or re.fullmatch(r"[0-9a-f]{64}", command_code_raw) is None
    ):
        raise ConfigurationError("command detector assurance identity is incomplete")
    result["external_implementation_sha256"] = implementation
    result["command_code_sha256"] = command_code
    result["command_code_raw_sha256"] = command_code_raw
    return result


def list_detectors() -> tuple[str, ...]:
    with _lock:
        registered = set(_detectors)
    return tuple(sorted(registered | set(_builtin_detector_factories()) | set(_detector_entries())))


def detector_errors() -> dict[str, str]:
    with _lock:
        return dict(_detector_errors)


def unregister_detector(name: str) -> None:
    """Remove an in-process detector registration; primarily useful in tests."""
    key = _name(name, "detector")
    with _lock:
        _detectors.pop(key, None)
        _detector_manifests.pop(key, None)
        _detector_identities.pop(key, None)
