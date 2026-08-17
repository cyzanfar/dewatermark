"""Thread-safe provider registry with Python entry-point discovery."""

from __future__ import annotations

from importlib import metadata
from threading import RLock
from typing import Any, Callable

from .exceptions import ConfigurationError
from .extension_safety import extension_identity, static_capability
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
_detector_builtins_seeded = False


def _entry_points(group: str) -> dict[str, Any]:
    failed = False
    entries: dict[str, Any] = {}
    try:
        eps: Any = metadata.entry_points()
        selected = eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])
        for entry_point in selected:
            name = entry_point.name
            if type(name) is str and name.strip():
                entries[name.strip().lower()] = entry_point
    except Exception:
        failed = True
    if failed:
        raise ConfigurationError("extension entry-point discovery failed") from None
    return entries


def _name(value: Any, kind: str) -> str:
    if type(value) is not str or not value.strip():
        raise ConfigurationError(f"{kind} name must be a non-empty string")
    return value.strip().lower()


def _provider_entries() -> dict[str, Any]:
    global _provider_entry_points
    with _lock:
        if _provider_entry_points is None:
            _provider_entry_points = _entry_points(ENTRY_POINT_GROUP)
        return dict(_provider_entry_points)


def _seed_detector_builtins() -> None:
    global _detector_builtins_seeded
    with _lock:
        if not _detector_builtins_seeded:
            from .detectors import builtin_detector_factories

            for name, factory in builtin_detector_factories().items():
                if name not in _detectors:
                    register_detector(name, factory)
            _detector_builtins_seeded = True


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
        _provider_revisions[key] = revision
        _providers[key] = factory
        _provider_manifests[key] = capability
        _provider_identities[key] = extension_identity(
            factory, ("transformer", "scorer"), revision=revision
        )


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
    with _lock:
        if key in _providers:
            return _providers[key]
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
    with _lock:
        factory = _providers.get(key)
        capability = _provider_manifests.get(key)
    if factory is None:
        if key in _provider_entries():
            return None
        raise ConfigurationError("unknown provider; call list_providers() for available names")
    if isinstance(capability, CapabilityManifest) and capability.kind == kind:
        return capability
    return None


def provider_identity(name: str, *, kind: str = "transformer") -> dict[str, Any] | None:
    """Return the immutable registration identity without loading entry points."""
    key = _name(name, "provider")
    with _lock:
        capability = _provider_manifests.get(key)
        identity = _provider_identities.get(key)
    if capability is None or capability.kind != kind or identity is None:
        if key in _provider_entries():
            return None
        if key not in _providers:
            raise ConfigurationError("unknown provider; call list_providers() for available names")
        return None
    return dict(identity)


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
        _detector_revisions[key] = revision
        _detectors[key] = factory
        _detector_manifests[key] = capability
        _detector_identities[key] = extension_identity(factory, "detector", revision=revision)


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
    with _lock:
        if key in _detectors:
            return _detectors[key]
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
    _seed_detector_builtins()
    key = _name(name, "detector")
    with _lock:
        factory = _detectors.get(key)
        capability = _detector_manifests.get(key)
    if factory is None:
        if key in _detector_entries():
            return None
        raise ConfigurationError("unknown detector; call list_detectors() for available names")
    if isinstance(capability, CapabilityManifest) and capability.kind == "detector":
        return capability
    return None


def detector_identity(name: str) -> dict[str, Any] | None:
    """Return a registered detector identity without importing an entry point."""
    _seed_detector_builtins()
    key = _name(name, "detector")
    with _lock:
        identity = _detector_identities.get(key)
    if identity is not None:
        return dict(identity)
    if key in _detector_entries() or key in _detectors:
        return None
    raise ConfigurationError("unknown detector; call list_detectors() for available names")


def list_detectors() -> tuple[str, ...]:
    _seed_detector_builtins()
    with _lock:
        registered = set(_detectors)
    return tuple(sorted(registered | set(_detector_entries())))


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
