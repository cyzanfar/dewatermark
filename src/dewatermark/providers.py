"""Thread-safe provider registry with Python entry-point discovery."""

from __future__ import annotations

from importlib import metadata
from threading import RLock
from typing import Any, Callable

from .exceptions import ConfigurationError

ProviderFactory = Callable[..., Any]
ENTRY_POINT_GROUP = "dewatermark.providers"
_lock = RLock()
_providers: dict[str, ProviderFactory] = {}
_provider_errors: dict[str, str] = {}
_discovered = False


def register_provider(name: str, factory: ProviderFactory, *, replace: bool = False) -> None:
    """Register an extension factory under a stable, case-insensitive name."""
    key = name.strip().lower()
    if not key or not callable(factory):
        raise ConfigurationError("provider name and callable factory are required")
    with _lock:
        if key in _providers and not replace:
            raise ConfigurationError(f"provider {key!r} is already registered")
        _providers[key] = factory


def discover_providers() -> dict[str, ProviderFactory]:
    """Load installed ``dewatermark.providers`` entry points once."""
    global _discovered
    with _lock:
        if not _discovered:
            eps: Any = metadata.entry_points()
            selected = (
                eps.select(group=ENTRY_POINT_GROUP)
                if hasattr(eps, "select")
                else eps.get(ENTRY_POINT_GROUP, [])
            )
            for entry_point in selected:
                try:
                    _providers.setdefault(entry_point.name.lower(), entry_point.load())
                except Exception as exc:
                    _provider_errors[entry_point.name.lower()] = type(exc).__name__
            _discovered = True
        return dict(_providers)


def get_provider(name: str) -> ProviderFactory:
    providers = discover_providers()
    try:
        return providers[name.lower()]
    except KeyError as exc:
        raise ConfigurationError(
            f"unknown provider {name!r}; available: {sorted(providers)}"
        ) from exc


def list_providers() -> tuple[str, ...]:
    return tuple(sorted(discover_providers()))


def provider_errors() -> dict[str, str]:
    """Return entry-point load failures without failing unrelated providers."""
    discover_providers()
    return dict(_provider_errors)


def unregister_provider(name: str) -> None:
    """Remove an in-process registration; primarily useful in tests."""
    with _lock:
        _providers.pop(name.lower(), None)
