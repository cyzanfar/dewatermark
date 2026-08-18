"""Adapters that turn registered rewrite providers into search strategies.

Provider discovery is explicit: :func:`registered_strategy` may import a
trusted entry-point plugin because the caller has asked to execute it.  The
provider itself is constructed lazily, inside the optimizer's request scope,
so its declared network/model work crosses the shared accounting boundary.
"""

from __future__ import annotations

import inspect
from typing import Any, Optional, Sequence

from .config import DewatermarkConfig, resolve
from .extension_safety import manifests_match, safe_extension_config, static_capability
from .models import CapabilityManifest
from .providers import get_provider, provider_manifest


class RegisteredProviderStrategy:
    """Lazy adapter for one explicitly loaded transformer registration."""

    def __init__(self, name: str, config: Optional[DewatermarkConfig] = None) -> None:
        # ``get_provider`` is intentionally the explicit plugin-load boundary.
        # Construction is deferred until ``available`` or ``generate`` runs.
        get_provider(name)
        declared = provider_manifest(name, kind="transformer")
        if declared is None:
            raise ValueError("registered strategy requires a static transformer manifest")
        self._name = name
        self._config = resolve(config)
        self._instance: Any = None
        self.capability: CapabilityManifest = declared

    def __repr__(self) -> str:
        return "<dewatermark registered provider strategy; details redacted>"

    def _provider(self) -> Any:
        if self._instance is not None:
            return self._instance
        # Re-read through the registry immediately before construction. This
        # checks the registration's reviewed static identity for drift.
        factory = get_provider(self._name)
        provider = factory(safe_extension_config(self._config))
        actual = static_capability(provider, "transformer")
        if not manifests_match(self.capability, actual):
            raise TypeError("provider instance capability does not match its registration")
        self._instance = provider
        return provider

    def available(self) -> bool:
        provider = self._provider()
        method = inspect.getattr_static(provider, "available", None)
        if method is None:
            return True
        value = provider.available()
        if type(value) is not bool:
            raise TypeError("provider availability must be boolean")
        return value

    def generate(self, text: str, *, context: Any, **options: Any) -> Sequence[Any]:
        """Return untrusted proposals; the optimizer alone may accept one."""
        provider = self._provider()
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


def registered_strategy(
    name: str, config: Optional[DewatermarkConfig] = None
) -> RegisteredProviderStrategy:
    """Load a trusted provider registration and adapt it for bounded search."""
    return RegisteredProviderStrategy(name, config)


__all__ = ["RegisteredProviderStrategy", "registered_strategy"]
