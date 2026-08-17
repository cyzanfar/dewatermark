"""Strict, side-effect-free capability checks for text-receiving extensions.

In-process extensions remain trusted Python code; these checks prevent accidental
invocation under an undeclared policy, but they are not a sandbox.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
from dataclasses import replace
from threading import RLock
from types import CodeType, FunctionType
from typing import Any, Iterable, Optional

from .exceptions import ConfigurationError
from .models import CapabilityManifest

EXTENSION_KINDS = frozenset(
    {"transformer", "scorer", "quality_gate", "semantic_scorer", "chunker", "detector"}
)
_identity_lock = RLock()
_instance_tokens: dict[int, tuple[Any, int]] = {}
_next_instance_token = 1


def _literal_metadata(value: Any) -> Any:
    """Copy a JSON-like literal without invoking user-defined protocols."""
    value_type = type(value)
    if value is None or value_type in (str, bool, int):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ConfigurationError("extension capability metadata numbers must be finite")
        return value
    if value_type in (list, tuple):
        return value_type(_literal_metadata(item) for item in value)
    if value_type is dict:
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ConfigurationError("extension capability metadata keys must be strings")
            copied[key] = _literal_metadata(item)
        return copied
    raise ConfigurationError(
        "extension capability metadata must contain only static JSON-like literals"
    )


def _static_attribute(target: Any, name: str) -> Any:
    """Read a literal attribute without invoking descriptors or extension code."""
    missing = False
    try:
        value = inspect.getattr_static(target, name)
    except Exception:
        missing = True
    if missing:
        raise ConfigurationError("extension must expose a static CapabilityManifest") from None
    return value


def static_capability(
    target: Any, expected_kind: str | Iterable[str] | None = None
) -> CapabilityManifest:
    capability = _static_attribute(target, "capability")
    if type(capability) is not CapabilityManifest:
        raise ConfigurationError("extension capability must be a literal CapabilityManifest")
    if any(
        type(getattr(capability, name)) is not str
        for name in ("identifier", "kind", "version", "description")
    ):
        raise ConfigurationError("extension capability text fields must be literal strings")
    if capability.kind not in EXTENSION_KINDS:
        raise ConfigurationError("unsupported extension capability kind")
    if expected_kind is not None:
        allowed = {expected_kind} if isinstance(expected_kind, str) else set(expected_kind)
        if capability.kind not in allowed:
            raise ConfigurationError(
                "extension capability kind does not match the required extension point"
            )
    if not capability.identifier.strip() or not capability.version.strip():
        raise ConfigurationError("extension capability identifier and version are required")
    if type(capability.schemes) is not tuple or any(
        type(scheme) is not str for scheme in capability.schemes
    ):
        raise ConfigurationError("extension capability schemes must be a tuple of strings")
    for name in (
        "network_required",
        "model_download_possible",
        "requires_secret",
        "calibrated",
        "independent",
    ):
        if type(getattr(capability, name)) is not bool:
            raise ConfigurationError(f"extension capability {name} must be boolean")
    if type(capability.minimum_characters) is not int or capability.minimum_characters < 0:
        raise ConfigurationError(
            "extension capability minimum_characters must be a non-negative integer"
        )
    if type(capability.metadata) is not dict:
        raise ConfigurationError("extension capability metadata must be a literal dictionary")
    return replace(capability, metadata=_literal_metadata(capability.metadata))


def enforce_consent(capability: CapabilityManifest, config: Any | None) -> None:
    allow_network = bool(config is not None and config.allow_remote_processing)
    allow_download = bool(config is not None and config.allow_model_download)
    if capability.network_required and not allow_network:
        raise PermissionError(f"{capability.kind} requires explicit remote-processing consent")
    if capability.model_download_possible and not allow_download:
        raise PermissionError(f"{capability.kind} requires explicit model-download consent")
    if capability.requires_secret:
        # The generic extension boundary deliberately receives no credential
        # resolver. Purpose-built adapters must implement a scoped secret channel.
        raise PermissionError(
            f"{capability.kind} requires a secret, but no scoped extension secret was configured"
        )


def require_extension(
    target: Any,
    expected_kind: str | Iterable[str],
    config: Any | None,
) -> CapabilityManifest:
    capability = static_capability(target, expected_kind)
    enforce_consent(capability, config)
    return capability


def safe_extension_config(config: Any) -> Any:
    """Project config without handing generic extensions unrelated credentials."""
    return replace(config, fireworks_api_key=None, llm_api_key=None)


def manifest_sha256(capability: CapabilityManifest) -> str:
    encoded = json.dumps(
        capability.to_dict(),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: f"<{type(value).__name__}>",
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def manifests_match(left: CapabilityManifest, right: CapabilityManifest) -> bool:
    # Both values are validated literal snapshots. Direct comparison catches
    # differences that the deliberately redacted public digest cannot expose.
    return left == right


def _code_digest(code: CodeType, digest: Any) -> None:
    digest.update(code.co_code)
    digest.update("|".join(code.co_names).encode("utf-8", "replace"))
    for value in code.co_consts:
        if isinstance(value, CodeType):
            _code_digest(value, digest)
        elif value is None or type(value) in (str, bytes, int, float, bool):
            digest.update(type(value).__name__.encode())
            digest.update(hashlib.sha256(repr(value).encode("utf-8", "replace")).digest())


def implementation_sha256(target: Any, *, instance_sensitive: bool = False) -> str:
    """Return a content-free implementation identity suitable for plan binding."""
    digest = hashlib.sha256()
    kind = target if isinstance(target, type) else type(target)
    namespace = type.__getattribute__(kind, "__dict__")
    module = namespace.get("__module__", "")
    qualname = namespace.get("__qualname__", "")
    if isinstance(target, FunctionType):
        module = target.__module__
        qualname = target.__qualname__
    digest.update(str(module).encode("utf-8", "replace"))
    digest.update(str(qualname).encode("utf-8", "replace"))
    for name in sorted(namespace):
        value = namespace[name]
        if type(value) in (staticmethod, classmethod):
            value = value.__func__
        if isinstance(value, FunctionType):
            digest.update(name.encode("utf-8", "replace"))
            _code_digest(value.__code__, digest)
    if isinstance(target, FunctionType):
        _code_digest(target.__code__, digest)
    if instance_sensitive and not isinstance(target, type):
        global _next_instance_token
        key = id(target)
        with _identity_lock:
            record = _instance_tokens.get(key)
            if record is None or record[0] is not target:
                record = (target, _next_instance_token)
                _instance_tokens[key] = record
                _next_instance_token += 1
        digest.update(f"instance:{record[1]}".encode("ascii"))
    return digest.hexdigest()


def extension_identity(
    target: Any,
    expected_kind: str | Iterable[str],
    *,
    revision: Optional[int] = None,
    instance_sensitive: bool = False,
) -> dict[str, Any]:
    capability = static_capability(target, expected_kind)
    return {
        "capability": capability.to_dict(),
        "capability_sha256": manifest_sha256(capability),
        "implementation_sha256": implementation_sha256(
            target, instance_sensitive=instance_sensitive
        ),
        **({"registry_revision": revision} if revision is not None else {}),
    }
