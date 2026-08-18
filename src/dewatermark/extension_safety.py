"""Strict, side-effect-free capability checks for text-receiving extensions.

In-process extensions remain trusted Python code; these checks prevent accidental
invocation under an undeclared policy, but they are not a sandbox.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import math
import weakref
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import replace
from threading import RLock
from types import CodeType, FunctionType, MemberDescriptorType
from typing import Any, Iterable, Iterator, Mapping, Optional

from .exceptions import ConfigurationError
from .models import CapabilityManifest

EXTENSION_KINDS = frozenset(
    {"transformer", "scorer", "quality_gate", "semantic_scorer", "chunker", "detector"}
)
_identity_lock = RLock()
_instance_tokens: dict[int, tuple[weakref.ReferenceType[Any], int]] = {}
_next_instance_token = 1
_IDENTITY_NODE_LIMIT = 8192
_IDENTITY_DEPTH_LIMIT = 32
# This is an intentionally public domain-separation key, not an authentication
# secret.  Static-state fingerprints are content addresses that must be stable
# when a reviewed plan is created and applied by separate CLI processes.  Raw
# extension values are fed only to the one-way HMAC and are never serialized.
_STATE_FINGERPRINT_KEY = hashlib.sha256(
    b"dewatermark/static-extension-state-fingerprint/v1"
).digest()


class _ReviewedExtensions:
    def __init__(
        self,
        targets: Iterable[tuple[Any, Mapping[str, Any]]],
        registrations: Mapping[tuple[str, str], Mapping[str, Any]],
    ) -> None:
        self.targets = {id(target): dict(identity) for target, identity in targets}
        self.registrations = {key: dict(identity) for key, identity in registrations.items()}
        self.started_targets: set[int] = set()
        self.started_registrations: set[tuple[str, str]] = set()
        self.violation = False


_REVIEWED_EXTENSIONS: ContextVar[Optional[_ReviewedExtensions]] = ContextVar(
    "dewatermark_reviewed_extensions", default=None
)


class ReviewedExtensionMismatch(ConfigurationError):
    """A digest-reviewed extension changed before its first runtime use."""


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
    validate_reviewed_extension(target, expected_kind)
    enforce_consent(capability, config)
    return capability


@contextmanager
def reviewed_extension_scope(
    targets: Iterable[tuple[Any, Mapping[str, Any]]],
    registrations: Mapping[tuple[str, str], Mapping[str, Any]],
) -> Iterator[None]:
    """Carry digest-reviewed extension identities to their first runtime use."""
    token: Token[Optional[_ReviewedExtensions]] = _REVIEWED_EXTENSIONS.set(
        _ReviewedExtensions(targets, registrations)
    )
    try:
        yield
    finally:
        violated = _REVIEWED_EXTENSIONS.get()
        _REVIEWED_EXTENSIONS.reset(token)
    if violated is not None and violated.violation:
        raise ReviewedExtensionMismatch("reviewed extension identity changed before execution")


def validate_reviewed_extension(target: Any, expected_kind: str | Iterable[str]) -> None:
    """Fail before first text access if a reviewed direct extension drifted."""
    reviewed = _REVIEWED_EXTENSIONS.get()
    identity = id(target)
    if reviewed is None or identity not in reviewed.targets:
        return
    if identity in reviewed.started_targets:
        return
    current = extension_identity(target, expected_kind, instance_sensitive=True)
    if current != reviewed.targets[identity]:
        reviewed.violation = True
        raise ReviewedExtensionMismatch("reviewed extension identity changed before execution")
    reviewed.started_targets.add(identity)


def validate_reviewed_registration(
    registry_kind: str,
    name: str,
    identity: Mapping[str, Any],
) -> None:
    """Fail before factory construction if a reviewed registration drifted."""
    reviewed = _REVIEWED_EXTENSIONS.get()
    key = (registry_kind, name)
    if reviewed is None or key not in reviewed.registrations:
        return
    if key in reviewed.started_registrations:
        return
    if dict(identity) != reviewed.registrations[key]:
        reviewed.violation = True
        raise ReviewedExtensionMismatch("reviewed extension identity changed before execution")
    reviewed.started_registrations.add(key)


def safe_extension_config(config: Any) -> Any:
    """Project config without handing generic extensions unrelated credentials."""
    return replace(config, fireworks_api_key=None, llm_api_key=None)


def manifest_sha256(capability: CapabilityManifest) -> str:
    encoded = json.dumps(
        capability.to_dict(),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda _value: "<redacted>",
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def manifests_match(left: CapabilityManifest, right: CapabilityManifest) -> bool:
    # Both values are validated literal snapshots. Direct comparison catches
    # differences that the deliberately redacted public digest cannot expose.
    return left == right


def _literal_name(value: Any) -> str:
    return value if type(value) is str else "<invalid>"


def _code_constant_digest(value: Any, digest: Any) -> None:
    if isinstance(value, CodeType):
        _code_digest(value, digest)
    elif value is None or type(value) in (str, bytes, int, float, bool, complex):
        digest.update(type(value).__name__.encode())
        digest.update(hashlib.sha256(repr(value).encode("utf-8", "replace")).digest())
    elif type(value) in (tuple, frozenset):
        digest.update(type(value).__name__.encode())
        if type(value) is tuple:
            for item in value:
                _code_constant_digest(item, digest)
        else:
            item_digests: list[bytes] = []
            for item in value:
                item_digest = hashlib.sha256()
                _code_constant_digest(item, item_digest)
                item_digests.append(item_digest.digest())
            for item_bytes in sorted(item_digests):
                digest.update(item_bytes)


def _code_digest(code: CodeType, digest: Any) -> None:
    digest.update(code.co_code)
    digest.update("|".join(code.co_names).encode("utf-8", "replace"))
    digest.update("|".join(code.co_varnames).encode("utf-8", "replace"))
    digest.update("|".join(code.co_freevars).encode("utf-8", "replace"))
    digest.update("|".join(code.co_cellvars).encode("utf-8", "replace"))
    digest.update(
        b"|".join(
            str(value).encode("ascii")
            for value in (
                code.co_argcount,
                code.co_posonlyargcount,
                code.co_kwonlyargcount,
                code.co_nlocals,
                code.co_flags,
            )
        )
    )
    for value in code.co_consts:
        _code_constant_digest(value, digest)


def _identity_token(target: Any) -> int:
    """Return a process-local token without retaining or exposing an object."""
    global _next_instance_token
    key = id(target)
    try:
        target_reference = weakref.ref(target)
    except TypeError:
        # The address is consumed only by a SHA-256 digest and is never exposed.
        return key
    with _identity_lock:
        record = _instance_tokens.get(key)
        if record is None or record[0]() is not target:
            token = _next_instance_token
            _next_instance_token += 1

            def discard(reference: weakref.ReferenceType[Any], identity: int = key) -> None:
                with _identity_lock:
                    current = _instance_tokens.get(identity)
                    if current is not None and current[0] is reference:
                        _instance_tokens.pop(identity, None)

            target_reference = weakref.ref(target, discard)
            record = (target_reference, token)
            _instance_tokens[key] = record
    return record[1]


def _digest_scalar(digest: Any, label: bytes, value: bytes = b"") -> None:
    digest.update(len(label).to_bytes(2, "big"))
    digest.update(label)
    digest.update(hashlib.sha256(value).digest())


def _function_state(
    function: FunctionType,
    digest: Any,
    seen: set[int],
    budget: list[int],
    depth: int,
) -> None:
    _code_digest(function.__code__, digest)
    _state_digest(function.__defaults__, digest, seen, budget, depth + 1)
    _state_digest(function.__kwdefaults__, digest, seen, budget, depth + 1)
    closure = function.__closure__
    if closure is not None:
        for cell in closure:
            try:
                value = cell.cell_contents
            except ValueError:
                _digest_scalar(digest, b"empty-cell")
            else:
                _state_digest(value, digest, seen, budget, depth + 1)
    globals_dict = function.__globals__
    for name in sorted(set(function.__code__.co_names)):
        if name in globals_dict and name != "__builtins__":
            _digest_scalar(digest, b"global-name", name.encode("utf-8", "replace"))
            _state_digest(globals_dict[name], digest, seen, budget, depth + 1)


def _class_state(
    kind: type,
    digest: Any,
    seen: set[int],
    budget: list[int],
    depth: int,
) -> None:
    try:
        lineage = type.__getattribute__(kind, "__mro__")
    except Exception:
        lineage = (kind,)
    for base in lineage:
        if base is object:
            continue
        namespace = type.__getattribute__(base, "__dict__")
        module = _literal_name(namespace.get("__module__", ""))
        qualname = _literal_name(namespace.get("__qualname__", ""))
        _digest_scalar(digest, b"class-module", module.encode("utf-8", "replace"))
        _digest_scalar(digest, b"class-name", qualname.encode("utf-8", "replace"))
        for name in sorted(namespace):
            if name.startswith("__") and name.endswith("__"):
                continue
            _digest_scalar(digest, b"attribute-name", name.encode("utf-8", "replace"))
            value = namespace[name]
            if type(value) in (staticmethod, classmethod):
                value = value.__func__
            _state_digest(value, digest, seen, budget, depth + 1)


def _instance_state(
    target: Any,
    digest: Any,
    seen: set[int],
    budget: list[int],
    depth: int,
) -> None:
    kind = type(target)
    _class_state(kind, digest, seen, budget, depth + 1)
    try:
        state = object.__getattribute__(target, "__dict__")
    except Exception:
        state = None
    if type(state) is dict:
        _state_digest(state, digest, seen, budget, depth + 1)
    try:
        lineage = type.__getattribute__(kind, "__mro__")
    except Exception:
        lineage = (kind,)
    for base in lineage:
        namespace = type.__getattribute__(base, "__dict__")
        for name in sorted(namespace):
            descriptor = namespace[name]
            if type(descriptor) is not MemberDescriptorType:
                continue
            _digest_scalar(digest, b"slot-name", name.encode("utf-8", "replace"))
            try:
                value = descriptor.__get__(target, kind)
            except (AttributeError, TypeError):
                _digest_scalar(digest, b"empty-slot")
            else:
                _state_digest(value, digest, seen, budget, depth + 1)


def _state_digest(
    value: Any,
    digest: Any,
    seen: set[int],
    budget: list[int],
    depth: int = 0,
) -> None:
    """Hash extension state without invoking user representations or mappings."""
    if depth > _IDENTITY_DEPTH_LIMIT:
        raise ConfigurationError("extension identity state is too deeply nested")
    budget[0] -= 1
    if budget[0] < 0:
        raise ConfigurationError("extension identity state is too large")
    value_type = type(value)
    if value is None:
        _digest_scalar(digest, b"none")
        return
    if value_type is str:
        _digest_scalar(digest, b"string", value.encode("utf-8", "replace"))
        return
    if value_type is bytes:
        _digest_scalar(digest, b"bytes", value)
        return
    if value_type is bool:
        _digest_scalar(digest, b"bool", b"1" if value else b"0")
        return
    if value_type is int:
        _digest_scalar(digest, b"integer", str(value).encode("ascii"))
        return
    if value_type is float:
        marker = value.hex() if math.isfinite(value) else "non-finite"
        _digest_scalar(digest, b"float", marker.encode("ascii"))
        return

    identity = id(value)
    if identity in seen:
        _digest_scalar(digest, b"cycle")
        return
    seen.add(identity)
    try:
        if value_type in (list, tuple):
            _digest_scalar(digest, value_type.__name__.encode("ascii"), str(len(value)).encode())
            for item in value:
                _state_digest(item, digest, seen, budget, depth + 1)
            return
        if value_type in (set, frozenset):
            item_digests: list[bytes] = []
            for item in value:
                item_digest = hashlib.sha256()
                _state_digest(item, item_digest, seen, budget, depth + 1)
                item_digests.append(item_digest.digest())
            for item_bytes in sorted(item_digests):
                _digest_scalar(digest, b"set-item", item_bytes)
            return
        if value_type is dict:
            entries: list[tuple[bytes, Any]] = []
            for key, item in value.items():
                key_digest = hashlib.sha256()
                _state_digest(key, key_digest, seen, budget, depth + 1)
                entries.append((key_digest.digest(), item))
            for key_bytes, item in sorted(entries, key=lambda entry: entry[0]):
                _digest_scalar(digest, b"mapping-key", key_bytes)
                _state_digest(item, digest, seen, budget, depth + 1)
            return
        if value_type is CapabilityManifest:
            for field_name in (
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
            ):
                _digest_scalar(digest, b"manifest-field", field_name.encode("ascii"))
                _state_digest(
                    object.__getattribute__(value, field_name),
                    digest,
                    seen,
                    budget,
                    depth + 1,
                )
            return
        if value_type is FunctionType:
            _function_state(value, digest, seen, budget, depth)
            return
        if value_type is property:
            _state_digest(value.fget, digest, seen, budget, depth + 1)
            _state_digest(value.fset, digest, seen, budget, depth + 1)
            _state_digest(value.fdel, digest, seen, budget, depth + 1)
            return
        if isinstance(value, type):
            _class_state(value, digest, seen, budget, depth)
            return

        # Only recursively inspect an object that participates in the extension
        # contract. Other runtime objects (for example an imported module or a
        # loaded tensor/model) are represented by their exact type. Their object
        # identity is process-local and would make a reviewed plan impossible to
        # apply in a fresh CLI/server process. Observable literal, callable,
        # class, manifest, instance-dictionary, and slot state remains bound.
        try:
            capability = inspect.getattr_static(value, "capability")
        except Exception:
            capability = None
        kind = value_type
        namespace = type.__getattribute__(kind, "__dict__")
        module = _literal_name(namespace.get("__module__", ""))
        qualname = _literal_name(namespace.get("__qualname__", ""))
        _digest_scalar(digest, b"object-type", f"{module}.{qualname}".encode("utf-8", "replace"))
        if type(capability) is CapabilityManifest:
            _instance_state(value, digest, seen, budget, depth)
        else:
            _digest_scalar(digest, b"opaque-state")
    finally:
        seen.discard(identity)


def implementation_sha256(target: Any, *, instance_sensitive: bool = False) -> str:
    """Return a content-free implementation identity suitable for receipts."""
    digest = hashlib.sha256()
    kind = target if isinstance(target, type) else type(target)
    namespace = type.__getattribute__(kind, "__dict__")
    module = _literal_name(namespace.get("__module__", ""))
    qualname = _literal_name(namespace.get("__qualname__", ""))
    if isinstance(target, FunctionType):
        module = target.__module__
        qualname = target.__qualname__
    digest.update(module.encode("utf-8", "replace"))
    digest.update(qualname.encode("utf-8", "replace"))
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
        digest.update(f"instance:{_identity_token(target)}".encode("ascii"))
    return digest.hexdigest()


def static_state_sha256(target: Any) -> str:
    """Return a deterministic one-way fingerprint of observable extension state."""
    digest = hmac.new(_STATE_FINGERPRINT_KEY, digestmod=hashlib.sha256)
    _state_digest(target, digest, set(), [_IDENTITY_NODE_LIMIT])
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
        "static_state_sha256": static_state_sha256(target),
        **({"registry_revision": revision} if revision is not None else {}),
    }
