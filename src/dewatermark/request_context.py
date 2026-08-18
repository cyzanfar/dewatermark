"""Request-scoped safety, resource, cancellation, and privacy accounting.

The context is intentionally internal to a request and contains no source text.
Remote backends and local model helpers discover it through a ``ContextVar`` so
existing public backend signatures remain compatible.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from threading import Event, RLock, get_ident
from typing import Any, Iterator, Mapping, Optional, cast
from urllib.parse import urlparse

from .config import DewatermarkConfig
from .exceptions import BackendUnavailableError

_PUBLIC_BACKENDS = frozenset({"fireworks", "llm", "remote"})
_SAFE_ERROR_KINDS = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")
_QUALITY_SCALARS = frozenset(
    {
        "passed",
        "length_ratio",
        "distinct_1_ratio",
        "unresolved_placeholders",
        "semantic_score",
    }
)
_QUALITY_REASONS = frozenset(
    {
        "empty candidate",
        "length ratio outside configured bounds",
        "degenerate repetition",
        "numbers were dropped",
        "numbers were introduced",
        "dates changed",
        "quantities or units changed",
        "URLs were dropped",
        "URLs were introduced",
        "email addresses were dropped",
        "email addresses were introduced",
        "quoted text was dropped",
        "quoted text was introduced",
        "negation changed",
        "modality changed",
        "protected entity-like spans changed",
        "citations changed",
        "document structure changed",
        "unresolved mask placeholder",
        "semantic score below threshold",
        "external quality gate rejected candidate",
    }
)
_STRUCTURE_REASONS = frozenset(
    {
        "fenced code blocks changed",
        "Markdown code-fence structure changed",
        "inline code spans changed",
        "Markdown link targets changed",
        "HTML tag structure changed",
        "Markdown heading structure changed",
        "Markdown list structure changed",
        "Markdown table structure changed",
        "candidate is not valid JSON",
        "JSON keys, types, or protected scalar values changed",
        "external quality gate reported a structural mismatch",
    }
)


class ResourceBudgetExceeded(BackendUnavailableError):
    """A request exceeded a declared call, token, or wall-clock limit."""


class ExtensionUsageRejected(ResourceBudgetExceeded):
    """An extension could not enter its declared accounting boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__("extension resource accounting preflight failed")


@dataclass
class RequestContext:
    """Mutable request ledger shared by every nested backend operation."""

    max_remote_calls: int
    max_output_tokens: int
    deadline: float
    allow_remote_processing: bool
    allow_model_download: bool
    cancel_event: Optional[Event] = field(default=None, repr=False)
    remote_calls: int = 0
    transmitted_characters: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    usage_reports: int = 0
    endpoints: set[str] = field(default_factory=set)
    backends: set[str] = field(default_factory=set)
    model_accesses: list[dict[str, Any]] = field(default_factory=list)
    _output_reservations: dict[int, list[int]] = field(default_factory=dict, repr=False)
    cancelled: bool = False
    deadline_exceeded: bool = False
    _lock: RLock = field(default_factory=RLock, repr=False)

    def __post_init__(self) -> None:
        if type(self.max_remote_calls) is not int or self.max_remote_calls < 0:
            raise ValueError("request remote-call limit must be a non-negative integer")
        if type(self.max_output_tokens) is not int or self.max_output_tokens < 1:
            raise ValueError("request output-token limit must be a positive integer")
        if (
            type(self.deadline) not in (int, float)
            or not math.isfinite(float(self.deadline))
            or self.deadline <= 0
        ):
            raise ValueError("request deadline must be a finite positive monotonic time")
        if (
            type(self.allow_remote_processing) is not bool
            or type(self.allow_model_download) is not bool
        ):
            raise TypeError("request consent flags must be boolean")

    @classmethod
    def from_config(
        cls, config: DewatermarkConfig, cancel_event: Optional[Event] = None
    ) -> "RequestContext":
        return cls(
            max_remote_calls=config.max_remote_calls,
            max_output_tokens=config.max_output_tokens,
            deadline=time.monotonic() + config.request_timeout,
            allow_remote_processing=config.allow_remote_processing,
            allow_model_download=config.allow_model_download,
            cancel_event=cancel_event,
        )

    def checkpoint(self) -> None:
        """Fail promptly on cancellation or expiration."""
        if self.cancel_event is not None and self.cancel_event.is_set():
            self.cancelled = True
            raise asyncio.CancelledError
        if time.monotonic() >= self.deadline:
            self.deadline_exceeded = True
            raise ResourceBudgetExceeded("request deadline exceeded")

    def remaining_seconds(self, requested: Optional[float] = None) -> float:
        self.checkpoint()
        remaining = max(0.001, self.deadline - time.monotonic())
        return min(remaining, requested) if requested is not None else remaining

    def remaining_output_tokens(self, requested: Optional[int] = None) -> int:
        """Bound a completion by the unspent request-level token ledger.

        Providers that report usage make this exact. Providers without usage are
        still bounded per call and transparently reported as unmetered.
        """
        if requested is not None and (type(requested) is not int or requested < 1):
            raise ResourceBudgetExceeded("request output-token budget exhausted")
        with self._lock:
            committed = self.completion_tokens + sum(
                sum(reservations) for reservations in self._output_reservations.values()
            )
            remaining = max(0, self.max_output_tokens - committed)
        if remaining < 1:
            raise ResourceBudgetExceeded("request output-token budget exhausted")
        return min(remaining, requested) if requested is not None else remaining

    def remaining_remote_calls(self) -> int:
        with self._lock:
            return max(0, self.max_remote_calls - self.remote_calls)

    def reserve_output_tokens(self, requested: int) -> int:
        """Reserve a conservative generation ceiling until usage reconciles it."""
        self.checkpoint()
        if type(requested) is not int or requested < 1:
            raise ResourceBudgetExceeded("request output-token budget exhausted")
        with self._lock:
            committed = self.completion_tokens + sum(
                sum(reservations) for reservations in self._output_reservations.values()
            )
            allowed = min(requested, max(0, self.max_output_tokens - committed))
            if allowed < 1:
                raise ResourceBudgetExceeded("request output-token budget exhausted")
            self._output_reservations.setdefault(get_ident(), []).append(allowed)
            return allowed

    def before_remote_call(self, url: str, backend: str, body: Mapping[str, Any]) -> None:
        """Reserve one physical HTTP attempt and record only privacy-safe metadata."""
        self.checkpoint()
        if not self.allow_remote_processing:
            raise ExtensionUsageRejected("remote_processing_not_permitted")
        parsed = urlparse(url)
        endpoint = parsed.hostname or "unknown"
        endpoint_digest = hashlib.sha256(endpoint.encode("utf-8", "replace")).hexdigest()
        # JSON length is a conservative measure of transmitted characters. The
        # payload itself is deliberately never retained.
        try:
            transmitted = len(
                json.dumps(body, ensure_ascii=False, default=lambda _value: "<non-json>")
            )
        except Exception:
            transmitted = 0
        if isinstance(backend, str) and backend in _PUBLIC_BACKENDS:
            public_backend = backend
        elif isinstance(backend, str):
            digest = hashlib.sha256(backend.encode("utf-8", "replace")).hexdigest()[:16]
            public_backend = f"external:{digest}"
        else:
            public_backend = "external:invalid"
        with self._lock:
            if self.remote_calls >= self.max_remote_calls:
                raise ResourceBudgetExceeded(
                    f"remote-call budget exhausted ({self.max_remote_calls})"
                )
            maximum = body.get("max_tokens")
            if type(maximum) in (int, float):
                numeric_maximum = cast(float, maximum)
                if math.isfinite(numeric_maximum) and numeric_maximum > 0:
                    committed = self.completion_tokens + sum(
                        sum(reservations) for reservations in self._output_reservations.values()
                    )
                    allowed = min(
                        int(numeric_maximum),
                        max(0, self.max_output_tokens - committed),
                    )
                    if allowed < int(numeric_maximum):
                        raise ResourceBudgetExceeded("request output-token budget exhausted")
                    self._output_reservations.setdefault(get_ident(), []).append(allowed)
            # Commit accounting only after every budget check succeeds. A call
            # rejected here never reached the network and is not a physical attempt.
            self.remote_calls += 1
            self.transmitted_characters += transmitted
            self.endpoints.add(endpoint_digest)
            self.backends.add(public_backend)

    def record_usage(self, usage: Mapping[str, Any]) -> None:
        with self._lock:
            self.usage_reports += 1
            prompt = usage.get("prompt_tokens")
            completion = usage.get("completion_tokens")
            total = usage.get("total_tokens")
            numeric_prompt = cast(float, prompt)
            if (
                type(prompt) in (int, float)
                and math.isfinite(numeric_prompt)
                and numeric_prompt >= 0
            ):
                self.prompt_tokens += int(numeric_prompt)
            numeric_completion = cast(float, completion)
            if (
                type(completion) in (int, float)
                and math.isfinite(numeric_completion)
                and numeric_completion >= 0
            ):
                reservations = self._output_reservations.get(get_ident(), [])
                if reservations:
                    reservations.pop(0)
                if not reservations:
                    self._output_reservations.pop(get_ident(), None)
                self.completion_tokens += int(numeric_completion)
            numeric_total = cast(float, total)
            if type(total) in (int, float) and math.isfinite(numeric_total) and numeric_total >= 0:
                self.total_tokens += int(numeric_total)

    def reconcile_local_generation(self, actual_tokens: int) -> None:
        """Replace the oldest local reservation with an observed token count."""
        with self._lock:
            reservations = self._output_reservations.get(get_ident(), [])
            if reservations:
                reservations.pop(0)
            if not reservations:
                self._output_reservations.pop(get_ident(), None)
            self.completion_tokens += max(0, int(actual_tokens))

    def release_latest_output_reservation(self) -> None:
        """Release a reservation after a definitive no-completion HTTP response."""
        with self._lock:
            reservations = self._output_reservations.get(get_ident(), [])
            if reservations:
                reservations.pop()
            if not reservations:
                self._output_reservations.pop(get_ident(), None)

    def record_model_access(self, model: str, *, cached: bool, download_allowed: bool) -> None:
        """Record a hashed model identifier, never a potentially private path."""
        if type(model) is not str:
            raise TypeError("model identifier must be a string")
        if type(download_allowed) is not bool:
            raise TypeError("model download permission must be boolean")
        if download_allowed and not self.allow_model_download:
            raise ExtensionUsageRejected("model_download_not_permitted")
        digest = hashlib.sha256(model.encode("utf-8", "replace")).hexdigest()
        with self._lock:
            self.model_accesses.append(
                {
                    "model_sha256": digest,
                    "cached": cached,
                    "download_allowed": download_allowed,
                }
            )

    def ledger(self) -> dict[str, Any]:
        with self._lock:
            return {
                "remote_processing_allowed": self.allow_remote_processing,
                "model_download_allowed": self.allow_model_download,
                "remote_calls_used": self.remote_calls,
                "remote_calls_limit": self.max_remote_calls,
                "transmitted_characters": self.transmitted_characters,
                "endpoint_sha256": sorted(self.endpoints),
                "backends": sorted(self.backends),
                "token_usage": {
                    "prompt_tokens": self.prompt_tokens,
                    "completion_tokens": self.completion_tokens,
                    "total_tokens": self.total_tokens,
                    "completion_token_limit": self.max_output_tokens,
                    "completion_tokens_reserved": sum(
                        sum(reservations) for reservations in self._output_reservations.values()
                    ),
                    "usage_reports": self.usage_reports,
                    "remote_calls_without_reported_usage": max(
                        0, self.remote_calls - self.usage_reports
                    ),
                },
                "model_accesses": list(self.model_accesses),
                "cancelled": self.cancelled,
                "deadline_exceeded": self.deadline_exceeded,
            }


_CURRENT: ContextVar[Optional[RequestContext]] = ContextVar(
    "dewatermark_request_context", default=None
)


def current_request_context() -> Optional[RequestContext]:
    return _CURRENT.get()


def extension_usage_snapshot() -> tuple[Optional[RequestContext], int, int]:
    """Capture content-free resource counters before invoking an extension."""
    context = current_request_context()
    if context is None:
        return None, 0, 0
    ledger = context.ledger()
    return context, int(ledger["remote_calls_used"]), len(ledger["model_accesses"])


def extension_resource_accounting(capability: Any) -> str:
    """Resolve a validated accounting contract from a static capability.

    Network use always requires parent-ledger accounting. A capability that may
    acquire a model defaults to model accounting unless it declares a stricter
    policy. Pure, dependency-free extensions may explicitly or implicitly use
    ``none``.
    """
    network_required = getattr(capability, "network_required", None)
    download_possible = getattr(capability, "model_download_possible", None)
    metadata = getattr(capability, "metadata", None)
    if type(network_required) is not bool or type(download_possible) is not bool:
        raise TypeError("extension capability resource flags must be boolean")
    if type(metadata) is not dict:
        raise TypeError("extension capability metadata must be a literal dictionary")
    default = "model" if download_possible else "none"
    accounting = metadata.get("resource_accounting", default)
    if type(accounting) is not str or accounting not in {"none", "model", "network"}:
        raise TypeError("extension resource_accounting must be none, model, or network")
    if network_required:
        return "network"
    if download_possible and accounting == "none":
        return "model"
    return accounting


def begin_extension_usage(
    capability: Any,
) -> tuple[tuple[Optional[RequestContext], int, int], str]:
    """Fail before extension execution when its declared budget is unavailable."""
    accounting = extension_resource_accounting(capability)
    network_required = capability.network_required
    download_possible = capability.model_download_possible
    snapshot = extension_usage_snapshot()
    if accounting == "none":
        return snapshot, accounting
    context = snapshot[0]
    if context is None:
        raise ExtensionUsageRejected("request_context_required")
    context.checkpoint()
    if network_required and not context.allow_remote_processing:
        raise ExtensionUsageRejected("remote_processing_not_permitted")
    if download_possible and not context.allow_model_download:
        raise ExtensionUsageRejected("model_download_not_permitted")
    if accounting == "network" and context.remaining_remote_calls() < 1:
        raise ResourceBudgetExceeded(f"remote-call budget exhausted ({context.max_remote_calls})")
    return snapshot, accounting


def extension_usage_error(
    snapshot: tuple[Optional[RequestContext], int, int],
    *,
    network_required: bool,
    resource_accounting: str,
) -> Optional[str]:
    """Return a reason code when declared extension work bypassed the ledger."""
    accounting = "network" if network_required else resource_accounting
    if accounting == "none":
        return None
    context, calls_before, models_before = snapshot
    if context is None:
        return "request_context_required"
    ledger = context.ledger()
    if accounting == "network" and int(ledger["remote_calls_used"]) <= calls_before:
        return "remote_usage_not_accounted"
    if accounting == "model" and len(ledger["model_accesses"]) <= models_before:
        return "model_usage_not_accounted"
    return None


@contextmanager
def request_scope(context: RequestContext) -> Iterator[RequestContext]:
    token: Token[Optional[RequestContext]] = _CURRENT.set(context)
    try:
        yield context
    finally:
        _CURRENT.reset(token)


def checkpoint() -> None:
    context = current_request_context()
    if context is not None:
        context.checkpoint()


def safe_error(kind: str, exc: BaseException) -> str:
    """Return an actionable error without reflecting remote/source content."""
    if isinstance(exc, ResourceBudgetExceeded):
        message = str(exc)
        if message == "request deadline exceeded":
            return message
        if message == "request output-token budget exhausted":
            return message
        if re.fullmatch(r"remote-call budget exhausted \(\d+\)", message):
            return message
        return "request resource budget exceeded"
    if isinstance(exc, asyncio.CancelledError):
        return "request cancelled"
    public_kind = kind if _SAFE_ERROR_KINDS.fullmatch(kind) else "operation"
    return f"{public_kind} failed; details were redacted"


def public_quality_report(report: Any) -> dict[str, Any]:
    """Serialize a quality result without retaining protected source spans.

    Built-in quality reports contain the exact numbers, URLs, addresses, quoted
    strings, and entity-like spans that differed. Those diagnostics are useful
    in-process but must not be copied into provider stage reports or logs.
    """
    try:
        raw = report.to_dict()
    except Exception:
        return {
            "passed": False,
            "reasons": ["quality report could not be serialized safely"],
        }
    if not isinstance(raw, Mapping):
        return {
            "passed": False,
            "reasons": ["quality report could not be serialized safely"],
        }
    public = {key: raw.get(key) for key in _QUALITY_SCALARS if key in raw}
    protected_counts = {
        str(key): len(value)
        for key, value in raw.items()
        if key not in _QUALITY_SCALARS
        and key not in {"reasons", "structure_errors"}
        and isinstance(value, (list, tuple))
        and value
    }
    if protected_counts:
        public["protected_difference_counts"] = protected_counts
    reasons = raw.get("reasons")
    if isinstance(reasons, (list, tuple)):
        public["reasons"] = [
            item
            if isinstance(item, str) and item in _QUALITY_REASONS
            else "quality gate rejected candidate"
            for item in reasons
        ]
    structure = raw.get("structure_errors")
    if isinstance(structure, (list, tuple)):
        public["structure_errors"] = [
            item
            if isinstance(item, str) and item in _STRUCTURE_REASONS
            else "document structure changed"
            for item in structure
        ]
    return public
