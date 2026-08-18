"""Bounded JSON subprocess adapter for candidate-generation strategies.

The configured executable is trusted by the caller, but every value crossing
the process boundary is treated as untrusted. Construction, capability access,
factory creation, and :meth:`CommandStrategy.available` never execute the
command. ``generate`` returns strings only; it never evaluates or accepts them.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, cast

from .bounded_process import BoundedProcessFailure, run_bounded_process
from .command_safety import validate_public_command, validate_public_json
from .config import DewatermarkConfig, resolve
from .exceptions import AdapterError
from .models import CapabilityManifest
from .optimizer import CandidateStrategy, DetectorFeedback, StrategyContext
from .request_context import (
    RequestContext,
    current_request_context,
    extension_resource_accounting,
    request_scope,
)

COMMAND_STRATEGY_PROTOCOL_VERSION = "1.0"
DEFAULT_COMMAND_STRATEGY_TIMEOUT_SECONDS = 60.0
DEFAULT_COMMAND_STRATEGY_STDOUT_BYTES = 4 * 1024 * 1024
DEFAULT_COMMAND_STRATEGY_STDERR_BYTES = 16 * 1024
DEFAULT_MAX_CANDIDATE_CHARACTERS = 1_000_000
DEFAULT_MAX_AGGREGATE_CANDIDATE_CHARACTERS = 4_000_000
_MAX_CAPTURE_BYTES = 16 * 1024 * 1024
_MAX_AGGREGATE_CHARACTERS = 64 * 1024 * 1024
_MAX_CONTEXT_SPANS = 4096
_MAX_CONTEXT_INTEGER = (1 << 63) - 1

_PROTOCOL_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PUBLIC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_DETECTION_STATUSES = frozenset(
    {
        "detected",
        "not_detected",
        "insufficient_evidence",
        "unsupported",
        "configuration_mismatch",
        "detector_error",
    }
)
_WINDOWS_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR", "PATHEXT")
_RESPONSE_KEYS = frozenset(
    {
        "protocol_version",
        "action",
        "strategy",
        "configuration_sha256",
        "candidates",
    }
)


class CommandStrategyError(AdapterError):
    """Base error for the command-strategy process boundary."""


class CommandStrategyContractError(CommandStrategyError):
    """The static contract, request context, or response was invalid."""


class CommandStrategyExecutionError(CommandStrategyError):
    """The command did not complete within its declared bounds."""


class CommandStrategyConsentError(CommandStrategyError, PermissionError):
    """A declared external requirement lacks explicit consent."""


def _public_json(value: Any, *, path: str = "configuration") -> Any:
    """Validate literal public JSON without reflecting its values in errors."""
    return validate_public_json(value, source=path)


def strategy_configuration_sha256(configuration: Mapping[str, Any]) -> str:
    """Fingerprint public strategy configuration, refusing credential fields."""
    if type(configuration) is not dict:
        raise TypeError("configuration must be a literal dictionary")
    public = _public_json(configuration)
    encoded = json.dumps(public, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def _fingerprint(value: Any, *, source: str) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise CommandStrategyContractError(f"{source} configuration_sha256 is invalid")
    return value.lower()


def command_strategy_manifest(
    *,
    identifier: str,
    configuration_sha256: str,
    schemes: Sequence[str] = (),
    version: str = "1",
    description: str = "External candidate generator using the bounded JSON command protocol.",
    network_required: bool = False,
    model_download_possible: bool = False,
    requires_secret: bool = False,
    minimum_characters: int = 0,
    metadata: Optional[Mapping[str, Any]] = None,
) -> CapabilityManifest:
    """Build a static transformer manifest for a command strategy."""
    if (
        type(identifier) is not str
        or not identifier.strip()
        or not _PUBLIC_IDENTIFIER.fullmatch(identifier.strip())
    ):
        raise ValueError("strategy identifier is invalid")
    if type(schemes) not in (list, tuple):
        raise TypeError("schemes must be a list or tuple")
    normalized_schemes: list[str] = []
    for scheme in schemes:
        if type(scheme) is not str or not scheme.strip():
            raise ValueError("strategy schemes must contain non-empty strings")
        normalized_schemes.append(scheme.strip())
    if len(set(normalized_schemes)) != len(normalized_schemes):
        raise ValueError("strategy schemes must be unique")
    fingerprint = _fingerprint(configuration_sha256, source="manifest")
    if type(minimum_characters) is not int or minimum_characters < 0:
        raise ValueError("minimum_characters must be a non-negative integer")
    for name, value in (
        ("network_required", network_required),
        ("model_download_possible", model_download_possible),
        ("requires_secret", requires_secret),
    ):
        if type(value) is not bool:
            raise TypeError(f"{name} must be boolean")
    if metadata is not None and type(metadata) is not dict:
        raise TypeError("metadata must be a literal dictionary")
    public_metadata = cast(dict[str, Any], _public_json(metadata or {}, path="metadata"))
    reserved = {
        "command_protocol_version": COMMAND_STRATEGY_PROTOCOL_VERSION,
        "configuration_sha256": fingerprint,
    }
    if set(public_metadata).intersection(reserved):
        raise ValueError("metadata cannot override command-strategy contract fields")
    return CapabilityManifest(
        identifier=identifier.strip(),
        kind="transformer",
        version=version,
        schemes=tuple(normalized_schemes),
        description=description,
        network_required=network_required,
        model_download_possible=model_download_possible,
        requires_secret=requires_secret,
        minimum_characters=minimum_characters,
        metadata={**public_metadata, **reserved},
    )


def _contract(capability: CapabilityManifest) -> tuple[str, str]:
    if type(capability) is not CapabilityManifest or capability.kind != "transformer":
        raise TypeError("capability must be a transformer CapabilityManifest")
    if not capability.identifier or not _PUBLIC_IDENTIFIER.fullmatch(capability.identifier):
        raise ValueError("strategy capability identifier is invalid")
    _public_json(capability.metadata, path="capability metadata")
    protocol = capability.metadata.get("command_protocol_version")
    if type(protocol) is not str or not _PROTOCOL_RE.fullmatch(protocol):
        raise CommandStrategyContractError("manifest protocol_version is invalid")
    if protocol != COMMAND_STRATEGY_PROTOCOL_VERSION:
        raise CommandStrategyContractError("manifest uses an incompatible command protocol")
    fingerprint = _fingerprint(capability.metadata.get("configuration_sha256"), source="manifest")
    return protocol, fingerprint


def _command(command: tuple[str, ...]) -> tuple[str, ...]:
    return validate_public_command(command)


def _limits(
    timeout_seconds: float,
    stdout_bytes: int,
    stderr_bytes: int,
    max_candidates: int,
    max_candidate_characters: int,
    max_aggregate_characters: int,
) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or type(timeout_seconds) not in (int, float)
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= 3600
    ):
        raise ValueError("timeout_seconds must be finite and between 0 and 3600")
    for name, value in (
        ("max_stdout_bytes", stdout_bytes),
        ("max_stderr_bytes", stderr_bytes),
    ):
        if type(value) is not int or not 1 <= value <= _MAX_CAPTURE_BYTES:
            raise ValueError(f"{name} must be between 1 and {_MAX_CAPTURE_BYTES}")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 1000:
        raise ValueError("max_candidates must be between 1 and 1000")
    if (
        type(max_candidate_characters) is not int
        or not 1 <= max_candidate_characters <= _MAX_AGGREGATE_CHARACTERS
    ):
        raise ValueError("max_candidate_characters is outside the supported range")
    if (
        type(max_aggregate_characters) is not int
        or not 1 <= max_aggregate_characters <= _MAX_AGGREGATE_CHARACTERS
        or max_aggregate_characters < max_candidate_characters
    ):
        raise ValueError("max_aggregate_candidate_characters is outside the supported range")


def _environment() -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", os.defpath)}
    if os.name == "nt":
        for key in _WINDOWS_ENVIRONMENT_KEYS:
            value = os.environ.get(key)
            if value is not None:
                environment[key] = value
    return environment


def _finite(value: Any, field: str, *, probability: bool = False) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or type(value) not in (int, float):
        raise CommandStrategyContractError(f"strategy context {field} must be numeric")
    number = float(value)
    if not math.isfinite(number):
        raise CommandStrategyContractError(f"strategy context {field} must be finite")
    if probability and not 0.0 <= number <= 1.0:
        raise CommandStrategyContractError(f"strategy context {field} must be between zero and one")
    return number


def _context_integer(value: Any, field: str, *, positive: bool = False) -> int:
    lower = 1 if positive else 0
    if type(value) is not int or not lower <= value <= _MAX_CONTEXT_INTEGER:
        qualifier = "positive" if positive else "non-negative"
        raise CommandStrategyContractError(
            f"strategy context {field} must be a {qualifier} integer"
        )
    return value


def _span(span: Any, text_characters: int) -> dict[str, Any]:
    from .detector_session import SignalSpan

    if type(span) is not SignalSpan:
        raise CommandStrategyContractError("strategy context contains an invalid signal span")
    if span.start < 0 or span.end <= span.start or span.end > text_characters:
        raise CommandStrategyContractError("strategy context signal span is out of bounds")
    values = {
        "start": span.start,
        "end": span.end,
        "score": _finite(span.score, "span score"),
        "p_value": _finite(span.p_value, "span p_value", probability=True),
        "threshold": _finite(span.threshold, "span threshold"),
    }
    return {key: value for key, value in values.items() if value is not None}


def _spans(value: Any, text_characters: int) -> list[dict[str, Any]]:
    if type(value) is not tuple or len(value) > _MAX_CONTEXT_SPANS:
        raise CommandStrategyContractError("strategy context signal spans are invalid")
    return [_span(span, text_characters) for span in value]


def _feedback(feedback: Any, text_characters: int) -> dict[str, Any]:
    if type(feedback) is not DetectorFeedback:
        raise CommandStrategyContractError("strategy context detector feedback is invalid")
    if (
        type(feedback.detector) is not str
        or not _PUBLIC_IDENTIFIER.fullmatch(feedback.detector)
        or type(feedback.status) is not str
        or feedback.status not in _DETECTION_STATUSES
    ):
        raise CommandStrategyContractError("strategy context detector feedback is invalid")
    values: dict[str, Any] = {
        "detector": feedback.detector,
        "status": feedback.status,
        "score": _finite(feedback.score, "detector score"),
        "threshold": _finite(feedback.threshold, "detector threshold"),
        "p_value": _finite(feedback.p_value, "detector p_value", probability=True),
        "detection_margin": _finite(feedback.detection_margin, "detector margin"),
        "localization": _spans(feedback.localization, text_characters),
    }
    return {key: value for key, value in values.items() if value is not None}


def _strategy_context(
    context: Any, text_characters: int, effective_candidate_limit: int
) -> dict[str, Any]:
    if type(context) is not StrategyContext:
        raise CommandStrategyContractError("strategy context is invalid")
    declared_limit = _context_integer(context.candidate_limit, "candidate_limit", positive=True)
    if declared_limit < effective_candidate_limit:
        raise CommandStrategyContractError("strategy context candidate_limit is inconsistent")
    return {
        "round_index": _context_integer(context.round_index, "round_index"),
        "invocation_index": _context_integer(
            context.invocation_index, "invocation_index", positive=True
        ),
        "random_seed": _context_integer(context.random_seed, "random_seed"),
        "candidate_limit": effective_candidate_limit,
        "detector_feedback": _feedback(context.feedback, text_characters),
        "source_localization": _spans(context.source_localization, text_characters),
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CommandStrategyContractError(
                "command strategy response contains duplicate JSON keys"
            )
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise CommandStrategyContractError(
        "command strategy response contains a non-finite JSON number"
    )


def _decode(output: bytes) -> dict[str, Any]:
    try:
        text = output.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise CommandStrategyContractError(
            "command strategy returned non-UTF-8 output; response content was redacted"
        ) from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except CommandStrategyContractError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise CommandStrategyContractError(
            "command strategy returned invalid JSON; response content was redacted"
        ) from None
    if type(value) is not dict:
        raise CommandStrategyContractError("command strategy must return one JSON object")
    return value


def _estimated_tokens(candidates: Sequence[str]) -> int:
    estimate = 0
    for candidate in candidates:
        encoded = candidate.encode("utf-8", "surrogatepass")
        ascii_characters = sum(byte < 128 for byte in encoded)
        non_ascii_bytes = len(encoded) - ascii_characters
        estimate += max(
            len(candidate.split()),
            math.ceil(ascii_characters / 4) + math.ceil(non_ascii_bytes / 3),
        )
    return estimate


def _run(
    command: tuple[str, ...],
    payload: bytes,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> bytes:
    def checkpoint() -> None:
        context = current_request_context()
        if context is not None:
            context.checkpoint()

    try:
        result = run_bounded_process(
            command,
            payload,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            environment=_environment(),
            checkpoint=checkpoint,
        )
    except BoundedProcessFailure as exc:
        if exc.kind == "launch_failed":
            message = "command strategy could not be launched; process details were redacted"
        elif exc.kind == "timed_out":
            message = "command strategy timed out; stdout and stderr were redacted"
        elif exc.kind == "output_limit":
            message = "command strategy exceeded its output limit; output was redacted"
        elif exc.kind == "nonzero_exit":
            message = f"command strategy exited with status {exc.returncode}; output was redacted"
        else:
            message = "command strategy cleanup failed; process details were redacted"
        raise CommandStrategyExecutionError(message) from None
    return result.stdout


class CommandStrategy:
    """Candidate generator backed by one explicitly configured JSON command."""

    def __init__(
        self,
        command: tuple[str, ...],
        capability: CapabilityManifest,
        config: Optional[DewatermarkConfig] = None,
        *,
        timeout_seconds: float = DEFAULT_COMMAND_STRATEGY_TIMEOUT_SECONDS,
        max_stdout_bytes: int = DEFAULT_COMMAND_STRATEGY_STDOUT_BYTES,
        max_stderr_bytes: int = DEFAULT_COMMAND_STRATEGY_STDERR_BYTES,
        max_candidates: int = 8,
        max_candidate_characters: int = DEFAULT_MAX_CANDIDATE_CHARACTERS,
        max_aggregate_candidate_characters: int = DEFAULT_MAX_AGGREGATE_CANDIDATE_CHARACTERS,
    ) -> None:
        self._command = _command(command)
        self.capability = capability
        self._protocol, self._configuration_sha256 = _contract(capability)
        self._config = resolve(config)
        _limits(
            timeout_seconds,
            max_stdout_bytes,
            max_stderr_bytes,
            max_candidates,
            max_candidate_characters,
            max_aggregate_candidate_characters,
        )
        self._timeout_seconds = float(timeout_seconds)
        self._max_stdout_bytes = max_stdout_bytes
        self._max_stderr_bytes = max_stderr_bytes
        self._max_candidates = max_candidates
        self._max_candidate_characters = max_candidate_characters
        self._max_aggregate_candidate_characters = max_aggregate_candidate_characters

    def __repr__(self) -> str:
        return "<command strategy; representation redacted>"

    def available(self) -> bool:
        """Check executable presence without starting a subprocess."""
        executable = self._command[0]
        if os.path.dirname(executable):
            return os.path.isfile(executable) and os.access(executable, os.X_OK)
        return shutil.which(executable) is not None

    def _preflight(
        self,
        text: Any,
        options: Mapping[str, Any],
        *,
        allow_network: bool,
        allow_model_download: bool,
    ) -> None:
        if type(text) is not str or not text:
            raise CommandStrategyContractError("command strategy text must be a non-empty string")
        try:
            text.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise CommandStrategyContractError(
                "command strategy text is not valid Unicode text"
            ) from None
        if len(text) < self.capability.minimum_characters:
            raise CommandStrategyContractError("command strategy input is below its static minimum")
        if len(text) > self._config.max_input_chars:
            raise CommandStrategyContractError("command strategy input exceeds max_input_chars")
        if options:
            raise CommandStrategyContractError(
                "command strategy does not accept an implicit options channel"
            )
        if self.capability.requires_secret:
            raise CommandStrategyConsentError(
                "command strategy requires a secret, but no explicit secret channel exists"
            )
        if self.capability.network_required and not allow_network:
            raise CommandStrategyConsentError(
                "command strategy requires explicit remote-processing consent"
            )
        if self.capability.model_download_possible and not allow_model_download:
            raise CommandStrategyConsentError(
                "command strategy requires explicit model-download consent"
            )

    def _normalize(
        self,
        response: dict[str, Any],
        *,
        max_candidates: int,
        max_candidate_characters: int,
        max_aggregate_characters: int,
        max_output_tokens: int,
    ) -> tuple[str, ...]:
        if set(response) != _RESPONSE_KEYS:
            raise CommandStrategyContractError(
                "command strategy response contains missing or unknown fields"
            )
        if response.get("protocol_version") != self._protocol:
            raise CommandStrategyContractError(
                "command strategy returned an incompatible protocol version"
            )
        if response.get("action") != "generate.result":
            raise CommandStrategyContractError(
                "command strategy response action must be generate.result"
            )
        if response.get("strategy") != self.capability.identifier:
            raise CommandStrategyContractError(
                "command strategy response identifier does not match its manifest"
            )
        if (
            _fingerprint(response.get("configuration_sha256"), source="response")
            != self._configuration_sha256
        ):
            raise CommandStrategyContractError(
                "command strategy response configuration does not match its manifest"
            )
        raw_candidates = response.get("candidates")
        if type(raw_candidates) is not list:
            raise CommandStrategyContractError("command strategy candidates must be one JSON array")
        if len(raw_candidates) > max_candidates:
            raise CommandStrategyContractError("command strategy returned too many candidates")
        candidates: list[str] = []
        aggregate = 0
        for candidate in raw_candidates:
            if type(candidate) is not str:
                raise CommandStrategyContractError(
                    "command strategy candidates must contain exact strings"
                )
            if len(candidate) > max_candidate_characters:
                raise CommandStrategyContractError(
                    "command strategy candidate exceeds the character limit"
                )
            try:
                candidate.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise CommandStrategyContractError(
                    "command strategy candidate is not valid Unicode text"
                ) from None
            aggregate += len(candidate)
            if aggregate > max_aggregate_characters:
                raise CommandStrategyContractError(
                    "command strategy candidates exceed the aggregate character limit"
                )
            candidates.append(candidate)
        estimated = _estimated_tokens(candidates)
        if estimated > max_output_tokens:
            raise CommandStrategyContractError(
                "command strategy candidates exceed the reserved output-token limit"
            )
        return tuple(candidates)

    def generate(self, text: str, *, context: StrategyContext, **options: Any) -> tuple[str, ...]:
        """Run the command and return bounded, untrusted candidate strings."""
        active = current_request_context()
        if active is None:
            with request_scope(RequestContext.from_config(self._config)):
                return self.generate(text, context=context, **options)
        allow_network = self._config.allow_remote_processing and active.allow_remote_processing
        allow_model_download = self._config.allow_model_download and active.allow_model_download
        self._preflight(
            text,
            options,
            allow_network=allow_network,
            allow_model_download=allow_model_download,
        )

        if type(context) is not StrategyContext:
            raise CommandStrategyContractError("strategy context is invalid")
        declared_candidate_limit = _context_integer(
            context.candidate_limit, "candidate_limit", positive=True
        )
        max_candidates = min(
            declared_candidate_limit,
            self._max_candidates,
            self._config.max_search_candidates,
        )
        max_candidate_characters = min(
            self._max_candidate_characters,
            self._config.max_input_chars,
        )
        max_aggregate_characters = min(
            self._max_aggregate_candidate_characters,
            max_candidate_characters * max_candidates,
        )
        context_value = _strategy_context(context, len(text), max_candidates)
        timeout = active.remaining_seconds(
            min(self._timeout_seconds, float(self._config.request_timeout))
        )
        requested_output_tokens = active.remaining_output_tokens(self._config.max_output_tokens)
        reserved_output_tokens = active.reserve_output_tokens(requested_output_tokens)
        accounting = extension_resource_accounting(self.capability)
        attempted = False
        network_accounting = accounting == "network"
        try:
            if network_accounting:
                active.before_remote_call(
                    "https://external-command-strategy.invalid/generate",
                    "remote",
                    {"text": text, "max_candidates": max_candidates},
                )
            if accounting == "model" or self.capability.model_download_possible:
                active.record_model_access(
                    self.capability.identifier,
                    cached=not self.capability.model_download_possible,
                    download_allowed=allow_model_download,
                )
            request = {
                "protocol_version": COMMAND_STRATEGY_PROTOCOL_VERSION,
                "action": "generate",
                "strategy": self.capability.identifier,
                "configuration_sha256": self._configuration_sha256,
                "policy": {
                    "allow_network": allow_network,
                    "allow_model_download": allow_model_download,
                    "max_candidates": max_candidates,
                    "max_candidate_characters": max_candidate_characters,
                    "max_aggregate_candidate_characters": max_aggregate_characters,
                    "max_output_tokens": reserved_output_tokens,
                },
                "context": context_value,
                "text": text,
            }
            payload = json.dumps(
                request, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("ascii")
            attempted = True
            output = _run(
                self._command,
                payload,
                timeout_seconds=timeout,
                max_stdout_bytes=self._max_stdout_bytes,
                max_stderr_bytes=self._max_stderr_bytes,
            )
            candidates = self._normalize(
                _decode(output),
                max_candidates=max_candidates,
                max_candidate_characters=max_candidate_characters,
                max_aggregate_characters=max_aggregate_characters,
                max_output_tokens=reserved_output_tokens,
            )
            active.checkpoint()
        except BaseException:
            if attempted:
                if network_accounting:
                    active.record_usage(
                        {
                            "completion_tokens": reserved_output_tokens,
                            "total_tokens": reserved_output_tokens,
                        }
                    )
                else:
                    active.reconcile_local_generation(reserved_output_tokens)
            else:
                active.release_latest_output_reservation()
            raise
        actual_tokens = _estimated_tokens(candidates)
        if network_accounting:
            active.record_usage({"completion_tokens": actual_tokens, "total_tokens": actual_tokens})
        else:
            active.reconcile_local_generation(actual_tokens)
        return candidates


@dataclass(frozen=True, repr=False)
class CommandStrategyFactory:
    """Static, registration-friendly factory that never starts its command."""

    command: tuple[str, ...]
    capability: CapabilityManifest
    timeout_seconds: float = DEFAULT_COMMAND_STRATEGY_TIMEOUT_SECONDS
    max_stdout_bytes: int = DEFAULT_COMMAND_STRATEGY_STDOUT_BYTES
    max_stderr_bytes: int = DEFAULT_COMMAND_STRATEGY_STDERR_BYTES
    max_candidates: int = 8
    max_candidate_characters: int = DEFAULT_MAX_CANDIDATE_CHARACTERS
    max_aggregate_candidate_characters: int = DEFAULT_MAX_AGGREGATE_CANDIDATE_CHARACTERS

    def __post_init__(self) -> None:
        _command(self.command)
        _contract(self.capability)
        _limits(
            self.timeout_seconds,
            self.max_stdout_bytes,
            self.max_stderr_bytes,
            self.max_candidates,
            self.max_candidate_characters,
            self.max_aggregate_candidate_characters,
        )

    def __repr__(self) -> str:
        return "<command strategy factory; representation redacted>"

    def __call__(self, config: Optional[DewatermarkConfig] = None) -> CommandStrategy:
        return CommandStrategy(
            self.command,
            self.capability,
            config,
            timeout_seconds=self.timeout_seconds,
            max_stdout_bytes=self.max_stdout_bytes,
            max_stderr_bytes=self.max_stderr_bytes,
            max_candidates=self.max_candidates,
            max_candidate_characters=self.max_candidate_characters,
            max_aggregate_candidate_characters=self.max_aggregate_candidate_characters,
        )


def make_command_strategy_factory(
    command: tuple[str, ...],
    capability: CapabilityManifest,
    *,
    timeout_seconds: float = DEFAULT_COMMAND_STRATEGY_TIMEOUT_SECONDS,
    max_stdout_bytes: int = DEFAULT_COMMAND_STRATEGY_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_COMMAND_STRATEGY_STDERR_BYTES,
    max_candidates: int = 8,
    max_candidate_characters: int = DEFAULT_MAX_CANDIDATE_CHARACTERS,
    max_aggregate_candidate_characters: int = DEFAULT_MAX_AGGREGATE_CANDIDATE_CHARACTERS,
) -> CommandStrategyFactory:
    """Create a factory without launching or probing the configured command."""
    return CommandStrategyFactory(
        command=command,
        capability=capability,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        max_candidates=max_candidates,
        max_candidate_characters=max_candidate_characters,
        max_aggregate_candidate_characters=max_aggregate_candidate_characters,
    )


__all__ = [
    "COMMAND_STRATEGY_PROTOCOL_VERSION",
    "CandidateStrategy",
    "CommandStrategy",
    "CommandStrategyConsentError",
    "CommandStrategyContractError",
    "CommandStrategyError",
    "CommandStrategyExecutionError",
    "CommandStrategyFactory",
    "command_strategy_manifest",
    "make_command_strategy_factory",
    "strategy_configuration_sha256",
]
