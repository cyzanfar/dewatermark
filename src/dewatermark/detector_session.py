"""Request-scoped, content-free detector scoring and verification.

``DetectorSession`` is the single detector-query boundary used by adaptive
mitigation. It deliberately owns a budget separate from remote/model budgets,
caches observations by a text digest, and never retains text in its public
trace. Detector implementations still run through :func:`run_detector`, so the
existing consent, deadline, cancellation, and extension-accounting rules apply.
"""

from __future__ import annotations

import hashlib
import inspect
import math
import re
import types
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from threading import RLock
from typing import Any, Iterator, Literal, Optional, Sequence, cast

from .assurance import evaluate_verification, resolve_detector
from .command_safety import command_code_identity_sha256
from .config import DewatermarkConfig, resolve
from .detectors import capability_of, run_detector
from .extension_safety import extension_identity, implementation_sha256, manifest_sha256
from .models import (
    CapabilityManifest,
    DetectionEvidence,
    VerificationEvidence,
    _public_identifier,
)
from .request_context import (
    RequestContext,
    ResourceBudgetExceeded,
    current_request_context,
    request_scope,
)

DetectorRole = Literal["primary", "verifier"]
ScoreDirection = Literal["higher", "lower"]
SessionVerificationStatus = Literal["verified", "residual", "not_verifiable", "failed"]

_PUBLIC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _digest(text: str) -> str:
    # Unlike ``replace``, surrogatepass cannot collapse distinct Python strings
    # onto one detector-cache key.
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _identifier(value: Any, fallback: str) -> str:
    if type(value) is str and _PUBLIC_IDENTIFIER.fullmatch(value):
        projected = _public_identifier(value)
        if projected != "redacted-identifier":
            return projected
    return fallback


def _finite(value: Any) -> Optional[float]:
    if isinstance(value, bool) or type(value) not in (int, float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _probability(value: Any) -> Optional[float]:
    number = _finite(value)
    return number if number is not None and 0.0 <= number <= 1.0 else None


def _immutable_callable_value(value: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if value is None or type(value) in (str, bytes, bool, int, float, complex):
        return True
    if type(value) in (tuple, frozenset):
        return all(_immutable_callable_value(item, depth=depth + 1) for item in value)
    return False


def _verification_callable_state_safe(function: Any) -> bool:
    if not inspect.isfunction(function):
        return False
    if not all(_immutable_callable_value(item) for item in (function.__defaults__ or ())):
        return False
    if not all(
        _immutable_callable_value(item) for item in (function.__kwdefaults__ or {}).values()
    ):
        return False
    closure = function.__closure__ or ()
    for cell in closure:
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        # ``super()`` creates an immutable ``__class__`` closure. The class's
        # effective methods are already part of ``implementation_sha256``.
        if not (_immutable_callable_value(value) or isinstance(value, type)):
            return False
    for name in set(function.__code__.co_names):
        if name not in function.__globals__ or name == "__builtins__":
            continue
        value = function.__globals__[name]
        if _immutable_callable_value(value) or isinstance(
            value, (types.ModuleType, type, types.FunctionType)
        ):
            continue
        return False
    return True


def _threshold_decision(score: float, threshold: float, operator: str) -> bool:
    if operator == ">":
        return score > threshold
    if operator == ">=":
        return score >= threshold
    if operator == "<":
        return score < threshold
    return score <= threshold


class DetectorQueryBudgetExceeded(ResourceBudgetExceeded):
    """The independent detector-query allowance was exhausted."""

    def __init__(self) -> None:
        super().__init__("detector-query budget exhausted")


class DetectorSessionScopeError(RuntimeError):
    """A session was reused from a different request context."""

    def __init__(self) -> None:
        super().__init__("detector session cannot cross request boundaries")


class DetectorPolicyDriftError(RuntimeError):
    """A detector contract changed after the session first bound it."""

    def __init__(self) -> None:
        super().__init__("detector policy changed during one scoring session")


@dataclass(frozen=True, repr=False)
class SignalSpan:
    """Content-free detector attribution for one half-open character span."""

    start: int
    end: int
    score: Optional[float] = None
    p_value: Optional[float] = None
    threshold: Optional[float] = None

    def __post_init__(self) -> None:
        if type(self.start) is not int or type(self.end) is not int:
            raise TypeError("signal span offsets must be integers")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("signal span must be a non-empty half-open interval")
        for value in (self.score, self.threshold):
            if value is not None and _finite(value) is None:
                raise ValueError("signal span scores must be finite")
        if self.p_value is not None and _probability(self.p_value) is None:
            raise ValueError("signal span p_value must be between zero and one")

    def __repr__(self) -> str:
        return "<dewatermark signal span; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values = {
            "start": self.start,
            "end": self.end,
            "score": self.score,
            "p_value": self.p_value,
            "threshold": self.threshold,
        }
        return {key: value for key, value in values.items() if value is not None}


def _signal_spans(evidence: DetectionEvidence) -> tuple[SignalSpan, ...]:
    raw = evidence.details.get("localization")
    if type(raw) not in (list, tuple):
        return ()
    spans: list[SignalSpan] = []
    for item in cast(Sequence[Any], raw):
        if type(item) is not dict:
            continue
        start = item.get("start")
        end = item.get("end")
        if (
            type(start) is not int
            or type(end) is not int
            or start < 0
            or end <= start
            or end > evidence.text_characters
        ):
            continue
        spans.append(
            SignalSpan(
                start=start,
                end=end,
                score=_finite(item.get("score")),
                p_value=_probability(item.get("p_value")),
                threshold=_finite(item.get("threshold")),
            )
        )
    return tuple(spans)


def _score_direction(evidence: DetectionEvidence) -> Optional[ScoreDirection]:
    declared = evidence.details.get("score_direction")
    if declared in ("higher", "lower"):
        return cast(ScoreDirection, declared)
    if evidence.score is None or evidence.threshold is None:
        return None
    if evidence.status == "detected":
        return "higher" if evidence.score >= evidence.threshold else "lower"
    if evidence.status == "not_detected":
        return "higher" if evidence.score < evidence.threshold else "lower"
    return None


def _detection_margin(
    evidence: DetectionEvidence, direction: Optional[ScoreDirection]
) -> Optional[float]:
    """Return a signed threshold margin: positive means the detected side."""
    if direction is None or evidence.score is None or evidence.threshold is None:
        return None
    if direction == "higher":
        return evidence.score - evidence.threshold
    return evidence.threshold - evidence.score


def _paired_contract_bound(before: "DetectorObservation", after: "DetectorObservation") -> bool:
    before_threshold = _finite(before.evidence.threshold)
    after_threshold = _finite(after.evidence.threshold)
    if (
        before.detector != after.detector
        or before.policy_sha256 != after.policy_sha256
        or before.evidence.detector != after.evidence.detector
        or type(before.evidence.scheme) is not str
        or not before.evidence.scheme
        or type(after.evidence.scheme) is not str
        or before.evidence.scheme != after.evidence.scheme
        or before_threshold is None
        or after_threshold is None
        or before_threshold != after_threshold
        or type(before.evidence.details) is not dict
        or type(after.evidence.details) is not dict
    ):
        return False
    configuration = before.evidence.details.get("configuration_sha256")
    direction = before.evidence.details.get("score_direction")
    operator = before.evidence.details.get("threshold_operator")
    before_score = _finite(before.evidence.score)
    after_score = _finite(after.evidence.score)
    threshold = before_threshold
    if (
        before_score is None
        or after_score is None
        or threshold is None
        or before.evidence.status != "detected"
        or after.evidence.status != "not_detected"
    ):
        return False
    if type(operator) is not str or operator not in {">", ">=", "<", "<="}:
        return False
    before_positive = _threshold_decision(before_score, threshold, operator)
    after_positive = _threshold_decision(after_score, threshold, operator)
    return bool(
        type(configuration) is str
        and _SHA256.fullmatch(configuration)
        and type(direction) is str
        and direction in {"higher", "lower"}
        and (operator in {">", ">="}) == (direction == "higher")
        and after.evidence.details.get("configuration_sha256") == configuration
        and after.evidence.details.get("score_direction") == direction
        and after.evidence.details.get("threshold_operator") == operator
        and before_positive is True
        and after_positive is False
    )


def _capability_contract_bound(capability: CapabilityManifest) -> bool:
    configuration = capability.metadata.get("configuration_sha256")
    threshold = _finite(capability.metadata.get("threshold"))
    direction = capability.metadata.get("score_direction")
    operator = capability.metadata.get("threshold_operator")
    return bool(
        type(configuration) is str
        and _SHA256.fullmatch(configuration)
        and threshold is not None
        and type(direction) is str
        and direction in {"higher", "lower"}
        and type(operator) is str
        and operator in {">", ">=", "<", "<="}
        and (operator in {">", ">="}) == (direction == "higher")
    )


@dataclass(frozen=True, repr=False)
class DetectorObservation:
    """A normalized detector result with cache and decision metadata."""

    detector: str
    role: DetectorRole
    text_sha256: str
    policy_sha256: str
    evidence: DetectionEvidence
    query_index: int
    cached: bool = False
    score_direction: Optional[ScoreDirection] = None
    p_value: Optional[float] = None
    detection_margin: Optional[float] = None
    localization: tuple[SignalSpan, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.detector) is not str
            or _identifier(self.detector, "invalid-detector") != self.detector
            or self.role not in {"primary", "verifier"}
            or type(self.text_sha256) is not str
            or _SHA256.fullmatch(self.text_sha256) is None
            or type(self.policy_sha256) is not str
            or _SHA256.fullmatch(self.policy_sha256) is None
            or type(self.evidence) is not DetectionEvidence
            or self.evidence.detector != self.detector
            or type(self.evidence.details) is not dict
            or type(self.query_index) is not int
            or self.query_index < 1
            or type(self.cached) is not bool
            or self.score_direction not in {None, "higher", "lower"}
            or (self.p_value is not None and _probability(self.p_value) is None)
            or (self.detection_margin is not None and _finite(self.detection_margin) is None)
            or type(self.localization) is not tuple
            or any(type(span) is not SignalSpan for span in self.localization)
            or any(span.end > self.evidence.text_characters for span in self.localization)
        ):
            raise ValueError("detector observation is not internally consistent")
        expected_direction = _score_direction(self.evidence)
        if (
            self.score_direction != expected_direction
            or self.p_value != _probability(self.evidence.details.get("p_value"))
            or self.detection_margin != _detection_margin(self.evidence, expected_direction)
            or self.localization != _signal_spans(self.evidence)
        ):
            raise ValueError("detector observation contradicts its normalized evidence")

    def __repr__(self) -> str:
        return "<dewatermark detector observation; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "detector": self.detector,
            "role": self.role,
            "text_sha256": self.text_sha256,
            "policy_sha256": self.policy_sha256,
            "evidence": self.evidence.to_dict(),
            "query_index": self.query_index,
            "cached": self.cached,
            "score_direction": self.score_direction,
            "p_value": self.p_value,
            "detection_margin": self.detection_margin,
            "localization": [item.to_dict() for item in self.localization],
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, repr=False)
class VerifierObservation:
    """Paired evidence from one verifier that was not used for search scoring."""

    detector: str
    before: DetectorObservation
    after: DetectorObservation
    verification: VerificationEvidence

    def __post_init__(self) -> None:
        if (
            type(self.detector) is not str
            or type(self.before) is not DetectorObservation
            or type(self.after) is not DetectorObservation
            or type(self.verification) is not VerificationEvidence
            or self.before.role != "verifier"
            or self.after.role != "verifier"
            or self.before.detector != self.detector
            or self.after.detector != self.detector
            or self.verification.detector != self.detector
            or self.verification.before is not self.before.evidence
            or self.verification.after is not self.after.evidence
        ):
            raise ValueError("verifier observation is not internally consistent")

    def __repr__(self) -> str:
        return "<dewatermark verifier observation; content redacted>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "verification": self.verification.to_dict(),
        }


@dataclass(frozen=True, repr=False)
class SessionVerification:
    """Primary clearance plus all held-out verification conclusions."""

    status: SessionVerificationStatus
    primary_before: Optional[DetectorObservation]
    primary_after: Optional[DetectorObservation]
    verifiers: tuple[VerifierObservation, ...] = ()
    reason_code: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in {"verified", "residual", "not_verifiable", "failed"}:
            raise ValueError("detector session has an invalid status")
        if type(self.verifiers) is not tuple or any(
            type(item) is not VerifierObservation for item in self.verifiers
        ):
            raise ValueError("detector session verifiers must be exact verifier observations")
        if self.status != "verified":
            return
        if (
            type(self.primary_before) is not DetectorObservation
            or type(self.primary_after) is not DetectorObservation
            or self.primary_before.role != "primary"
            or self.primary_after.role != "primary"
            or self.primary_before.detector != self.primary_after.detector
            or self.primary_before.text_sha256 == self.primary_after.text_sha256
            or self.primary_before.evidence.status != "detected"
            or self.primary_after.evidence.status != "not_detected"
            or not _paired_contract_bound(self.primary_before, self.primary_after)
            or not self.verifiers
            or self.reason_code is not None
            or any(
                item.before.text_sha256 != self.primary_before.text_sha256
                or item.after.text_sha256 != self.primary_after.text_sha256
                or item.before.evidence.status != "detected"
                or item.after.evidence.status != "not_detected"
                or item.verification.status != "verified_cleared"
                or not _paired_contract_bound(item.before, item.after)
                for item in self.verifiers
            )
            or len({item.detector for item in self.verifiers}) != len(self.verifiers)
            or self.primary_before.detector in {item.detector for item in self.verifiers}
        ):
            raise ValueError("verified detector session requires complete clearance evidence")

    def __repr__(self) -> str:
        return "<dewatermark session verification; content redacted>"

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def to_dict(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            "status": self.status,
            "primary_before": (
                self.primary_before.to_dict() if self.primary_before is not None else None
            ),
            "primary_after": (
                self.primary_after.to_dict() if self.primary_after is not None else None
            ),
            "verifiers": [item.to_dict() for item in self.verifiers],
            "reason_code": self.reason_code,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(repr=False)
class _Target:
    spec: Any = field(repr=False)
    role: DetectorRole
    index: int
    fallback_name: str
    instance: Any = field(default=None, repr=False)
    resolved: bool = False


class DetectorSession:
    """Bounded detector access for one mitigation request.

    Cache hits do not consume queries. A batch either fits in the remaining
    allowance or fails before any new detector is invoked. Sessions bind to the
    first active :class:`RequestContext` they encounter; using one from a second
    request is rejected.
    """

    def __init__(
        self,
        primary_detector: str | Any,
        *,
        verifier_detectors: Sequence[str | Any] = (),
        config: Optional[DewatermarkConfig] = None,
        max_queries: Optional[int] = None,
    ) -> None:
        if primary_detector is None:
            raise ValueError("primary_detector is required")
        if type(verifier_detectors) not in (list, tuple):
            raise TypeError("verifier_detectors must be a list or tuple")
        self.config = resolve(config)
        if len(verifier_detectors) > self.config.max_batch_items:
            raise ValueError("verifier_detectors exceeds max_batch_items")
        requested_queries = self.config.max_detector_queries if max_queries is None else max_queries
        if type(requested_queries) is not int or not 1 <= requested_queries <= 100_000:
            raise ValueError("max_queries must be between 1 and 100000")
        self.max_queries = min(requested_queries, self.config.max_detector_queries)
        self._targets = (
            self._make_target(primary_detector, "primary", 0),
            *(
                self._make_target(detector, "verifier", index + 1)
                for index, detector in enumerate(verifier_detectors)
            ),
        )
        self._cache: dict[tuple[int, str, str], DetectorObservation] = {}
        self._queries_used = 0
        self._lock = RLock()
        self._bound_context: Optional[RequestContext] = None
        self._owns_context = False
        self._verification_manifests: Optional[tuple[str, ...]] = None
        self._bound_policies: dict[int, str] = {}

    @staticmethod
    def _make_target(spec: Any, role: DetectorRole, index: int) -> _Target:
        fallback = _identifier(spec, f"{role}-detector-{index}")
        if not isinstance(spec, str):
            fallback = capability_of(spec, fallback).identifier
        return _Target(spec=spec, role=role, index=index, fallback_name=fallback)

    def __repr__(self) -> str:
        return "<dewatermark detector session; content and extensions redacted>"

    @property
    def queries_used(self) -> int:
        with self._lock:
            return self._queries_used

    @property
    def queries_remaining(self) -> int:
        with self._lock:
            return max(0, self.max_queries - self._queries_used)

    @property
    def verifier_count(self) -> int:
        return len(self._targets) - 1

    def primary_capability(self) -> CapabilityManifest:
        """Return the bound primary capability without sending detector text."""
        with self._scope(), self._lock:
            target = self._targets[0]
            return capability_of(self._resolve_target(target), target.fallback_name)

    def ledger(self) -> dict[str, int]:
        with self._lock:
            return {
                "detector_queries_used": self._queries_used,
                "detector_queries_limit": self.max_queries,
                "detector_queries_remaining": max(0, self.max_queries - self._queries_used),
                "detector_cache_entries": len(self._cache),
            }

    @contextmanager
    def _scope(self) -> Iterator[None]:
        active = current_request_context()
        with self._lock:
            if self._bound_context is None:
                self._bound_context = active or RequestContext.from_config(self.config)
                self._owns_context = active is None
            bound = self._bound_context
            if active is not None and active is not bound:
                raise DetectorSessionScopeError
            if active is None and not self._owns_context:
                raise DetectorSessionScopeError
        assert bound is not None
        if active is bound:
            bound.checkpoint()
            yield
        else:
            with request_scope(bound):
                bound.checkpoint()
                yield

    def _resolve_target(self, target: _Target) -> Any:
        if target.resolved:
            return target.instance
        if isinstance(target.spec, str):
            instance, name = resolve_detector(target.spec, self.config)
            target.instance = instance
            if name is not None:
                target.fallback_name = _identifier(name, target.fallback_name)
        else:
            target.instance = target.spec
        target.resolved = True
        return target.instance

    def _target_identity(
        self, target: _Target, capability: Optional[CapabilityManifest] = None
    ) -> tuple[str, str, str, str, int, Optional[str], str]:
        instance = self._resolve_target(target)
        declared = capability or capability_of(instance, target.fallback_name)
        configuration = declared.metadata.get("configuration_sha256")
        configuration_key = (
            configuration
            if type(configuration) is str and _PUBLIC_IDENTIFIER.fullmatch(configuration)
            else manifest_sha256(declared)
        )
        identity = extension_identity(instance, "detector")
        implementation = str(identity["implementation_sha256"])
        code_identity = implementation
        from .command_detector import CommandDetector, _contract_from_manifest

        command_identity_error: Optional[str] = None
        if isinstance(instance, CommandDetector):
            if type(instance) is not CommandDetector:
                # A subclass can change decisions outside the pinned command.
                # Do not let cosmetic wrapper classes manufacture independence.
                command_identity_error = "command_detector_identity_unverifiable"
            elif type(instance._contract.implementation_sha256) is str and _SHA256.fullmatch(
                instance._contract.implementation_sha256
            ):
                implementation = instance._contract.implementation_sha256
            else:
                command_identity_error = "command_detector_implementation_unbound"
            try:
                if object.__getattribute__(instance, "_contract") != _contract_from_manifest(
                    declared
                ):
                    command_identity_error = "command_detector_identity_unverifiable"
            except Exception:
                command_identity_error = "command_detector_identity_unverifiable"
            command_code = command_code_identity_sha256(
                object.__getattribute__(instance, "_command")
            )
            if type(command_code) is str and _SHA256.fullmatch(command_code):
                code_identity = command_code
            else:
                command_identity_error = "command_detector_identity_unverifiable"
        else:
            try:
                state = object.__getattribute__(instance, "__dict__")
            except Exception:
                state = None
            kind = type(instance)
            try:
                lineage = type.__getattribute__(kind, "__mro__")
                custom_dispatch = any(
                    base is not object
                    and "__getattribute__" in type.__getattribute__(base, "__dict__")
                    for base in lineage
                )
                detect_descriptor = inspect.getattr_static(kind, "detect")
            except Exception:
                custom_dispatch = True
                detect_descriptor = None
            if (
                type(state) is dict
                and any(name in state for name in ("detect", "available"))
                or custom_dispatch
                or not _verification_callable_state_safe(detect_descriptor)
            ):
                command_identity_error = "held_out_verifier_identity_unverifiable"
        return (
            declared.identifier,
            configuration_key,
            implementation,
            str(identity["static_state_sha256"]),
            id(instance),
            command_identity_error,
            code_identity,
        )

    def _verification_preflight(self) -> Optional[str]:
        """Bind all verification targets before any detector receives text."""
        self._verification_manifests = None
        if not self._targets[1:]:
            return "held_out_verifier_required"
        try:
            with self._scope(), self._lock:
                instances = tuple(self._resolve_target(target) for target in self._targets)
                capabilities = tuple(
                    capability_of(instance, target.fallback_name)
                    for instance, target in zip(instances, self._targets)
                )
                identities = [
                    self._target_identity(target, capability)
                    for target, capability in zip(self._targets, capabilities)
                ]
        except ResourceBudgetExceeded:
            raise
        except Exception:
            return "held_out_verifier_identity_unverifiable"

        common_schemes = set(capabilities[0].schemes)
        for capability in capabilities[1:]:
            common_schemes.intersection_update(capability.schemes)
        if not common_schemes:
            return "held_out_verifier_target_mismatch"

        from .command_detector import CommandDetector

        # Report command-wrapper identity failures before the general decision
        # contract check so subclasses cannot disguise why verification stopped.
        command_identity_errors = [identity[5] for identity in identities if identity[5]]
        if command_identity_errors:
            return command_identity_errors[0]

        if any(
            not (
                type(instance) is CommandDetector
                and instance._contract.threshold_operator_explicit
                or not isinstance(instance, CommandDetector)
                and _capability_contract_bound(capability)
            )
            for instance, capability in zip(instances, capabilities)
        ):
            return "detector_decision_contract_unbound"

        targets = tuple(
            (
                instance._contract.watermark_target_sha256
                if type(instance) is CommandDetector
                else capability.metadata.get("watermark_target_sha256")
            )
            for instance, capability in zip(instances, capabilities)
        )
        if any(type(value) is not str or _SHA256.fullmatch(value) is None for value in targets):
            return "watermark_target_unbound"
        if len(set(targets)) != 1:
            return "held_out_verifier_target_mismatch"

        # The Python wrapper is the same implementation for every command
        # detector. Verification therefore needs a public commitment to the
        # complete external implementation, while ordinary detection remains
        # compatible with older manifests that do not publish one.
        object_ids = [identity[4] for identity in identities]
        declared = [(identity[0], identity[1]) for identity in identities]
        implementations = [identity[2] for identity in identities]
        static_states = [identity[3] for identity in identities]
        code_identities = [identity[6] for identity in identities]
        if (
            len(set(object_ids)) != len(object_ids)
            or len(set(declared)) != len(declared)
            or len(set(implementations)) != len(implementations)
            or len(set(static_states)) != len(static_states)
            or len(set(code_identities)) != len(code_identities)
        ):
            return "held_out_verifier_not_distinct"

        if any(
            not capability.calibrated or not capability.independent
            for capability in capabilities[1:]
        ):
            return "held_out_verifier_not_qualified"
        manifests = tuple(
            self._target_policy_sha256(target, capability)
            for target, capability in zip(self._targets, capabilities)
        )
        if any(
            target.index in self._bound_policies and self._bound_policies[target.index] != manifest
            for target, manifest in zip(self._targets, manifests)
        ):
            return "detector_policy_drift"
        self._verification_manifests = manifests
        return None

    def _verification_policy_drifted(self) -> bool:
        """Recheck static detector contracts after calls and before acceptance."""
        expected = self._verification_manifests
        if expected is None:
            return True
        try:
            with self._scope(), self._lock:
                current = tuple(
                    self._target_policy_sha256(target, capability)
                    for target in self._targets
                    for capability in (
                        capability_of(self._resolve_target(target), target.fallback_name),
                    )
                )
        except ResourceBudgetExceeded:
            raise
        except Exception:
            return True
        return current != expected

    def _target_policy_sha256(
        self, target: _Target, capability: Optional[CapabilityManifest] = None
    ) -> str:
        """Bind cache evidence to both the manifest and executable detector code."""
        instance = self._resolve_target(target)
        declared = capability or capability_of(instance, target.fallback_name)
        policy = manifest_sha256(declared)
        from .command_detector import CommandDetector

        behavior_identity = implementation_sha256(instance)
        if isinstance(instance, CommandDetector):
            code_identity = command_code_identity_sha256(
                object.__getattribute__(instance, "_command")
            )
            if type(code_identity) is str and _SHA256.fullmatch(code_identity):
                behavior_identity = _digest(f"{code_identity}\0{implementation_sha256(instance)}")
        return _digest(f"{policy}\0{behavior_identity}")

    def _score_policy_sha256(self, target: _Target) -> str:
        """Resolve one scoring policy without reflecting resolution failures."""
        try:
            capability = capability_of(self._resolve_target(target), target.fallback_name)
            return self._target_policy_sha256(target, capability)
        except ResourceBudgetExceeded:
            raise
        except Exception:
            return hashlib.sha256(
                f"unresolved-detector-policy/{target.index}/{target.fallback_name}".encode("utf-8")
            ).hexdigest()

    def _observe(
        self, target: _Target, text: str, query_index: int, policy_sha256: str
    ) -> DetectorObservation:
        try:
            instance = self._resolve_target(target)
            if instance is None:
                raise RuntimeError("detector resolution failed")
            evidence = run_detector(
                instance,
                text,
                fallback_name=target.fallback_name,
                config=self.config,
            )
        except PermissionError:
            evidence = DetectionEvidence(
                detector=target.fallback_name,
                status="configuration_mismatch",
                text_characters=len(text),
                reason="detector requirements are not explicitly permitted",
            )
        except ResourceBudgetExceeded:
            raise
        except Exception:
            evidence = DetectionEvidence(
                detector=target.fallback_name,
                status="detector_error",
                text_characters=len(text),
                reason="detector failed; details were redacted",
            )
        direction = _score_direction(evidence)
        return DetectorObservation(
            detector=_identifier(evidence.detector, target.fallback_name),
            role=target.role,
            text_sha256=_digest(text),
            policy_sha256=policy_sha256,
            evidence=evidence,
            query_index=query_index,
            score_direction=direction,
            p_value=_probability(evidence.details.get("p_value")),
            detection_margin=_detection_margin(evidence, direction),
            localization=_signal_spans(evidence),
        )

    def _score_requests(
        self, requests: Sequence[tuple[_Target, str]]
    ) -> tuple[DetectorObservation, ...]:
        if not requests:
            return ()
        for _target, text in requests:
            if type(text) is not str or not text:
                raise ValueError("detector text must be a non-empty string")
            if len(text) > self.config.max_input_chars:
                raise ValueError("detector text exceeds max_input_chars")
        with self._scope():
            # Serialize one session. Besides making cache misses atomic, this
            # keeps query order and therefore traces deterministic.
            with self._lock:
                # Hash executable/policy material once per detector, not once
                # per text. This bounds identity I/O before query preflight.
                targets_by_index: dict[int, _Target] = {}
                for target, _text in requests:
                    targets_by_index.setdefault(target.index, target)
                policies_by_index: dict[int, str] = {}
                for index, target in targets_by_index.items():
                    policy = self._score_policy_sha256(target)
                    bound_policy = self._bound_policies.get(target.index)
                    if bound_policy is None:
                        self._bound_policies[target.index] = policy
                    elif bound_policy != policy:
                        raise DetectorPolicyDriftError
                    policies_by_index[index] = policy
                    active = current_request_context()
                    if active is not None:
                        active.checkpoint()
                policies = [policies_by_index[target.index] for target, _text in requests]
                keys = [
                    (target.index, policy, _digest(text))
                    for (target, text), policy in zip(requests, policies)
                ]
                missing: list[tuple[tuple[int, str, str], _Target, str]] = []
                seen_missing: set[tuple[int, str, str]] = set()
                for key, (target, text) in zip(keys, requests):
                    if key not in self._cache and key not in seen_missing:
                        missing.append((key, target, text))
                        seen_missing.add(key)
                if self._queries_used + len(missing) > self.max_queries:
                    raise DetectorQueryBudgetExceeded
                for key, target, text in missing:
                    self._queries_used += 1
                    observation = self._observe(target, text, self._queries_used, key[1])
                    self._cache[key] = observation

                for index, target in targets_by_index.items():
                    if self._score_policy_sha256(target) != policies_by_index[index]:
                        raise DetectorPolicyDriftError
                    active = current_request_context()
                    if active is not None:
                        active.checkpoint()

                output: list[DetectorObservation] = []
                emitted: set[tuple[int, str, str]] = set()
                missing_keys = {item[0] for item in missing}
                for key in keys:
                    observation = self._cache[key]
                    was_cached = key not in missing_keys or key in emitted
                    output.append(replace(observation, cached=was_cached))
                    emitted.add(key)
                return tuple(output)

    def score(self, text: str) -> DetectorObservation:
        """Score text with the primary detector."""
        return self._score_requests(((self._targets[0], text),))[0]

    def score_many(self, texts: Sequence[str]) -> tuple[DetectorObservation, ...]:
        """Score an ordered batch with atomic budget preflight and digest caching."""
        if type(texts) not in (list, tuple):
            raise TypeError("texts must be a list or tuple")
        if len(texts) > self.config.max_batch_items:
            raise ValueError("detector batch exceeds max_batch_items")
        return self._score_requests(tuple((self._targets[0], text) for text in texts))

    def verify(self, source: str, candidate: str) -> SessionVerification:
        """Verify primary clearance and require every held-out verifier to clear."""
        if not source or not candidate:
            raise ValueError("source and candidate must be non-empty strings")
        # Two distinct observations are required for every target. If the
        # session-wide allowance cannot possibly hold them, fail before any
        # detector resolution or executable hashing.
        if 2 * len(self._targets) > self.max_queries:
            raise DetectorQueryBudgetExceeded
        preflight_error = self._verification_preflight()
        if preflight_error is not None:
            return SessionVerification(
                status="not_verifiable",
                primary_before=None,
                primary_after=None,
                reason_code=preflight_error,
            )
        requests: list[tuple[_Target, str]] = [
            (self._targets[0], source),
            (self._targets[0], candidate),
        ]
        for target in self._targets[1:]:
            requests.extend(((target, source), (target, candidate)))
        try:
            observations = self._score_requests(requests)
        except DetectorPolicyDriftError:
            return SessionVerification(
                status="not_verifiable",
                primary_before=None,
                primary_after=None,
                reason_code="detector_policy_drift",
            )
        primary_before, primary_after = observations[:2]
        if self._verification_policy_drifted():
            return SessionVerification(
                status="not_verifiable",
                primary_before=primary_before,
                primary_after=primary_after,
                reason_code="held_out_verifier_policy_drift",
            )
        if primary_before.evidence.status != "detected":
            return SessionVerification(
                status="not_verifiable",
                primary_before=primary_before,
                primary_after=primary_after,
                reason_code="primary_source_not_detected",
            )
        if primary_after.evidence.status == "detected":
            return SessionVerification(
                status="residual",
                primary_before=primary_before,
                primary_after=primary_after,
                reason_code="primary_residual",
            )
        if primary_after.evidence.status != "not_detected":
            status: SessionVerificationStatus = (
                "failed" if primary_after.evidence.status == "detector_error" else "not_verifiable"
            )
            return SessionVerification(
                status=status,
                primary_before=primary_before,
                primary_after=primary_after,
                reason_code="primary_inconclusive",
            )
        if not _paired_contract_bound(primary_before, primary_after):
            return SessionVerification(
                status="not_verifiable",
                primary_before=primary_before,
                primary_after=primary_after,
                reason_code="primary_decision_contract_mismatch",
            )
        verifier_results: list[VerifierObservation] = []
        offset = 2
        for target in self._targets[1:]:
            before, after = observations[offset : offset + 2]
            offset += 2
            instance = target.instance
            verification = evaluate_verification(
                before.evidence,
                after.evidence,
                instance,
                detector_name=before.detector,
            )
            verifier_results.append(
                VerifierObservation(
                    detector=before.detector,
                    before=before,
                    after=after,
                    verification=verification,
                )
            )

        statuses = {item.verification.status for item in verifier_results}
        final_status: SessionVerificationStatus
        if statuses == {"verified_cleared"}:
            final_status = "verified"
            reason = None
        elif "residual" in statuses:
            final_status = "residual"
            reason = "held_out_residual"
        elif "failed" in statuses:
            final_status = "failed"
            reason = "held_out_failed"
        else:
            final_status = "not_verifiable"
            reason = "held_out_inconclusive"
        return SessionVerification(
            status=final_status,
            primary_before=primary_before,
            primary_after=primary_after,
            verifiers=tuple(verifier_results),
            reason_code=reason,
        )
