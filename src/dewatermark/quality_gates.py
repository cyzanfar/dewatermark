"""Fail-closed, consent-bound learned quality-gate adapters.

This module deliberately contains no default model and performs no import,
network access, or model acquisition during discovery or construction. The
cached Transformers adapter uses ``local_files_only=True`` unconditionally.
Applications opt into each gate with :class:`~dewatermark.quality.QualityGateBinding`.
"""

from __future__ import annotations

import hashlib
import importlib.util
import math
import re
from dataclasses import dataclass
from threading import RLock
from typing import Any, Literal, Optional

from .extension_safety import implementation_sha256, manifests_match, static_capability
from .models import CapabilityManifest
from .quality import QualityGateDecision, QualityGateType, ScoreDirection
from .request_context import (
    ExtensionUsageRejected,
    begin_extension_usage,
    checkpoint,
    current_request_context,
    extension_resource_accounting,
    extension_usage_error,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PAIRWISE_TYPES = frozenset(
    {"atomic_claim_qa", "entity_linking", "citation_grounding", "task_contract"}
)
_ACCOUNTING = frozenset({"none", "model", "network"})


@dataclass(frozen=True)
class PairwiseAssessment:
    """Content-free output from an atomic-claim/entity/citation/task adapter."""

    score: Optional[float]
    checked_items: int


def _safe_identifier(value: str) -> str:
    if _IDENTIFIER.fullmatch(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]
    return f"adapter-sha256:{digest}"


def _number(value: Any, *, probability: bool = False) -> float:
    if type(value) not in (int, float):
        raise TypeError("quality adapter score must be a finite number")
    score = float(value)
    if not math.isfinite(score) or (probability and not 0.0 <= score <= 1.0):
        raise TypeError("quality adapter score is outside its valid range")
    return score


def _adapter_accounting(capability: CapabilityManifest) -> str:
    accounting = extension_resource_accounting(capability)
    if accounting not in _ACCOUNTING:
        raise ValueError("quality adapter resource_accounting must be none, model, or network")
    return accounting


def _accounting_error(
    accounting: str, before: tuple[Any, int, int]
) -> Optional[QualityGateDecision]:
    error = extension_usage_error(
        before,
        network_required=accounting == "network",
        resource_accounting=accounting,
    )
    return QualityGateDecision(status="error", reason_code=error) if error else None


def _derived_capability(
    adapter: Any,
    gate_type: QualityGateType,
    *,
    threshold: float,
    score_direction: ScoreDirection = "higher",
) -> tuple[CapabilityManifest, CapabilityManifest, str]:
    nested = static_capability(adapter, "quality_gate")
    adapter_implementation = implementation_sha256(adapter, instance_sensitive=True)
    accounting = _adapter_accounting(nested)
    identifier = _safe_identifier(f"{gate_type}:{nested.identifier}")
    capability = CapabilityManifest(
        identifier=identifier,
        kind="quality_gate",
        version=nested.version,
        description=f"Fail-closed {gate_type} quality gate backed by a declared adapter.",
        network_required=nested.network_required,
        model_download_possible=nested.model_download_possible,
        requires_secret=nested.requires_secret,
        calibrated=nested.calibrated,
        independent=nested.independent,
        metadata={
            "quality_gate_type": gate_type,
            "adapter_identifier": _safe_identifier(nested.identifier),
            "adapter_implementation_sha256": adapter_implementation,
            "resource_accounting": accounting,
            "score_direction": score_direction,
            "threshold": threshold,
        },
    )
    return capability, nested, accounting


class BidirectionalNLIGate:
    """Require entailment in both directions to catch additions and omissions.

    The adapter must expose a static ``quality_gate`` capability, a side-effect-
    free ``available()`` method, and
    ``entailment_probability(premise, hypothesis) -> float``. The two directional
    probabilities and their minimum are retained in the content-free receipt.
    """

    def __init__(self, adapter: Any, *, min_entailment: float = 0.80) -> None:
        threshold = _number(min_entailment, probability=True)
        capability, nested, accounting = _derived_capability(
            adapter, "bidirectional_nli", threshold=threshold
        )
        self.capability = capability
        self._adapter = adapter
        self._adapter_capability = nested
        self._adapter_implementation = implementation_sha256(adapter, instance_sensitive=True)
        self._accounting = accounting
        self._threshold = threshold

    def evaluate(self, source: str, candidate: str) -> QualityGateDecision:
        try:
            actual = static_capability(self._adapter, "quality_gate")
            if (
                not manifests_match(actual, self._adapter_capability)
                or implementation_sha256(self._adapter, instance_sensitive=True)
                != self._adapter_implementation
            ):
                return QualityGateDecision(status="error", reason_code="invalid_adapter_result")
            checkpoint()
            before, _ = begin_extension_usage(self._adapter_capability)
            available = self._adapter.available()
            if type(available) is not bool:
                return QualityGateDecision(status="error", reason_code="invalid_adapter_result")
            if not available:
                return QualityGateDecision(status="abstained", reason_code="adapter_unavailable")
            forward = _number(
                self._adapter.entailment_probability(source, candidate), probability=True
            )
            checkpoint()
            reverse = _number(
                self._adapter.entailment_probability(candidate, source), probability=True
            )
            checkpoint()
            accounting_error = _accounting_error(self._accounting, before)
            if accounting_error is not None:
                return accounting_error
            score = min(forward, reverse)
            passed = score >= self._threshold
            return QualityGateDecision(
                status="passed" if passed else "failed",
                score=score,
                source_entails_candidate=forward,
                candidate_entails_source=reverse,
                threshold=self._threshold,
                checked_items=2,
                reason_code="threshold_met" if passed else "threshold_not_met",
            )
        except ExtensionUsageRejected as exc:
            return QualityGateDecision(status="error", reason_code=exc.reason_code)
        except Exception:
            return QualityGateDecision(status="error", reason_code="adapter_error")


class PairwiseAdapterGate:
    """Strict adapter for claim-QA, entity, citation, and task-specific checks."""

    def __init__(
        self,
        adapter: Any,
        *,
        gate_type: Literal[
            "atomic_claim_qa", "entity_linking", "citation_grounding", "task_contract"
        ],
        threshold: float = 1.0,
        score_direction: ScoreDirection = "higher",
        minimum_checked_items: int = 1,
    ) -> None:
        if gate_type not in _PAIRWISE_TYPES:
            raise ValueError("unsupported pairwise quality gate type")
        if score_direction not in ("higher", "lower"):
            raise ValueError("score_direction must be higher or lower")
        if type(minimum_checked_items) is not int or minimum_checked_items < 1:
            raise ValueError("minimum_checked_items must be a positive integer")
        numeric_threshold = _number(threshold)
        capability, nested, accounting = _derived_capability(
            adapter,
            gate_type,
            threshold=numeric_threshold,
            score_direction=score_direction,
        )
        self.capability = capability
        self._adapter = adapter
        self._adapter_capability = nested
        self._adapter_implementation = implementation_sha256(adapter, instance_sensitive=True)
        self._accounting = accounting
        self._gate_type = gate_type
        self._threshold = numeric_threshold
        self._direction = score_direction
        self._minimum_checked_items = minimum_checked_items

    def evaluate(self, source: str, candidate: str) -> QualityGateDecision:
        try:
            actual = static_capability(self._adapter, "quality_gate")
            if (
                not manifests_match(actual, self._adapter_capability)
                or implementation_sha256(self._adapter, instance_sensitive=True)
                != self._adapter_implementation
            ):
                return QualityGateDecision(status="error", reason_code="invalid_adapter_result")
            checkpoint()
            before, _ = begin_extension_usage(self._adapter_capability)
            available = self._adapter.available()
            if type(available) is not bool:
                return QualityGateDecision(status="error", reason_code="invalid_adapter_result")
            if not available:
                return QualityGateDecision(status="abstained", reason_code="adapter_unavailable")
            assessment = self._adapter.assess(source, candidate)
            checkpoint()
            if type(assessment) is not PairwiseAssessment:
                return QualityGateDecision(status="error", reason_code="invalid_adapter_result")
            if type(assessment.checked_items) is not int or assessment.checked_items < 0:
                return QualityGateDecision(status="error", reason_code="invalid_adapter_result")
            if assessment.score is None or assessment.checked_items < self._minimum_checked_items:
                return QualityGateDecision(
                    status="abstained",
                    checked_items=assessment.checked_items,
                    reason_code="no_items_checked",
                )
            score = _number(assessment.score)
            accounting_error = _accounting_error(self._accounting, before)
            if accounting_error is not None:
                return accounting_error
            passed = (
                score >= self._threshold
                if self._direction == "higher"
                else score <= self._threshold
            )
            return QualityGateDecision(
                status="passed" if passed else "failed",
                score=score,
                threshold=self._threshold,
                score_direction=self._direction,
                checked_items=assessment.checked_items,
                reason_code="threshold_met" if passed else "threshold_not_met",
            )
        except ExtensionUsageRejected as exc:
            return QualityGateDecision(status="error", reason_code=exc.reason_code)
        except Exception:
            return QualityGateDecision(status="error", reason_code="adapter_error")


class AtomicClaimQAGate(PairwiseAdapterGate):
    def __init__(
        self, adapter: Any, *, threshold: float = 1.0, minimum_checked_items: int = 1
    ) -> None:
        super().__init__(
            adapter,
            gate_type="atomic_claim_qa",
            threshold=threshold,
            minimum_checked_items=minimum_checked_items,
        )


class EntityLinkingGate(PairwiseAdapterGate):
    def __init__(
        self, adapter: Any, *, threshold: float = 1.0, minimum_checked_items: int = 1
    ) -> None:
        super().__init__(
            adapter,
            gate_type="entity_linking",
            threshold=threshold,
            minimum_checked_items=minimum_checked_items,
        )


class CitationGroundingGate(PairwiseAdapterGate):
    def __init__(
        self, adapter: Any, *, threshold: float = 1.0, minimum_checked_items: int = 1
    ) -> None:
        super().__init__(
            adapter,
            gate_type="citation_grounding",
            threshold=threshold,
            minimum_checked_items=minimum_checked_items,
        )


class TaskContractGate(PairwiseAdapterGate):
    def __init__(
        self,
        adapter: Any,
        *,
        threshold: float = 1.0,
        score_direction: ScoreDirection = "higher",
        minimum_checked_items: int = 1,
    ) -> None:
        super().__init__(
            adapter,
            gate_type="task_contract",
            threshold=threshold,
            score_direction=score_direction,
            minimum_checked_items=minimum_checked_items,
        )


class CachedTransformersNLIAdapter:
    """Optional local NLI adapter that can never download a model.

    ``transformers`` and ``torch`` are imported only during evaluation. Both
    tokenizer and model loads always set ``local_files_only=True``. Cache the
    reviewed model separately before constructing this adapter.
    """

    def __init__(self, model: str, *, max_length: int = 512) -> None:
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty local path or cached identifier")
        if type(max_length) is not int or not 32 <= max_length <= 8192:
            raise ValueError("max_length must be between 32 and 8192")
        model_digest = hashlib.sha256(model.encode("utf-8", "replace")).hexdigest()
        self.capability = CapabilityManifest(
            identifier=f"cached-transformers-nli:{model_digest[:24]}",
            kind="quality_gate",
            description="Cached-only Transformers sequence-classification NLI adapter.",
            network_required=False,
            model_download_possible=False,
            metadata={
                "quality_gate_type": "bidirectional_nli",
                "resource_accounting": "model",
                "model_sha256": model_digest,
                "local_files_only": True,
            },
        )
        self._model_name = model
        self._max_length = max_length
        self._tokenizer: Any = None
        self._model: Any = None
        self._entailment_index: Optional[int] = None
        self._lock = RLock()

    def available(self) -> bool:
        """Check dependencies without importing them or touching model storage."""
        return (
            importlib.util.find_spec("torch") is not None
            and importlib.util.find_spec("transformers") is not None
        )

    def _load(self) -> tuple[Any, Any, int]:
        with self._lock:
            if self._tokenizer is None or self._model is None or self._entailment_index is None:
                checkpoint()
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                tokenizer = AutoTokenizer.from_pretrained(
                    self._model_name,
                    local_files_only=True,
                )
                model = AutoModelForSequenceClassification.from_pretrained(
                    self._model_name,
                    local_files_only=True,
                )
                label2id = getattr(model.config, "label2id", {}) or {}
                entailment_index = next(
                    (
                        int(index)
                        for label, index in label2id.items()
                        if "entail" in str(label).lower()
                    ),
                    None,
                )
                if entailment_index is None:
                    id2label = getattr(model.config, "id2label", {}) or {}
                    entailment_index = next(
                        (
                            int(index)
                            for index, label in id2label.items()
                            if "entail" in str(label).lower()
                        ),
                        None,
                    )
                if entailment_index is None:
                    raise ValueError("model configuration has no named entailment label")
                model.eval()
                self._tokenizer = tokenizer
                self._model = model
                self._entailment_index = entailment_index
            return self._tokenizer, self._model, self._entailment_index

    def entailment_probability(self, premise: str, hypothesis: str) -> float:
        context = current_request_context()
        if context is None:
            raise RuntimeError("a request context is required for model accounting")
        context.record_model_access(
            self._model_name,
            cached=True,
            download_allowed=False,
        )
        tokenizer, model, entailment_index = self._load()
        checkpoint()
        import torch

        encoded = tokenizer(
            premise,
            hypothesis,
            return_tensors="pt",
            truncation=True,
            max_length=self._max_length + 1,
        )
        input_ids = encoded.get("input_ids")
        if input_ids is None or int(input_ids.shape[-1]) > self._max_length:
            raise ValueError("NLI input exceeds the reviewed maximum; refusing truncated scoring")
        with torch.inference_mode():
            logits = model(**encoded).logits[0]
            probability = torch.softmax(logits, dim=-1)[entailment_index].item()
        checkpoint()
        return float(probability)


def quality_gate_conformance(gate: Any) -> dict[str, Any]:
    """Inspect a gate without invoking it, importing dependencies, or reading text."""
    capability = static_capability(gate, "quality_gate")
    kind = type(gate)
    namespace = type.__getattribute__(kind, "__dict__")
    bases = type.__getattribute__(kind, "__mro__")
    has_evaluate = any("evaluate" in type.__getattribute__(base, "__dict__") for base in bases)
    return {
        "conformant": has_evaluate,
        "identifier": _safe_identifier(capability.identifier),
        "version": capability.version,
        "network_required": capability.network_required,
        "model_download_possible": capability.model_download_possible,
        "requires_secret": capability.requires_secret,
        "quality_gate_type": capability.metadata.get("quality_gate_type", "external"),
        "implementation_class": "<redacted>",
        "implementation_sha256": implementation_sha256(gate),
        "declares_instance_state": bool(namespace.get("__dict__")),
    }
