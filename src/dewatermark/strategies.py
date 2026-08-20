"""Adapters that turn registered rewrite providers into search strategies.

Provider discovery is explicit: :func:`registered_strategy` may import a
trusted entry-point plugin because the caller has asked to execute it.  The
provider itself is constructed lazily, inside the optimizer's request scope,
so its declared network/model work crosses the shared accounting boundary.
"""

from __future__ import annotations

import hashlib
import heapq
import inspect
import itertools
import json
import re
from typing import Any, Optional, Sequence

from .config import DewatermarkConfig, resolve
from .detector_session import SignalSpan
from .extension_safety import manifests_match, safe_extension_config, static_capability
from .models import CapabilityManifest
from .optimizer import StrategyContext
from .providers import get_provider, provider_manifest

_WORD_PATTERN = r"[A-Za-z]+(?:['’][A-Za-z]+)?"
_MAX_SIGNAL_SPANS = 4096
_LEXICON_REVISION = "minimal-english-v1"
_LEXICAL_RULES = (
    ("additionally", "also"),
    ("approximately", "about"),
    ("commence", "begin"),
    ("demonstrate", "show"),
    ("demonstrates", "shows"),
    ("frequently", "often"),
    ("however", "yet"),
    ("nevertheless", "still"),
    ("numerous", "many"),
    ("perhaps", "maybe"),
    ("primarily", "mainly"),
    ("purchase", "buy"),
    ("regarding", "about"),
    ("therefore", "thus"),
    ("typically", "usually"),
    ("utilize", "use"),
    ("utilized", "used"),
    ("utilizes", "uses"),
)
_LEXICON_SHA256 = hashlib.sha256(
    json.dumps(_LEXICAL_RULES, ensure_ascii=True, separators=(",", ":")).encode("ascii")
).hexdigest()


def _bounded_integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _configuration_sha256(configuration: dict[str, Any]) -> str:
    encoded = json.dumps(
        configuration,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _replacement(word: str) -> Optional[str]:
    lowered = word.lower()
    replacement = next((right for left, right in _LEXICAL_RULES if left == lowered), None)
    if replacement is None:
        return None
    if word.islower():
        return replacement
    if word.isupper():
        return replacement.upper()
    if word.istitle():
        return replacement.capitalize()
    return None


def _span_rank(span: SignalSpan) -> tuple[float, float, int, int]:
    p_value = span.p_value if span.p_value is not None else 1.0
    if span.score is None:
        margin = 0.0
    elif span.threshold is None:
        margin = abs(span.score)
    else:
        margin = abs(span.score - span.threshold)
    return (p_value, -margin, span.start, span.end)


def _apply_edits(text: str, edits: Sequence[tuple[int, int, str]]) -> str:
    candidate = text
    for start, end, replacement in sorted(edits, key=lambda item: item[0], reverse=True):
        candidate = candidate[:start] + replacement + candidate[end:]
    return candidate


class ContextAwareMinimalEditStrategy:
    """Propose small lexical edits near detector-supplied signal spans.

    This strategy has no acceptance method. Its deterministic outputs remain
    untrusted candidates for the optimizer's central quality and verification
    pipeline.
    """

    def __init__(
        self,
        *,
        context_influence: int = 2,
        max_edits: int = 3,
        max_candidates: int = 24,
    ) -> None:
        self._context_influence = _bounded_integer(
            context_influence, "context_influence", minimum=0, maximum=64
        )
        self._max_edits = _bounded_integer(max_edits, "max_edits", minimum=1, maximum=16)
        self._max_candidates = _bounded_integer(
            max_candidates, "max_candidates", minimum=1, maximum=64
        )
        configuration = {
            "context_influence": self._context_influence,
            "lexicon_revision": _LEXICON_REVISION,
            "lexicon_sha256": _LEXICON_SHA256,
            "max_candidates": self._max_candidates,
            "max_edits": self._max_edits,
            "maximum_signal_spans": _MAX_SIGNAL_SPANS,
        }
        configuration_sha256 = _configuration_sha256(configuration)
        self.capability = CapabilityManifest(
            identifier=f"context-aware-minimal-edit-v1:{configuration_sha256}",
            kind="transformer",
            version="1",
            schemes=("detector-attribution",),
            description="Deterministic lexical candidates guided by content-free signal spans.",
            metadata={
                **configuration,
                "attribution_required": True,
                "candidate_only": True,
                "configuration_sha256": configuration_sha256,
                "deterministic": True,
                "resource_accounting": "none",
                "retains_text": False,
            },
        )

    def __repr__(self) -> str:
        return "<dewatermark context-aware minimal-edit strategy; text redacted>"

    def available(self) -> bool:
        return True

    def generate(self, text: str, *, context: StrategyContext, **options: Any) -> Sequence[str]:
        """Return bounded proposals ordered by edit count and signal proximity."""
        if type(text) is not str:
            raise TypeError("strategy text must be a string")
        if type(context) is not StrategyContext:
            raise TypeError("context must be a StrategyContext")
        if options:
            raise TypeError("context-aware strategy does not accept per-call options")
        if type(context.candidate_limit) is not int or context.candidate_limit <= 0:
            return ()
        spans = context.feedback.localization
        if not spans and context.round_index == 0:
            spans = context.source_localization
        if not spans:
            return ()

        words = tuple(re.finditer(_WORD_PATTERN, text))
        ordered_spans = sorted(
            enumerate(spans[:_MAX_SIGNAL_SPANS]),
            key=lambda item: (item[1].start, item[1].end, *_span_rank(item[1]), item[0]),
        )
        span_cursor = 0
        active_spans: list[tuple[tuple[float, float, int, int], int, SignalSpan]] = []
        signals_by_token: list[Optional[SignalSpan]] = [None] * len(words)
        for token_index, token in enumerate(words):
            while (
                span_cursor < len(ordered_spans)
                and ordered_spans[span_cursor][1].start < token.end()
            ):
                ordinal, span = ordered_spans[span_cursor]
                heapq.heappush(active_spans, (_span_rank(span), ordinal, span))
                span_cursor += 1
            while active_spans and active_spans[0][2].end <= token.start():
                heapq.heappop(active_spans)
            if active_spans:
                signals_by_token[token_index] = active_spans[0][2]
        if not any(span is not None for span in signals_by_token):
            return ()

        ranked_edits: list[tuple[tuple[Any, ...], tuple[int, int, str]]] = []
        for token_index, token in enumerate(words):
            replacement = _replacement(token.group(0))
            if replacement is None:
                continue
            nearby: list[tuple[int, int, SignalSpan]] = []
            for signal_index in range(
                max(0, token_index - self._context_influence),
                min(len(words), token_index + self._context_influence + 1),
            ):
                candidate_span = signals_by_token[signal_index]
                if candidate_span is not None:
                    nearby.append((abs(token_index - signal_index), signal_index, candidate_span))
            nearest = min(
                nearby,
                key=lambda item: (item[0], *_span_rank(item[2]), item[1]),
                default=None,
            )
            if nearest is None:
                continue
            distance, _nearest_index, nearest_span = nearest
            edit = (token.start(), token.end(), replacement)
            edit_characters = max(token.end() - token.start(), len(replacement))
            rank = (distance, *_span_rank(nearest_span), edit_characters, *edit)
            ranked_edits.append((rank, edit))
        if not ranked_edits:
            return ()
        ranked = tuple(edit for _rank, edit in sorted(ranked_edits))
        edit_limit = min(self._max_edits, len(ranked))
        candidate_limit = min(self._max_candidates, context.candidate_limit)
        candidates: list[str] = []
        seen = {text}

        # Put cumulative minimum-edit paths first so a small candidate limit can
        # still reach a detector threshold that requires more than one edit.
        for edit_count in range(1, edit_limit + 1):
            candidate = _apply_edits(text, ranked[:edit_count])
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
            if len(candidates) >= candidate_limit:
                return tuple(candidates)

        # Fill the remaining bounded allowance with stable alternative subsets.
        for edit_count in range(1, edit_limit + 1):
            for edits in itertools.combinations(ranked, edit_count):
                candidate = _apply_edits(text, edits)
                if candidate in seen:
                    continue
                seen.add(candidate)
                candidates.append(candidate)
                if len(candidates) >= candidate_limit:
                    return tuple(candidates)
        return tuple(candidates)


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


def context_aware_strategy(
    *,
    context_influence: int = 2,
    max_edits: int = 3,
    max_candidates: int = 24,
) -> ContextAwareMinimalEditStrategy:
    """Build the deterministic, signal-span-guided minimal-edit strategy."""
    return ContextAwareMinimalEditStrategy(
        context_influence=context_influence,
        max_edits=max_edits,
        max_candidates=max_candidates,
    )


__all__ = [
    "ContextAwareMinimalEditStrategy",
    "RegisteredProviderStrategy",
    "context_aware_strategy",
    "registered_strategy",
]
