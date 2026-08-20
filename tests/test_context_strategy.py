import json
import re
import sys

import pytest

from dewatermark.command_detector import CommandDetector, command_detector_manifest
from dewatermark.config import DewatermarkConfig
from dewatermark.detector_session import SignalSpan
from dewatermark.extension_safety import extension_identity
from dewatermark.models import CapabilityManifest
from dewatermark.optimizer import DetectorFeedback, SearchLimits, StrategyContext, mitigate
from dewatermark.strategies import ContextAwareMinimalEditStrategy, context_aware_strategy

_TARGET_SHA256 = "e" * 64
_PRIMARY_CONFIGURATION_SHA256 = "a" * 64


def _context(
    *spans: SignalSpan,
    candidate_limit: int = 12,
    round_index: int = 0,
    source_spans: tuple[SignalSpan, ...] = (),
) -> StrategyContext:
    return StrategyContext(
        round_index=round_index,
        invocation_index=1,
        random_seed=7,
        candidate_limit=candidate_limit,
        feedback=DetectorFeedback(
            detector="context-fixture",
            status="detected",
            score=2.0,
            threshold=2.0,
            p_value=0.01,
            detection_margin=0.0,
            localization=tuple(spans),
        ),
        source_localization=source_spans,
    )


def test_context_aware_strategy_is_deterministic_bounded_and_span_guided():
    source = "However signal prose remains clear, and additionally marker prose stays concise."
    signal = source.index("signal")
    marker = source.index("marker")
    context = _context(
        SignalSpan(signal, signal + len("signal"), score=3.0, p_value=0.01, threshold=2.0),
        SignalSpan(marker, marker + len("marker"), score=2.5, p_value=0.02, threshold=2.0),
        candidate_limit=2,
    )
    strategy = context_aware_strategy(context_influence=1, max_edits=2, max_candidates=8)

    first = strategy.generate(source, context=context)
    second = strategy.generate(source, context=context)

    assert first == second
    assert first == (
        source.replace("However", "Yet", 1),
        source.replace("However", "Yet", 1).replace("additionally", "also", 1),
    )
    assert len(first) == context.candidate_limit
    assert source not in first
    assert strategy.capability.metadata["candidate_only"] is True
    assert strategy.capability.metadata["retains_text"] is False
    assert not hasattr(strategy, "accept")
    assert not hasattr(strategy, "verify")
    assert not hasattr(strategy, "transform")


def test_context_influence_and_round_scoping_prevent_unguided_edits():
    source = "However signal prose remains clear."
    start = source.index("signal")
    span = SignalSpan(start, start + len("signal"), score=2.0)

    exact_only = context_aware_strategy(context_influence=0)
    assert exact_only.generate(source, context=_context(span)) == ()

    adjacent = context_aware_strategy(context_influence=1)
    assert adjacent.generate(source, context=_context(span)) == (
        source.replace("However", "Yet", 1),
    )

    # Source offsets are allowed only for the first round; later rounds require
    # fresh detector feedback because prior edits can invalidate old offsets.
    stale_context = _context(round_index=1, source_spans=(span,))
    assert adjacent.generate(source, context=stale_context) == ()


def test_context_strategy_configuration_is_publicly_bound_and_validated():
    left = ContextAwareMinimalEditStrategy(context_influence=1, max_edits=2)
    same = ContextAwareMinimalEditStrategy(context_influence=1, max_edits=2)
    right = ContextAwareMinimalEditStrategy(context_influence=2, max_edits=2)

    assert left.capability.identifier == same.capability.identifier
    assert (
        left.capability.metadata["configuration_sha256"]
        == same.capability.metadata["configuration_sha256"]
    )
    assert left.capability.identifier != right.capability.identifier
    assert (
        left.capability.metadata["configuration_sha256"]
        != right.capability.metadata["configuration_sha256"]
    )
    left_identity = extension_identity(left, "transformer")
    same_identity = extension_identity(same, "transformer")
    assert left_identity["capability_sha256"] == same_identity["capability_sha256"]
    assert left_identity["implementation_sha256"] == same_identity["implementation_sha256"]
    assert left_identity["static_state_sha256"] == same_identity["static_state_sha256"]
    assert "private" not in repr(left)

    for kwargs in (
        {"context_influence": True},
        {"context_influence": 65},
        {"max_edits": 0},
        {"max_candidates": 65},
    ):
        with pytest.raises((TypeError, ValueError)):
            ContextAwareMinimalEditStrategy(**kwargs)

    source = "However signal prose remains clear."
    start = source.index("signal")
    with pytest.raises(TypeError, match="per-call options"):
        left.generate(source, context=_context(SignalSpan(start, start + 6)), override=True)


class IndependentHoweverVerifier:
    capability = CapabilityManifest(
        identifier="context-aware-heldout",
        kind="detector",
        schemes=("context-aware-fixture",),
        calibrated=True,
        independent=True,
        metadata={
            "configuration_sha256": "b" * 64,
            "resource_accounting": "none",
            "score_direction": "higher",
            "threshold": 2.0,
            "threshold_operator": ">=",
            "watermark_target_sha256": _TARGET_SHA256,
        },
    )

    def available(self):
        return True

    def detect(self, text):
        score = float(text.lower().count("however"))
        return {
            "scheme": "context-aware-fixture",
            "status": "detected" if score >= 2.0 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "threshold_operator": ">=",
            "configuration_sha256": self.capability.metadata["configuration_sha256"],
            "p_value": 0.01 if score >= 2.0 else 0.8,
        }


def test_command_attribution_drives_context_strategy_through_optimizer(monkeypatch):
    source = (
        "However signal patterns appear in this careful example, and however signal patterns "
        "remain visible to both calibrated checks."
    )
    manifest = command_detector_manifest(
        identifier="context-aware-primary",
        schemes=("context-aware-fixture",),
        configuration_sha256=_PRIMARY_CONFIGURATION_SHA256,
        implementation_sha256="1" * 64,
        threshold=2.0,
        threshold_operator=">=",
        calibrated=True,
        attribution_kind="token_character_spans",
        maximum_attributions=8,
        watermark_target_sha256=_TARGET_SHA256,
    )
    primary = CommandDetector(
        (sys.executable, __file__),
        manifest,
        DewatermarkConfig(local_lm_enabled=False),
    )
    requests = []

    def attributed_response(_command, payload, **_limits):
        request = json.loads(payload)
        requests.append(request)
        text = request["text"]
        score = float(text.lower().count("however"))
        attributions = [
            {
                "start": match.start(),
                "end": match.end(),
                "score": 2.5,
                "p_value": 0.01 + index * 0.01,
                "threshold": 2.0,
            }
            for index, match in enumerate(re.finditer(r"\bsignal\b", text))
        ]
        response = {
            "protocol_version": "1.2",
            "action": "detect.result",
            "detector": request["detector"],
            "scheme": "context-aware-fixture",
            "status": "detected" if score >= 2.0 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "threshold_operator": ">=",
            "effective_tokens": len(text.split()),
            "configuration_sha256": request["configuration_sha256"],
            "attributions": attributions,
        }
        return json.dumps(response).encode("ascii")

    monkeypatch.setattr("dewatermark.command_detector._run_bounded_command", attributed_response)
    strategy = context_aware_strategy(context_influence=1, max_edits=1, max_candidates=4)

    result = mitigate(
        source,
        primary,
        [strategy],
        verifier_detectors=[IndependentHoweverVerifier()],
        config=DewatermarkConfig(local_lm_enabled=False),
        limits=SearchLimits(max_rounds=1, max_candidates=4, max_transform_calls=1),
    )

    assert result.status == "verified"
    assert result.cleaned_text in {
        source.replace("However", "Yet", 1),
        source.replace("however", "yet", 1),
    }
    assert result.receipt.selected_strategy == strategy.capability.identifier
    assert result.receipt.primary_before is not None
    assert result.receipt.primary_before.localization
    assert requests[0]["attribution"] == {
        "kind": "token_character_spans",
        "maximum_attributions": 8,
    }
    assert source not in json.dumps(result.receipt.to_dict())
