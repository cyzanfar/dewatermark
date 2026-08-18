import hashlib
import json
from dataclasses import replace

import pytest

import dewatermark.optimizer as optimizer_module
from dewatermark.config import DewatermarkConfig
from dewatermark.detector_session import SignalSpan
from dewatermark.localization import LocalizedSignal
from dewatermark.models import CapabilityManifest
from dewatermark.optimizer import CandidateProposal, SearchLimits, StrategyBinding, mitigate
from dewatermark.quality import QualityGateDecision
from dewatermark.request_context import RequestContext, current_request_context, request_scope


class WordDetector:
    def __init__(self, identifier):
        self.capability = CapabilityManifest(
            identifier=identifier,
            kind="detector",
            schemes=("word-count-test",),
            calibrated=True,
            independent=True,
            metadata={
                "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
                "resource_accounting": "none",
                "score_direction": "higher",
                "threshold": 2.0,
                "threshold_operator": ">=",
                "watermark_target_sha256": "b" * 64,
            },
        )
        self.calls = 0

    def available(self):
        return True

    def detect(self, text):
        self.calls += 1
        score = float(text.count("blue"))
        return {
            "scheme": "word-count-test",
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "p_value": 0.01 if score >= 2 else 0.8,
        }


class HeldoutWordDetector(WordDetector):
    def detect(self, text):
        return super().detect(text)


class ReplacementStrategy:
    def __init__(self, identifier, count):
        self.capability = CapabilityManifest(
            identifier=identifier,
            kind="transformer",
            schemes=("word-count-test",),
            metadata={"resource_accounting": "none"},
        )
        self.count = count
        self.contexts = []

    def available(self):
        return True

    def generate(self, text, *, context, **_options):
        self.contexts.append(context)
        return [text.replace("blue", "teal", self.count)]


class LegacyReplacement:
    capability = CapabilityManifest(
        identifier="legacy-replacement",
        kind="transformer",
        metadata={"resource_accounting": "none"},
    )

    def available(self):
        return True

    def transform(self, text, **_options):
        return text.replace("blue", "teal", 2), {"private": text}


SOURCE = "alpha blue beta blue gamma blue delta epsilon zeta eta theta iota kappa lambda"


def _detectors():
    return WordDetector("optimizer-primary"), HeldoutWordDetector("optimizer-heldout")


def test_mitigation_selects_smallest_verified_edit_not_first_candidate():
    primary, verifier = _detectors()
    broad = ReplacementStrategy("broad-rewrite", 3)
    minimal = ReplacementStrategy("minimal-rewrite", 2)
    localized = (SignalSpan(6, 10, score=3.0),)

    result = mitigate(
        SOURCE,
        primary,
        [broad, minimal],
        verifier_detectors=[verifier],
        source_localization=localized,
    )

    assert result.status == "verified"
    assert result.changed is True
    assert result.cleaned_text == SOURCE.replace("blue", "teal", 2)
    assert result.receipt.selected_strategy == "minimal-rewrite"
    assert result.receipt.verification is not None
    assert result.receipt.verification.verified
    assert result.receipt.resources["search_limits"]["max_candidates"] == 24
    assert result.receipt.resources["search_limits"]["max_detector_queries"] == 64
    assert minimal.contexts[0].source_localization == localized
    assert SOURCE not in repr(result)
    assert SOURCE not in repr(result.receipt)
    assert SOURCE not in json.dumps(result.receipt.to_dict())


def test_window_localization_can_feed_strategy_without_becoming_verification():
    primary, verifier = _detectors()
    strategy = ReplacementStrategy("localized-rewrite", 2)
    localized = (LocalizedSignal(6, 10, 2, strongest_margin=1.0, smallest_p_value=0.01),)

    result = mitigate(
        SOURCE,
        primary,
        [strategy],
        verifier_detectors=[verifier],
        source_localization=localized,
    )

    assert result.status == "verified"
    assert strategy.contexts[0].source_localization == (SignalSpan(6, 10, p_value=0.01),)
    # Verification still consists only of full detector observations.
    assert result.receipt.verification is not None
    assert len(result.receipt.verification.verifiers) == 1


def test_legacy_transformer_adapter_is_quality_checked_and_verified():
    primary, verifier = _detectors()

    result = mitigate(
        SOURCE,
        primary,
        [StrategyBinding(LegacyReplacement(), options={})],
        verifier_detectors=[verifier],
    )

    assert result.status == "verified"
    assert result.cleaned_text == SOURCE.replace("blue", "teal", 2)
    assert SOURCE not in json.dumps(result.receipt.to_dict())


class RejectEverythingGate:
    capability = CapabilityManifest(
        identifier="reject-everything",
        kind="quality_gate",
        metadata={"quality_gate_type": "external", "resource_accounting": "none"},
    )

    def evaluate(self, _source, _candidate):
        return QualityGateDecision(
            status="failed",
            score=0.0,
            threshold=1.0,
            checked_items=1,
            reason_code="threshold_not_met",
        )


def test_untrusted_candidate_cannot_bypass_central_quality_gate():
    primary, verifier = _detectors()
    config = DewatermarkConfig(quality_gates=(RejectEverythingGate(),))

    result = mitigate(
        SOURCE,
        primary,
        [ReplacementStrategy("quality-target", 2)],
        verifier_detectors=[verifier],
        config=config,
    )

    assert result.status == "rolled_back"
    assert result.reason_code == "quality_rejected"
    assert result.cleaned_text == SOURCE
    assert result.changed is False


def test_query_exhaustion_rolls_back_exact_source():
    primary, verifier = _detectors()

    result = mitigate(
        SOURCE,
        primary,
        [ReplacementStrategy("budget-target", 2)],
        verifier_detectors=[verifier],
        config=DewatermarkConfig(max_detector_queries=2),
        limits=SearchLimits(max_detector_queries=50),
    )

    assert result.status == "rolled_back"
    assert result.reason_code == "detector_budget_exhausted"
    assert result.cleaned_text == SOURCE
    assert result.receipt.resources["detector_queries_limit"] == 2


def test_missing_or_repeated_verifier_never_commits_candidate():
    primary, _ = _detectors()
    strategy = ReplacementStrategy("not-verifiable", 2)

    missing = mitigate(SOURCE, primary, [strategy])
    assert missing.status == "abstained"
    assert missing.reason_code == "held_out_verifier_required"
    assert missing.cleaned_text == SOURCE

    repeated = mitigate(
        SOURCE,
        primary,
        [strategy],
        verifier_detectors=[primary],
    )
    assert repeated.status == "rolled_back"
    assert repeated.reason_code == "verification_inconclusive"
    assert repeated.cleaned_text == SOURCE


class RemoteStrategy:
    capability = CapabilityManifest(
        identifier="remote-without-consent",
        kind="transformer",
        network_required=True,
        metadata={"resource_accounting": "network"},
    )

    def __init__(self):
        self.called = False

    def available(self):
        return True

    def generate(self, text, *, context, **_options):
        self.called = True
        return [text]


def test_strategy_cannot_use_network_without_explicit_consent():
    primary, verifier = _detectors()
    strategy = RemoteStrategy()

    result = mitigate(SOURCE, primary, [strategy], verifier_detectors=[verifier])

    assert strategy.called is False
    assert result.status == "rolled_back"
    assert result.reason_code == "no_candidates"
    assert result.cleaned_text == SOURCE


class AccountedRemoteReplacementStrategy(RemoteStrategy):
    capability = CapabilityManifest(
        identifier="accounted-remote-replacement",
        kind="transformer",
        network_required=True,
        metadata={"resource_accounting": "network"},
    )

    def generate(self, text, *, context, **_options):
        self.called = True
        active = current_request_context()
        assert active is not None
        active.before_remote_call("https://example.test/generate", "remote", {})
        return [text.replace("blue", "teal", 2)]


class AccountedModelReplacementStrategy(RemoteStrategy):
    capability = CapabilityManifest(
        identifier="accounted-model-replacement",
        kind="transformer",
        model_download_possible=True,
        metadata={"resource_accounting": "model"},
    )

    def generate(self, text, *, context, **_options):
        self.called = True
        active = current_request_context()
        assert active is not None
        active.record_model_access("private-model", cached=False, download_allowed=True)
        return [text.replace("blue", "teal", 2)]


@pytest.mark.parametrize(
    ("strategy", "inner_config"),
    [
        (
            AccountedRemoteReplacementStrategy(),
            DewatermarkConfig(allow_remote_processing=True),
        ),
        (
            AccountedModelReplacementStrategy(),
            DewatermarkConfig(allow_model_download=True),
        ),
    ],
)
def test_nested_request_cannot_relax_outer_consent(strategy, inner_config):
    primary, verifier = _detectors()
    outer = RequestContext.from_config(DewatermarkConfig())

    with request_scope(outer):
        result = mitigate(
            SOURCE,
            primary,
            [strategy],
            verifier_detectors=[verifier],
            config=inner_config,
        )

    assert strategy.called is False
    assert result.status == "rolled_back"
    assert result.cleaned_text == SOURCE
    assert outer.remote_calls == 0
    assert outer.model_accesses == []


class UnaccountedFailingRemoteStrategy(RemoteStrategy):
    capability = CapabilityManifest(
        identifier="unaccounted-failing-remote",
        kind="transformer",
        network_required=True,
        metadata={"resource_accounting": "network"},
    )

    def generate(self, _text, *, context, **_options):
        raise RuntimeError("private candidate and credential detail")


def test_strategy_exception_cannot_mask_missing_resource_accounting():
    primary, verifier = _detectors()
    result = mitigate(
        SOURCE,
        primary,
        [UnaccountedFailingRemoteStrategy()],
        verifier_detectors=[verifier],
        config=DewatermarkConfig(allow_remote_processing=True),
    )

    rendered = json.dumps(result.receipt.to_dict())
    assert result.cleaned_text == SOURCE
    assert any(event.reason_code == "remote_usage_not_accounted" for event in result.receipt.trace)
    assert "private candidate" not in rendered
    assert "credential detail" not in rendered


class UnaccountedUnavailableRemoteStrategy(RemoteStrategy):
    capability = CapabilityManifest(
        identifier="unaccounted-unavailable-remote",
        kind="transformer",
        network_required=True,
        metadata={"resource_accounting": "network"},
    )

    def available(self):
        return False


def test_unavailable_strategy_cannot_bypass_declared_resource_accounting():
    primary, verifier = _detectors()
    result = mitigate(
        SOURCE,
        primary,
        [UnaccountedUnavailableRemoteStrategy()],
        verifier_detectors=[verifier],
        config=DewatermarkConfig(allow_remote_processing=True),
    )

    assert result.cleaned_text == SOURCE
    assert any(event.reason_code == "remote_usage_not_accounted" for event in result.receipt.trace)


class HostileProposalStrategy:
    capability = CapabilityManifest(
        identifier="hostile-proposal",
        kind="transformer",
        metadata={"resource_accounting": "none"},
    )

    def available(self):
        return True

    def generate(self, _text, *, context, **_options):
        proposal = object.__new__(CandidateProposal)
        object.__setattr__(proposal, "text", object())
        return [proposal]


def test_hostile_candidate_value_is_rejected_without_escaping_or_leaking():
    primary, verifier = _detectors()

    result = mitigate(
        SOURCE,
        primary,
        [HostileProposalStrategy()],
        verifier_detectors=[verifier],
    )

    assert result.status == "rolled_back"
    assert result.cleaned_text == SOURCE
    rendered = json.dumps(result.receipt.to_dict())
    assert SOURCE not in rendered
    assert "object at" not in rendered


def test_config_caps_candidate_policy_and_candidate_proposal_validates_text():
    with pytest.raises(TypeError, match="must be a string"):
        CandidateProposal(object())  # type: ignore[arg-type]

    primary, verifier = _detectors()
    result = mitigate(
        SOURCE,
        primary,
        [ReplacementStrategy("candidate-cap", 2)],
        verifier_detectors=[verifier],
        config=DewatermarkConfig(max_search_candidates=1),
        limits=SearchLimits(max_candidates=200),
    )
    scored = [event for event in result.receipt.trace if event.kind == "candidate_scored"]
    assert len(scored) == 1


def test_receipt_rejects_hash_quality_and_exact_rollback_forgery():
    primary, verifier = _detectors()
    verified = mitigate(
        SOURCE,
        primary,
        [ReplacementStrategy("receipt-binding", 2)],
        verifier_detectors=[verifier],
    )
    assert verified.status == "verified"

    with pytest.raises(ValueError, match="bound clearance evidence"):
        replace(verified.receipt, input_sha256="f" * 64)
    with pytest.raises(ValueError, match="bound clearance evidence"):
        replace(verified.receipt, quality={"passed": False})
    with pytest.raises(ValueError, match="internally consistent"):
        replace(verified.receipt, claim_scope="universal removal verified")

    abstained = mitigate(
        SOURCE,
        WordDetector("rollback-primary"),
        [ReplacementStrategy("rollback-strategy", 2)],
    )
    with pytest.raises(ValueError, match="exact rollback"):
        replace(abstained.receipt, output_sha256="f" * 64)
    with pytest.raises(ValueError, match="exact rollback"):
        replace(abstained.receipt, selected_strategy="forged-strategy")


def test_primary_policy_mutation_during_search_rolls_back_without_exception():
    primary, verifier = _detectors()

    class MutatingStrategy(ReplacementStrategy):
        def generate(self, text, *, context, **options):
            primary.capability.metadata["configuration_sha256"] = "f" * 64
            return super().generate(text, context=context, **options)

    result = mitigate(
        SOURCE,
        primary,
        [MutatingStrategy("mutating-strategy", 2)],
        verifier_detectors=[verifier],
    )

    assert result.status == "rolled_back"
    assert result.reason_code == "verification_inconclusive"
    assert result.cleaned_text == SOURCE


def test_request_expiring_after_verification_cannot_commit_changed_text(monkeypatch):
    primary, verifier = _detectors()
    real_verify = optimizer_module.DetectorSession.verify

    def verify_then_expire(session, source, candidate):
        verification = real_verify(session, source, candidate)
        active = current_request_context()
        assert active is not None
        active.deadline = 1.0
        return verification

    monkeypatch.setattr(optimizer_module.DetectorSession, "verify", verify_then_expire)
    result = mitigate(
        SOURCE,
        primary,
        [ReplacementStrategy("post-verify-deadline", 2)],
        verifier_detectors=[verifier],
    )

    assert result.status == "rolled_back"
    assert result.reason_code == "resource_budget_exhausted"
    assert result.cleaned_text == SOURCE
    assert result.changed is False


def test_oversized_candidate_is_rejected_before_digest_allocation(monkeypatch):
    original_digest = optimizer_module._digest

    def guarded_digest(value):
        if len(value) > 64:
            raise RuntimeError("oversized candidate reached digest")
        return original_digest(value)

    class OversizedStrategy:
        capability = CapabilityManifest(
            identifier="oversized-strategy",
            kind="transformer",
            metadata={"resource_accounting": "none"},
        )

        def available(self):
            return True

        def generate(self, _text, *, context, **_options):
            return ["x" * 65]

    monkeypatch.setattr(optimizer_module, "_digest", guarded_digest)
    source = "blue blue alpha beta"
    result = mitigate(
        source,
        WordDetector("size-primary"),
        [OversizedStrategy()],
        verifier_detectors=[HeldoutWordDetector("size-verifier")],
        limits=SearchLimits(max_candidate_characters=64),
    )

    assert result.status == "rolled_back"
    assert result.reason_code == "no_candidates"
    assert all(event.text_sha256 is None for event in result.receipt.trace[1:])
