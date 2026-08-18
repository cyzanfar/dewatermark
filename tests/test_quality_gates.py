from __future__ import annotations

from dataclasses import replace

import dewatermark
from dewatermark.assurance_api import create_plan
from dewatermark.config import DewatermarkConfig
from dewatermark.models import CapabilityManifest
from dewatermark.providers import register_provider, unregister_provider
from dewatermark.quality import (
    QualityGateBinding,
    evaluate_candidate,
    evaluate_quality,
)
from dewatermark.quality_gates import (
    AtomicClaimQAGate,
    BidirectionalNLIGate,
    CachedTransformersNLIAdapter,
    PairwiseAssessment,
    TaskContractGate,
    quality_gate_conformance,
)
from dewatermark.request_context import current_request_context

OFFLINE = DewatermarkConfig(local_lm_enabled=False)
SOURCE = "The service is stable and ready today."
CANDIDATE = "Today, the service is ready and stable."


class RewriteProvider:
    capability = CapabilityManifest(identifier="quality-rewrite-fixture", kind="transformer")

    def __init__(self, _config):
        pass

    def available(self):
        return True

    def rewrite(self, _text, **_options):
        return CANDIDATE, {"strategy": "fixture"}


class NLIAdapter:
    capability = CapabilityManifest(
        identifier="local-nli-fixture",
        kind="quality_gate",
        metadata={"resource_accounting": "none"},
    )

    def __init__(self, scores=(0.94, 0.91), available=True):
        self.scores = iter(scores)
        self.is_available = available
        self.calls = 0

    def available(self):
        return self.is_available

    def entailment_probability(self, _premise, _hypothesis):
        self.calls += 1
        return next(self.scores)


class PairwiseAdapter:
    capability = CapabilityManifest(
        identifier="local-pairwise-fixture",
        kind="quality_gate",
        metadata={"resource_accounting": "none"},
    )

    def __init__(self, score=1.0, count=3):
        self.score = score
        self.count = count

    def available(self):
        return True

    def assess(self, _source, _candidate):
        return PairwiseAssessment(score=self.score, checked_items=self.count)


def _rewrite_with_gate(binding):
    register_provider("quality-rewrite-fixture", RewriteProvider)
    try:
        return dewatermark.remove(
            SOURCE,
            mode="full",
            config=replace(
                OFFLINE,
                rewriter_provider="quality-rewrite-fixture",
                quality_gates=(binding,),
            ),
        )
    finally:
        unregister_provider("quality-rewrite-fixture")


def test_bidirectional_nli_passes_both_directions_and_is_in_receipt():
    result = _rewrite_with_gate(QualityGateBinding(BidirectionalNLIGate(NLIAdapter())))
    assert result.cleaned_text == CANDIDATE
    outcome = result.receipt.to_dict()["quality"]["gate_outcomes"][0]
    assert outcome["gate_type"] == "bidirectional_nli"
    assert outcome["status"] == "passed"
    assert outcome["score"] == 0.91
    assert outcome["source_entails_candidate"] == 0.94
    assert outcome["candidate_entails_source"] == 0.91
    assert outcome["checked_items"] == 2
    assert SOURCE not in str(outcome)


def test_required_nli_failure_rejects_candidate_but_advisory_failure_does_not():
    required = _rewrite_with_gate(
        QualityGateBinding(BidirectionalNLIGate(NLIAdapter((0.95, 0.20))))
    )
    assert required.cleaned_text == SOURCE
    assert required.report.transformation_status == "rejected_quality"
    assert required.receipt.to_dict()["quality"]["gate_outcomes"][0]["status"] == "failed"

    advisory = _rewrite_with_gate(
        QualityGateBinding(BidirectionalNLIGate(NLIAdapter((0.95, 0.20))), required=False)
    )
    assert advisory.cleaned_text == CANDIDATE
    outcome = advisory.receipt.to_dict()["quality"]["gate_outcomes"][0]
    assert outcome["status"] == "failed"
    assert outcome["required"] is False


def test_required_unavailable_gate_abstains_and_fails_closed():
    adapter = NLIAdapter(available=False)
    result = _rewrite_with_gate(QualityGateBinding(BidirectionalNLIGate(adapter)))
    outcome = result.receipt.to_dict()["quality"]["gate_outcomes"][0]
    assert result.cleaned_text == SOURCE
    assert outcome["status"] == "abstained"
    assert outcome["reason_code"] == "adapter_unavailable"
    assert adapter.calls == 0


def test_network_gate_requires_consent_before_receiving_text():
    class NetworkAdapter(NLIAdapter):
        capability = CapabilityManifest(
            identifier="network-nli-fixture",
            kind="quality_gate",
            network_required=True,
            metadata={"resource_accounting": "network"},
        )

    adapter = NetworkAdapter()
    report = evaluate_candidate(
        SOURCE,
        CANDIDATE,
        replace(
            OFFLINE,
            quality_gates=(QualityGateBinding(BidirectionalNLIGate(adapter)),),
        ),
    )
    assert not report.passed
    assert report.gate_outcomes[0].status == "error"
    assert report.gate_outcomes[0].reason_code == "extension_rejected"
    assert adapter.calls == 0


def test_declared_network_gate_must_use_request_ledger():
    class UnaccountedNetworkAdapter(NLIAdapter):
        capability = CapabilityManifest(
            identifier="unaccounted-network-nli",
            kind="quality_gate",
            network_required=True,
            metadata={"resource_accounting": "network"},
        )

    register_provider("quality-rewrite-fixture", RewriteProvider)
    try:
        result = dewatermark.remove(
            SOURCE,
            mode="full",
            config=replace(
                OFFLINE,
                allow_remote_processing=True,
                rewriter_provider="quality-rewrite-fixture",
                quality_gates=(
                    QualityGateBinding(BidirectionalNLIGate(UnaccountedNetworkAdapter())),
                ),
            ),
        )
    finally:
        unregister_provider("quality-rewrite-fixture")
    outcome = result.receipt.to_dict()["quality"]["gate_outcomes"][0]
    assert result.cleaned_text == SOURCE
    assert outcome["status"] == "error"
    assert outcome["reason_code"] == "remote_usage_not_accounted"


def test_nli_calls_share_the_request_wide_remote_call_budget():
    class AccountedNetworkAdapter(NLIAdapter):
        capability = CapabilityManifest(
            identifier="accounted-network-nli",
            kind="quality_gate",
            network_required=True,
            metadata={"resource_accounting": "network"},
        )

        def entailment_probability(self, premise, _hypothesis):
            context = current_request_context()
            assert context is not None
            context.before_remote_call(
                "https://quality.invalid/v1/entailment",
                "external-quality",
                {"text": premise},
            )
            return 0.95

    register_provider("quality-rewrite-fixture", RewriteProvider)
    try:
        result = dewatermark.remove(
            SOURCE,
            mode="full",
            config=replace(
                OFFLINE,
                allow_remote_processing=True,
                max_remote_calls=1,
                rewriter_provider="quality-rewrite-fixture",
                quality_gates=(
                    QualityGateBinding(BidirectionalNLIGate(AccountedNetworkAdapter())),
                ),
            ),
        )
    finally:
        unregister_provider("quality-rewrite-fixture")
    outcome = result.receipt.to_dict()["quality"]["gate_outcomes"][0]
    assert result.cleaned_text == SOURCE
    assert outcome["status"] == "error"
    assert outcome["reason_code"] == "adapter_error"
    assert result.receipt.resources["remote_calls_used"] == 1


def test_model_accounting_is_shared_and_content_free():
    class AccountedModelAdapter(NLIAdapter):
        capability = CapabilityManifest(
            identifier="accounted-model-nli",
            kind="quality_gate",
            metadata={"resource_accounting": "model"},
        )

        def entailment_probability(self, _premise, _hypothesis):
            context = current_request_context()
            assert context is not None
            context.record_model_access(
                "private/local/model/path", cached=True, download_allowed=False
            )
            return 0.95

    result = _rewrite_with_gate(QualityGateBinding(BidirectionalNLIGate(AccountedModelAdapter())))
    assert result.cleaned_text == CANDIDATE
    accesses = result.receipt.resources["model_accesses"]
    assert len(accesses) == 2
    assert "private/local/model/path" not in str(accesses)


def test_legacy_semantic_scorer_cannot_bypass_resource_accounting():
    class Semantic:
        capability = CapabilityManifest(
            identifier="unaccounted-semantic",
            kind="semantic_scorer",
            network_required=True,
            metadata={"resource_accounting": "network"},
        )

        def __call__(self, _source, _candidate):
            return 1.0

    report = evaluate_candidate(
        SOURCE,
        CANDIDATE,
        replace(
            OFFLINE,
            allow_remote_processing=True,
            semantic_scorer=Semantic(),
            quality_min_semantic_score=0.8,
        ),
    )
    assert not report.passed
    assert report.gate_outcomes[0].status == "error"
    assert report.gate_outcomes[0].reason_code == "request_context_required"


def test_claim_qa_and_task_contract_adapters_are_typed_and_fail_closed():
    claim = AtomicClaimQAGate(PairwiseAdapter(score=0.5, count=4), threshold=0.9)
    task = TaskContractGate(PairwiseAdapter(score=1.0, count=2))
    report = evaluate_candidate(
        SOURCE,
        CANDIDATE,
        replace(
            OFFLINE,
            quality_gates=(
                QualityGateBinding(claim, required=False),
                QualityGateBinding(task),
            ),
        ),
    )
    assert report.passed
    assert [item.gate_type for item in report.gate_outcomes] == [
        "atomic_claim_qa",
        "task_contract",
    ]
    assert [item.status for item in report.gate_outcomes] == ["failed", "passed"]


def test_invalid_gate_result_is_error_and_required_policy_rejects():
    class InvalidGate:
        capability = CapabilityManifest(identifier="invalid-gate", kind="quality_gate")

        def evaluate(self, _source, _candidate):
            return {"status": "passed", "private": SOURCE}

    report = evaluate_candidate(
        SOURCE,
        CANDIDATE,
        replace(OFFLINE, quality_gates=(QualityGateBinding(InvalidGate()),)),
    )
    assert not report.passed
    assert report.gate_outcomes[0].status == "error"
    assert SOURCE not in str(report.gate_outcomes[0].to_dict())


def test_nli_label_cannot_pass_without_both_directional_scores():
    class ForgedNLI:
        capability = CapabilityManifest(
            identifier="forged-nli",
            kind="quality_gate",
            metadata={"quality_gate_type": "bidirectional_nli"},
        )

        def evaluate(self, _source, _candidate):
            from dewatermark.quality import QualityGateDecision

            return QualityGateDecision(
                status="passed",
                score=1.0,
                threshold=0.8,
                checked_items=2,
            )

    report = evaluate_candidate(
        SOURCE,
        CANDIDATE,
        replace(OFFLINE, quality_gates=(QualityGateBinding(ForgedNLI()),)),
    )
    assert not report.passed
    assert report.gate_outcomes[0].status == "error"


def test_citation_identifiers_are_protected_by_deterministic_gate():
    report = evaluate_quality(
        "The result is established [4] and archived as arXiv:2401.12345.",
        "The result is established [5] and archived as arXiv:2401.54321.",
    )
    assert not report.passed
    assert report.missing_citations == ["[4]", "arXiv:2401.12345"]
    assert report.introduced_citations == ["[5]", "arXiv:2401.54321"]
    assert "citations changed" in report.reasons


def test_cached_nli_construction_and_conformance_have_no_import_or_model_access(monkeypatch):
    imported = []

    def forbidden_find_spec(name):
        imported.append(name)
        raise AssertionError("dependency discovery should not run during construction")

    monkeypatch.setattr("dewatermark.quality_gates.importlib.util.find_spec", forbidden_find_spec)
    adapter = CachedTransformersNLIAdapter("reviewed/local-model")
    gate = BidirectionalNLIGate(adapter)
    manifest = quality_gate_conformance(gate)
    assert manifest["conformant"] is True
    assert manifest["quality_gate_type"] == "bidirectional_nli"
    assert manifest["model_download_possible"] is False
    assert imported == []


def test_agent_plan_binds_gate_identity_without_invoking_it():
    class NeverRunGate:
        capability = CapabilityManifest(
            identifier="plan-only-gate",
            kind="quality_gate",
            metadata={"quality_gate_type": "task_contract"},
        )

        def evaluate(self, _source, _candidate):
            raise AssertionError("planning must not invoke a quality gate")

    planned = create_plan(
        SOURCE,
        mode="full",
        config=replace(
            OFFLINE,
            quality_gates=(QualityGateBinding(NeverRunGate()),),
        ),
    )
    configured = planned["policy"]["config"]["quality_gates"]
    assert configured[0]["required"] is True
    assert configured[0]["capability"]["identifier"] == "plan-only-gate"
