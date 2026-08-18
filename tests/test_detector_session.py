import asyncio
import hashlib
import time
from dataclasses import replace
from threading import Event

import pytest

from dewatermark.config import DewatermarkConfig
from dewatermark.detector_session import (
    DetectorQueryBudgetExceeded,
    DetectorSession,
    SessionVerification,
    VerifierObservation,
)
from dewatermark.models import CapabilityManifest, VerificationEvidence
from dewatermark.request_context import RequestContext, ResourceBudgetExceeded, request_scope


class CountingDetector:
    def __init__(self, identifier="counting-primary", *, p_value=0.02):
        self.capability = CapabilityManifest(
            identifier=identifier,
            kind="detector",
            schemes=("counting-test",),
            calibrated=True,
            independent=True,
            metadata={
                "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
                "resource_accounting": "none",
                "score_direction": "higher",
                "threshold": 2.0,
                "threshold_operator": ">=",
                "watermark_target_sha256": "a" * 64,
            },
        )
        self.p_value = p_value
        self.calls = 0

    def available(self):
        return True

    def detect(self, text):
        self.calls += 1
        score = float(text.count("blue"))
        start = text.find("blue")
        return {
            "scheme": "counting-test",
            "status": "detected" if score >= 2.0 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "p_value": self.p_value,
            "localization": [
                {"start": start, "end": start + 4, "score": score, "p_value": 0.1},
                {"start": 0, "end": len(text) + 1, "score": 999.0},
            ],
        }


class HeldoutCountingDetector(CountingDetector):
    def detect(self, text):
        return super().detect(text)


def test_session_batches_caches_and_exposes_content_free_decision_metadata():
    detector = CountingDetector()
    session = DetectorSession(detector, max_queries=4)
    marked = "alpha blue beta blue gamma"
    clear = "alpha teal beta blue gamma"

    observations = session.score_many([marked, clear, marked])

    assert detector.calls == 2
    assert session.queries_used == 2
    assert [item.cached for item in observations] == [False, False, True]
    assert observations[0].p_value == 0.02
    assert observations[0].detection_margin == 0.0
    assert observations[1].detection_margin == -1.0
    assert [(span.start, span.end) for span in observations[0].localization] == [(6, 10)]
    assert marked not in repr(observations[0])
    assert marked not in str(observations[0].to_dict())

    cached = session.score(marked)
    assert cached.cached is True
    assert detector.calls == 2


def test_cached_scores_and_verification_still_enforce_request_deadline():
    primary = CountingDetector("deadline-primary")
    verifier = HeldoutCountingDetector("deadline-verifier")
    session = DetectorSession(primary, verifier_detectors=(verifier,), max_queries=8)
    context = RequestContext.from_config(DewatermarkConfig(request_timeout=30))
    source = "alpha blue beta blue gamma"
    candidate = "alpha teal beta blue gamma"

    with request_scope(context):
        assert session.verify(source, candidate).status == "verified"
        assert session.score(source).cached is True
        calls = (primary.calls, verifier.calls)
        context.deadline = time.monotonic() - 1
        with pytest.raises(ResourceBudgetExceeded, match="deadline"):
            session.score(source)
        with pytest.raises(ResourceBudgetExceeded, match="deadline"):
            session.verify(source, candidate)

    assert (primary.calls, verifier.calls) == calls
    assert context.deadline_exceeded is True


def test_cached_score_still_enforces_request_cancellation():
    detector = CountingDetector("cancel-primary")
    cancellation = Event()
    context = RequestContext.from_config(
        DewatermarkConfig(request_timeout=30), cancel_event=cancellation
    )
    session = DetectorSession(detector)
    source = "alpha blue beta blue gamma"

    with request_scope(context):
        session.score(source)
        cancellation.set()
        with pytest.raises(asyncio.CancelledError):
            session.score(source)

    assert detector.calls == 1
    assert context.cancelled is True


def test_batch_budget_preflight_is_atomic_and_config_caps_explicit_budget():
    detector = CountingDetector()
    config = DewatermarkConfig(max_detector_queries=2)
    session = DetectorSession(detector, config=config, max_queries=99)

    assert session.max_queries == 2
    with pytest.raises(DetectorQueryBudgetExceeded):
        session.score_many(["blue blue one", "blue blue two", "blue blue three"])
    assert detector.calls == 0
    assert session.queries_used == 0


def test_batch_hashes_detector_policy_once_before_and_after_scoring(monkeypatch):
    detector = CountingDetector("policy-batch-primary")
    session = DetectorSession(detector, max_queries=4)
    real_policy = session._target_policy_sha256
    calls = 0

    def counted_policy(target, capability=None):
        nonlocal calls
        calls += 1
        return real_policy(target, capability)

    monkeypatch.setattr(session, "_target_policy_sha256", counted_policy)
    observations = session.score_many(["blue blue repeated"] * 100)

    assert len(observations) == 100
    assert detector.calls == 1
    assert calls == 2


def test_impossible_verifier_portfolio_fails_before_identity_preflight(monkeypatch):
    session = DetectorSession(
        CountingDetector("impossible-primary"),
        verifier_detectors=(HeldoutCountingDetector("impossible-verifier"),),
        max_queries=2,
    )

    def forbidden_preflight():
        raise AssertionError("identity preflight must not run")

    monkeypatch.setattr(session, "_verification_preflight", forbidden_preflight)
    with pytest.raises(DetectorQueryBudgetExceeded):
        session.verify("blue blue source", "teal teal candidate")


def test_session_enforces_input_and_batch_limits():
    detector = CountingDetector()
    config = DewatermarkConfig(max_input_chars=12, max_batch_items=1)
    session = DetectorSession(detector, config=config)

    with pytest.raises(ValueError, match="max_input_chars"):
        session.score("blue blue blue")
    with pytest.raises(ValueError, match="max_batch_items"):
        session.score_many(["blue", "teal"])
    assert detector.calls == 0


def test_invalid_probability_and_out_of_bounds_localization_are_discarded():
    detector = CountingDetector(p_value=2.0)
    observation = DetectorSession(detector).score("blue blue text")

    assert observation.p_value is None
    assert len(observation.localization) == 1
    assert "2.0" not in str(observation.to_dict().get("p_value"))


def test_detector_response_cannot_claim_an_undeclared_scheme():
    class WrongSchemeDetector(CountingDetector):
        def detect(self, _text):
            self.calls += 1
            return {
                "scheme": "different-scheme",
                "status": "detected",
                "score": 3.0,
                "threshold": 2.0,
            }

    detector = WrongSchemeDetector()
    observation = DetectorSession(detector).score("blue blue")

    assert observation.evidence.status == "configuration_mismatch"
    assert observation.evidence.scheme is None


def test_self_contradictory_detector_decision_cannot_verify():
    class ContradictoryVerifier(HeldoutCountingDetector):
        def detect(self, _text):
            self.calls += 1
            return {
                "scheme": "counting-test",
                "status": "not_detected",
                "score": 10.0,
                "threshold": 1.0,
                "score_direction": "higher",
                "threshold_operator": ">=",
            }

    primary = CountingDetector("contradiction-primary")
    verifier = ContradictoryVerifier("contradiction-heldout")
    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "blue blue source", "teal teal candidate"
    )

    assert result.status == "not_verifiable"
    assert result.verifiers[0].before.evidence.status == "configuration_mismatch"
    assert result.verifiers[0].after.evidence.status == "configuration_mismatch"


def test_paired_verifier_threshold_and_configuration_drift_cannot_verify():
    class DriftingDecisionVerifier:
        capability = CapabilityManifest(
            identifier="decision-drift-heldout",
            kind="detector",
            schemes=("counting-test",),
            calibrated=True,
            independent=True,
            metadata={
                "configuration_sha256": "a" * 64,
                "resource_accounting": "none",
                "score_direction": "higher",
                "threshold": 1.0,
                "threshold_operator": ">=",
                "watermark_target_sha256": "a" * 64,
            },
        )

        def available(self):
            return True

        def detect(self, text):
            if text.count("blue") >= 2:
                return {
                    "scheme": "counting-test",
                    "status": "detected",
                    "score": 10.0,
                    "threshold": 1.0,
                    "score_direction": "higher",
                    "threshold_operator": ">=",
                    "configuration_sha256": "a" * 64,
                }
            return {
                "scheme": "counting-test",
                "status": "not_detected",
                "score": 10.0,
                "threshold": 100.0,
                "score_direction": "higher",
                "threshold_operator": ">=",
                "configuration_sha256": "b" * 64,
            }

    result = DetectorSession(
        CountingDetector("decision-drift-primary"),
        verifier_detectors=(DriftingDecisionVerifier(),),
    ).verify("blue blue source", "teal teal candidate")

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_inconclusive"
    assert result.verifiers[0].verification.status == "not_verifiable"


def test_unknown_detector_name_cannot_leak_a_credential_into_results():
    secret_name = "sk-live-PRIVATECREDENTIAL123456"
    observation = DetectorSession(secret_name).score("ordinary text")

    rendered = str(observation.to_dict())
    assert observation.detector == "primary-detector-0"
    assert secret_name not in rendered


def test_verification_requires_distinct_held_out_detector():
    primary = CountingDetector()
    source = "alpha blue beta blue gamma"
    candidate = "alpha teal beta blue gamma"

    repeated = DetectorSession(primary, verifier_detectors=(primary,))
    repeated_result = repeated.verify(source, candidate)
    assert repeated_result.status == "not_verifiable"
    assert repeated_result.reason_code == "held_out_verifier_not_distinct"
    assert primary.calls == 0

    verifier = HeldoutCountingDetector("counting-heldout")
    independent = DetectorSession(primary, verifier_detectors=(verifier,))
    result = independent.verify(source, candidate)
    assert result.status == "verified"
    assert result.verified is True

    same_implementation = DetectorSession(
        CountingDetector("another-primary"),
        verifier_detectors=(CountingDetector("another-heldout"),),
    ).verify(source, candidate)
    assert same_implementation.status == "not_verifiable"
    assert same_implementation.reason_code == "held_out_verifier_not_distinct"


def test_cosmetic_cross_module_subclasses_cannot_manufacture_independence():
    class CosmeticPrimary(CountingDetector):
        pass

    class CosmeticVerifier(CountingDetector):
        pass

    CosmeticPrimary.__module__ = "fixture_detector_primary"
    CosmeticVerifier.__module__ = "fixture_detector_verifier"
    primary = CosmeticPrimary("cosmetic-primary")
    verifier = CosmeticVerifier("cosmetic-verifier")

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "alpha blue beta blue gamma", "alpha teal beta blue gamma"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"
    assert primary.calls == 0
    assert verifier.calls == 0


def test_generic_detector_code_change_invalidates_cached_evidence(monkeypatch):
    primary = CountingDetector("generic-code-primary")
    verifier = HeldoutCountingDetector("generic-code-verifier")
    session = DetectorSession(primary, verifier_detectors=(verifier,))
    source = "alpha blue beta blue gamma"

    assert session.score(source).evidence.status == "detected"
    calls = primary.calls

    def changed_detect(self, text):
        self.calls += 1
        return {
            "scheme": "counting-test",
            "status": "not_detected",
            "score": 0.0,
            "threshold": 2.0,
            "score_direction": "higher",
            "threshold_operator": ">=",
            "configuration_sha256": self.capability.metadata["configuration_sha256"],
        }

    monkeypatch.setattr(CountingDetector, "detect", changed_detect)
    result = session.verify(source, "alpha teal beta blue gamma")

    assert result.status == "not_verifiable"
    assert result.reason_code == "detector_policy_drift"
    assert primary.calls == calls
    assert verifier.calls == 0


def test_generic_detector_reason_code_cannot_echo_source_text():
    class EchoReasonDetector(CountingDetector):
        def detect(self, text):
            evidence = super().detect(text)
            evidence["reason_code"] = text.split()[0]
            return evidence

    source = "privateword blue blue"
    rendered = DetectorSession(EchoReasonDetector()).score(source).to_dict()

    assert "privateword" not in str(rendered)
    assert rendered["evidence"]["details"]["reason_code"] == "detector_reported_reason"


def test_generic_detector_instance_method_shadow_cannot_verify():
    primary = CountingDetector("shadow-primary")
    verifier = HeldoutCountingDetector("shadow-verifier")
    shadow_calls = 0

    def forged(_text):
        nonlocal shadow_calls
        shadow_calls += 1
        return {
            "scheme": "counting-test",
            "status": "not_detected",
            "score": 0.0,
            "threshold": 2.0,
        }

    primary.detect = forged
    verifier.detect = forged
    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "alpha blue beta blue gamma", "alpha teal beta blue gamma"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_identity_unverifiable"
    assert shadow_calls == 0


def test_generic_detector_default_drift_invalidates_cached_evidence(monkeypatch):
    class DefaultPrimary(CountingDetector):
        def detect(self, text, multiplier=1.0):
            self.calls += 1
            score = float(text.count("blue")) * multiplier
            return {
                "scheme": "counting-test",
                "status": "detected" if score >= 2.0 else "not_detected",
                "score": score,
                "threshold": 2.0,
                "score_direction": "higher",
                "threshold_operator": ">=",
                "configuration_sha256": self.capability.metadata["configuration_sha256"],
            }

    primary = DefaultPrimary("default-drift-primary")
    verifier = HeldoutCountingDetector("default-drift-verifier")
    session = DetectorSession(primary, verifier_detectors=(verifier,))
    source = "alpha blue beta blue gamma"

    assert session.score(source).evidence.status == "detected"
    calls = primary.calls
    monkeypatch.setattr(DefaultPrimary.detect, "__defaults__", (0.0,))
    result = session.verify(source, "alpha teal beta blue gamma")

    assert result.status == "not_verifiable"
    assert result.reason_code == "detector_policy_drift"
    assert primary.calls == calls
    assert verifier.calls == 0


def test_verified_session_cannot_be_forged_without_observations_and_verifiers():
    with pytest.raises(ValueError, match="complete clearance evidence"):
        SessionVerification(
            status="verified",
            primary_before=None,
            primary_after=None,
            verifiers=(),
        )


def test_verification_rejects_a_different_watermark_target_before_text_access():
    primary = CountingDetector("scheme-a-primary")
    verifier = HeldoutCountingDetector("scheme-b-verifier")
    verifier.capability = CapabilityManifest(
        identifier="scheme-b-verifier",
        kind="detector",
        schemes=("different-scheme",),
        calibrated=True,
        independent=True,
        metadata={
            "configuration_sha256": "b" * 64,
            "resource_accounting": "none",
            "watermark_target_sha256": "b" * 64,
        },
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "blue blue red red", "teal teal green green"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_target_mismatch"
    assert primary.calls == 0
    assert verifier.calls == 0


def test_verification_rejects_detector_policy_drift_after_scoring():
    class DriftingVerifier(HeldoutCountingDetector):
        def detect(self, text):
            result = super().detect(text)
            self.capability.metadata["watermark_target_sha256"] = "f" * 64
            return result

    primary = CountingDetector("drift-primary")
    verifier = DriftingVerifier("drift-verifier")
    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "blue blue source", "teal teal candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "detector_policy_drift"
    assert verifier.calls == 2


def test_surrogate_inputs_have_distinct_cache_keys():
    detector = CountingDetector()
    session = DetectorSession(detector)

    left, right = session.score_many(["prefix\ud800", "prefix\ud801"])

    assert left.text_sha256 != right.text_sha256
    assert detector.calls == 2


def test_unavailable_detector_cannot_bypass_declared_resource_accounting():
    class UnavailableNetworkDetector:
        capability = CapabilityManifest(
            identifier="unavailable-network-detector",
            kind="detector",
            schemes=("fixture",),
            network_required=True,
            metadata={"resource_accounting": "network"},
        )

        def available(self):
            return False

    observation = DetectorSession(
        UnavailableNetworkDetector(),
        config=DewatermarkConfig(allow_remote_processing=True),
    ).score("private source")

    assert observation.evidence.status == "configuration_mismatch"
    assert observation.evidence.reason == "remote_usage_not_accounted"


def test_structured_evidence_fields_cannot_smuggle_source_text():
    class HostileDetailsDetector(CountingDetector):
        def detect(self, text):
            result = super().detect(text)
            result["localization"] = text
            result["mismatch_fields"] = text
            result["protocol_version"] = text
            return result

    source = "ordinary source prose blue blue"
    observation = DetectorSession(HostileDetailsDetector()).score(source)

    assert "localization" not in observation.evidence.details
    assert "mismatch_fields" not in observation.evidence.details
    assert "protocol_version" not in observation.evidence.details
    assert source not in str(observation.to_dict())


def test_verification_requires_a_static_decision_contract_before_text_access():
    primary = CountingDetector("unbound-primary")
    verifier = HeldoutCountingDetector("unbound-verifier")
    del primary.capability.metadata["threshold_operator"]

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "blue blue source", "teal teal candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "detector_decision_contract_unbound"
    assert primary.calls == 0
    assert verifier.calls == 0


def test_malformed_static_decision_contract_fails_before_text_access():
    primary = CountingDetector("malformed-primary")
    verifier = HeldoutCountingDetector("malformed-verifier")
    primary.capability.metadata["threshold_operator"] = []

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "blue blue source", "teal teal candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "detector_decision_contract_unbound"
    assert primary.calls == 0
    assert verifier.calls == 0


def test_cache_cannot_reuse_evidence_after_detector_policy_changes():
    primary = CountingDetector("cache-primary")
    verifier = HeldoutCountingDetector("cache-verifier")
    session = DetectorSession(primary, verifier_detectors=(verifier,))

    first = session.verify("blue blue source", "teal teal candidate")
    assert first.status == "verified"
    calls = (primary.calls, verifier.calls)

    primary.capability.metadata["configuration_sha256"] = "c" * 64
    verifier.capability.metadata["configuration_sha256"] = "d" * 64
    second = session.verify("blue blue source", "teal teal candidate")

    assert second.status == "not_verifiable"
    assert second.reason_code == "detector_policy_drift"
    assert (primary.calls, verifier.calls) == calls


def test_primary_decision_contract_drift_returns_inconclusive_instead_of_raising():
    class DriftingPrimary(CountingDetector):
        def detect(self, text):
            result = super().detect(text)
            if "teal" in text:
                result["threshold"] = 100.0
            return result

    result = DetectorSession(
        DriftingPrimary("drifting-primary"),
        verifier_detectors=(HeldoutCountingDetector("stable-verifier"),),
    ).verify("blue blue source", "teal teal candidate")

    assert result.status == "not_verifiable"
    assert result.reason_code == "primary_inconclusive"


def test_verified_session_rejects_role_and_cross_text_hash_forgery():
    result = DetectorSession(
        CountingDetector("binding-primary"),
        verifier_detectors=(HeldoutCountingDetector("binding-verifier"),),
    ).verify("blue blue source", "teal teal candidate")
    assert result.status == "verified"
    assert result.primary_before is not None
    verifier = result.verifiers[0]

    with pytest.raises(ValueError, match="complete clearance evidence"):
        SessionVerification(
            status="verified",
            primary_before=replace(result.primary_before, role="verifier"),
            primary_after=result.primary_after,
            verifiers=result.verifiers,
        )

    wrong_hash_before = replace(verifier.before, text_sha256="f" * 64)
    wrong_hash_verifier = VerifierObservation(
        detector=verifier.detector,
        before=wrong_hash_before,
        after=verifier.after,
        verification=VerificationEvidence(
            status="verified_cleared",
            detector=verifier.detector,
            before=wrong_hash_before.evidence,
            after=verifier.after.evidence,
        ),
    )
    with pytest.raises(ValueError, match="complete clearance evidence"):
        SessionVerification(
            status="verified",
            primary_before=result.primary_before,
            primary_after=result.primary_after,
            verifiers=(wrong_hash_verifier,),
        )


def test_verified_clearance_rejects_incomplete_nested_evidence():
    with pytest.raises(ValueError, match="complete paired detector evidence"):
        VerificationEvidence(status="verified_cleared", detector="fixture")
