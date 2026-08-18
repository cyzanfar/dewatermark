import json

import dewatermark
from dewatermark.detector_tools import (
    conform_reference_detectors,
    discover_detector_capabilities,
    doctor_detectors,
)
from dewatermark.reference_detectors import (
    KGWReferenceDetector,
    TournamentReferenceDetector,
    UnigramReferenceDetector,
    generate_reference_text,
    load_reference_golden_vectors,
)


def test_reference_detectors_have_matched_positive_and_negative_fixtures():
    classes = {
        "kgw-word-v1": KGWReferenceDetector,
        "unigram-word-v1": UnigramReferenceDetector,
        "tournament-word-v1": TournamentReferenceDetector,
    }
    for scheme, detector_class in classes.items():
        detector = detector_class()
        positive = detector.detect(
            generate_reference_text(scheme, token_count=96, seed=11, watermarked=True)
        )
        negative = detector.detect(
            generate_reference_text(scheme, token_count=96, seed=29, watermarked=False)
        )
        assert positive.status == "detected"
        assert negative.status == "not_detected"
        assert positive.score is not None and negative.score is not None
        assert positive.score > negative.score
        assert positive.details["reference_only"] is True
        assert positive.details["vendor_equivalent"] is False
        assert detector.capability.calibrated is False
        assert detector.capability.independent is False


def test_reference_detector_abstains_below_effective_length():
    evidence = KGWReferenceDetector().detect("too short for statistical evidence")
    assert evidence.status == "insufficient_evidence"
    assert evidence.details["effective_tokens"] < 32


def test_packaged_reference_vectors_are_content_redacting_and_conformant():
    vectors = load_reference_golden_vectors()
    assert len(vectors) == 6
    assert "text=<redacted>" in repr(vectors[0])
    report = conform_reference_detectors()
    assert report.passed
    public = json.dumps(report.to_dict())
    assert vectors[0].text not in public
    assert len(report.vectors_sha256) == 64


def test_reference_detector_registry_names_cannot_be_mistaken_for_vendor_support():
    names = set(dewatermark.list_detectors())
    assert {"reference-kgw", "reference-unigram", "reference-tournament"} <= names
    evidence = dewatermark.inspect(
        generate_reference_text("kgw-word-v1", token_count=96),
        detector="reference-kgw",
    )
    assert evidence.status == "detected"
    assert evidence.scheme == "research-reference/kgw-word-v1"
    assert evidence.details["vendor_equivalent"] is False


def test_detector_inventory_and_doctor_are_static_and_explicit():
    inventory = discover_detector_capabilities()
    reference = next(
        item for item in inventory if item.identifier == "research-reference/kgw-word-v1"
    )
    assert reference.status == "research_fixture_only"
    assert "reference-kgw" in reference.aliases
    report = doctor_detectors()
    assert report.passed
    assert report.to_dict()["side_effect_free"] is True
    assert any(check.check == "fixture_claim_boundary" for check in report.checks)
