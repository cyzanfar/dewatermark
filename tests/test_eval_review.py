import os

import pytest
from review import (
    RATING_DIMENSIONS,
    ReviewValidationError,
    create_blinded_review_packet,
    summarize_blinded_reviews,
    write_private_review_artifact,
)


def _protocol():
    return {
        "protocol_id": "review-v1",
        "eligibility_rule_sha256": "a" * 64,
        "exclusion_rule_sha256": "b" * 64,
        "rating_scale": {"minimum": 1, "maximum": 5},
        "pre_registered": True,
    }


def _pairs():
    return [
        {
            "sample_id": f"sample-{index}",
            "method_id": "fixture-method",
            "source_text": f"Source {index}",
            "candidate_text": f"Candidate {index}",
        }
        for index in range(4)
    ]


def test_packet_requires_consent_and_separates_method_key_from_blinded_text():
    with pytest.raises(ReviewValidationError, match="explicit"):
        create_blinded_review_packet(_pairs(), review_protocol=_protocol(), seed=7)
    packet, key = create_blinded_review_packet(
        _pairs(), review_protocol=_protocol(), seed=7, allow_text_artifacts=True
    )
    assert (
        packet
        == create_blinded_review_packet(
            _pairs(), review_protocol=_protocol(), seed=7, allow_text_artifacts=True
        )[0]
    )
    assert "method" not in str(packet)
    assert "sample-" not in str(packet)
    assert all("text_a" in item and "text_b" in item for item in packet["items"])
    assert all("method_id" in item for item in key["items"])


def test_private_review_writer_is_owner_only_and_non_overwriting(tmp_path):
    packet, _key = create_blinded_review_packet(
        _pairs(), review_protocol=_protocol(), seed=7, allow_text_artifacts=True
    )
    path = tmp_path / "review.json"
    write_private_review_artifact(path, packet)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ReviewValidationError, match="overwrite"):
        write_private_review_artifact(path, packet)


def test_review_summary_is_blinded_content_free_and_cluster_bootstrapped():
    packet, key = create_blinded_review_packet(
        _pairs(), review_protocol=_protocol(), seed=11, allow_text_artifacts=True
    )
    responses = []
    for reviewer, offset in (("reviewer-a", 0), ("reviewer-b", 1)):
        for item in packet["items"]:
            responses.append(
                {
                    "assignment_id": item["assignment_id"],
                    "reviewer_id": reviewer,
                    "ratings": {dimension: 4 - offset for dimension in RATING_DIMENSIONS},
                }
            )
    result = summarize_blinded_reviews(
        packet, key, responses, bootstrap_replicates=50, bootstrap_seed=3
    )
    manifest = result["human_review_manifest"]
    assert manifest["state"] == "complete"
    assert manifest["reviewer_count"] == 2
    assert manifest["agreement"]["metric"] == "krippendorff_alpha"
    assert result["bootstrap"]["unit"] == "assignment"
    assert "Source" not in str(result)
    assert "Candidate" not in str(result)
