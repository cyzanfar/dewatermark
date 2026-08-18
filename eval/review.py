"""Local-only blinded review packets and deterministic agreement reporting."""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from .manifest import canonical_json, json_safe
except ImportError:  # direct-script compatibility
    from manifest import canonical_json, json_safe  # type: ignore

REVIEW_PACKET_SCHEMA_VERSION = "1.0"
RATING_DIMENSIONS = ("semantic", "factual", "fluency", "formatting")


class ReviewValidationError(ValueError):
    """A review packet or response set violates the blinded protocol."""


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def create_blinded_review_packet(
    pairs: Sequence[Mapping[str, Any]],
    *,
    review_protocol: Mapping[str, Any],
    seed: int,
    allow_text_artifacts: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Randomize A/B order and separate private texts from the method key.

    Packet creation is denied unless the caller explicitly opts into local text
    artifacts. This function performs no network I/O and imports no plugin code.
    """
    if not allow_text_artifacts:
        raise ReviewValidationError(
            "blinded packet creation requires explicit allow_text_artifacts consent"
        )
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ReviewValidationError("review seed must be a non-negative integer")
    if not isinstance(review_protocol, Mapping):
        raise ReviewValidationError("review_protocol must be an object")
    required_protocol = {
        "protocol_id",
        "eligibility_rule_sha256",
        "exclusion_rule_sha256",
        "rating_scale",
        "pre_registered",
    }
    if (
        set(review_protocol) != required_protocol
        or review_protocol.get("pre_registered") is not True
    ):
        raise ReviewValidationError("review protocol must be complete and pre-registered")
    if review_protocol.get("rating_scale") != {"minimum": 1, "maximum": 5}:
        raise ReviewValidationError("review rating scale must be the registered 1-5 scale")
    rng = random.Random(seed)
    packet_items: list[dict[str, Any]] = []
    key_items: list[dict[str, Any]] = []
    seen_samples: set[str] = set()
    for index, pair in enumerate(pairs):
        if not isinstance(pair, Mapping) or set(pair) != {
            "sample_id",
            "method_id",
            "source_text",
            "candidate_text",
        }:
            raise ReviewValidationError(f"review pair {index} fields are incomplete")
        sample_id = pair.get("sample_id")
        method_id = pair.get("method_id")
        source = pair.get("source_text")
        candidate = pair.get("candidate_text")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen_samples:
            raise ReviewValidationError("review sample ids must be unique non-empty strings")
        seen_samples.add(sample_id)
        if not isinstance(method_id, str) or not method_id:
            raise ReviewValidationError(f"review pair {index} requires a method id")
        if not isinstance(source, str) or not isinstance(candidate, str):
            raise ReviewValidationError(f"review pair {index} requires two strings")
        assignment_id = hashlib.sha256(f"{seed}\0{sample_id}\0{index}".encode("utf-8")).hexdigest()[
            :24
        ]
        source_is_a = bool(rng.getrandbits(1))
        packet_items.append(
            {
                "assignment_id": assignment_id,
                "text_a": source if source_is_a else candidate,
                "text_b": candidate if source_is_a else source,
                "rating_dimensions": list(RATING_DIMENSIONS),
            }
        )
        key_items.append(
            {
                "assignment_id": assignment_id,
                "sample_id": sample_id,
                "method_id": method_id,
                "source_slot": "a" if source_is_a else "b",
            }
        )
    rng.shuffle(packet_items)
    protocol_sha256 = _sha256(review_protocol)
    packet: dict[str, Any] = {
        "schema_version": REVIEW_PACKET_SCHEMA_VERSION,
        "packet_type": "private_blinded_text_review",
        "protocol_sha256": protocol_sha256,
        "pre_registered": True,
        "items": packet_items,
    }
    packet["packet_id"] = _sha256(packet)
    key: dict[str, Any] = {
        "schema_version": REVIEW_PACKET_SCHEMA_VERSION,
        "key_type": "private_review_assignment_key",
        "packet_id": packet["packet_id"],
        "items": key_items,
    }
    key["assignment_sha256"] = _sha256(key)
    return packet, key


def write_private_review_artifact(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically write a non-overwriting, owner-readable local review file."""
    if path.exists():
        raise ReviewValidationError("review artifact already exists; refusing to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(json_safe(value), handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _krippendorff_interval_alpha(groups: Sequence[Sequence[int]]) -> float:
    observed_terms: list[float] = []
    all_ratings: list[int] = []
    for ratings in groups:
        all_ratings.extend(ratings)
        for left in range(len(ratings)):
            for right in range(left + 1, len(ratings)):
                observed_terms.append(float((ratings[left] - ratings[right]) ** 2))
    if not observed_terms or len(all_ratings) < 2:
        return float("nan")
    expected_terms = [
        float((all_ratings[left] - all_ratings[right]) ** 2)
        for left in range(len(all_ratings))
        for right in range(left + 1, len(all_ratings))
    ]
    observed = sum(observed_terms) / len(observed_terms)
    expected = sum(expected_terms) / len(expected_terms)
    if expected == 0:
        return 1.0 if observed == 0 else float("nan")
    return max(-1.0, min(1.0, 1.0 - observed / expected))


def _percentile(values: Sequence[float], q: float) -> float:
    finite = sorted(value for value in values if math.isfinite(value))
    if not finite:
        return float("nan")
    index = min(len(finite) - 1, max(0, math.ceil(q * len(finite)) - 1))
    return finite[index]


def summarize_blinded_reviews(
    packet: Mapping[str, Any],
    assignment_key: Mapping[str, Any],
    responses: Sequence[Mapping[str, Any]],
    *,
    bootstrap_replicates: int = 500,
    bootstrap_seed: int = 0,
) -> dict[str, Any]:
    """Validate blinded ratings and report interval agreement by assignment."""
    if packet.get("packet_id") != _sha256(
        {key: item for key, item in packet.items() if key != "packet_id"}
    ):
        raise ReviewValidationError("review packet content digest mismatch")
    if assignment_key.get("assignment_sha256") != _sha256(
        {key: item for key, item in assignment_key.items() if key != "assignment_sha256"}
    ):
        raise ReviewValidationError("assignment key content digest mismatch")
    if assignment_key.get("packet_id") != packet.get("packet_id"):
        raise ReviewValidationError("assignment key belongs to another packet")
    assignments = {str(item["assignment_id"]) for item in packet.get("items", [])}
    ratings: dict[str, dict[str, list[int]]] = {
        dimension: defaultdict(list) for dimension in RATING_DIMENSIONS
    }
    reviewers: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for index, response in enumerate(responses):
        if not isinstance(response, Mapping) or set(response) != {
            "assignment_id",
            "reviewer_id",
            "ratings",
        }:
            raise ReviewValidationError(f"response {index} fields are incomplete")
        assignment_id = response.get("assignment_id")
        reviewer_id = response.get("reviewer_id")
        if assignment_id not in assignments or not isinstance(reviewer_id, str) or not reviewer_id:
            raise ReviewValidationError(
                f"response {index} references an unknown assignment/reviewer"
            )
        unique = (str(assignment_id), reviewer_id)
        if unique in seen:
            raise ReviewValidationError("a reviewer may rate an assignment only once")
        seen.add(unique)
        reviewers.add(reviewer_id)
        values = response.get("ratings")
        if not isinstance(values, Mapping) or set(values) != set(RATING_DIMENSIONS):
            raise ReviewValidationError(f"response {index} rating dimensions are incomplete")
        for dimension in RATING_DIMENSIONS:
            rating = values[dimension]
            if not isinstance(rating, int) or isinstance(rating, bool) or not 1 <= rating <= 5:
                raise ReviewValidationError(f"response {index} rating is outside 1-5")
            ratings[dimension][str(assignment_id)].append(rating)
    if len(reviewers) < 2:
        raise ReviewValidationError("agreement reporting requires at least two reviewers")
    if any(
        len(ratings[dimension].get(assignment, [])) < 2
        for dimension in RATING_DIMENSIONS
        for assignment in assignments
    ):
        raise ReviewValidationError("every assignment requires at least two ratings per dimension")
    assignment_order = sorted(assignments)
    by_dimension = {
        dimension: _krippendorff_interval_alpha(
            [ratings[dimension][assignment] for assignment in assignment_order]
        )
        for dimension in RATING_DIMENSIONS
    }
    rng = random.Random(bootstrap_seed)
    bootstrap_values: list[float] = []
    if bootstrap_replicates >= 2:
        for _ in range(bootstrap_replicates):
            chosen = [
                assignment_order[rng.randrange(len(assignment_order))] for _ in assignment_order
            ]
            values = [
                _krippendorff_interval_alpha(
                    [ratings[dimension][assignment] for assignment in chosen]
                )
                for dimension in RATING_DIMENSIONS
            ]
            finite = [value for value in values if math.isfinite(value)]
            if finite:
                bootstrap_values.append(sum(finite) / len(finite))
    finite_agreements = [value for value in by_dimension.values() if math.isfinite(value)]
    summary_value = (
        sum(finite_agreements) / len(finite_agreements) if finite_agreements else float("nan")
    )
    interval = [_percentile(bootstrap_values, 0.025), _percentile(bootstrap_values, 0.975)]
    manifest = {
        "state": "complete",
        "packet_sha256": str(packet["packet_id"]),
        "assignment_sha256": str(assignment_key["assignment_sha256"]),
        "protocol_sha256": str(packet["protocol_sha256"]),
        "reviewer_count": len(reviewers),
        "blinded": True,
        "pre_registered": True,
        "agreement": {
            "metric": "krippendorff_alpha",
            "value": summary_value,
            "ci95": interval,
        },
    }
    return {
        "schema_version": "1.0",
        "classification": "blinded_human_review_aggregate_no_text",
        "human_review_manifest": manifest,
        "agreement_by_dimension": by_dimension,
        "assignments": len(assignments),
        "reviewers": len(reviewers),
        "responses": len(responses),
        "bootstrap": {
            "unit": "assignment",
            "replicates": bootstrap_replicates,
            "seed": bootstrap_seed,
        },
    }
