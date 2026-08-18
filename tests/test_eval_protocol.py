import hashlib
from collections.abc import Mapping
from types import SimpleNamespace

import protocol as protocol_module
import pytest
from protocol import (
    ProtocolValidationError,
    human_control_records,
    length_bin_for,
    load_protocol_registry,
    registry_sha256,
    required_length_sweep,
    validate_sample_registry,
)


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _sample(identifier, *, split, task, language, tokens, cohort, key, paired=None):
    protocol = load_protocol_registry()
    task_entry = next(value for value in protocol["tasks"] if value["id"] == task)
    metadata = {}
    if cohort in {"watermarked_positive", "matched_generator_null"}:
        metadata = {
            "generator_id": "fixture-generator@immutable-revision",
            "decoding_config_sha256": _digest("decoding-v1"),
        }
        if paired is not None:
            metadata["paired_sample_id"] = paired
    else:
        metadata = {
            "content_sha256": _digest(identifier),
            "license_id": "CC0-1.0",
            "source_date": "2025-01-02",
            "domain": "fixture-domain",
            "selection_rule_sha256": _digest("selection-v1"),
            "matching_rule_sha256": _digest("matching-v1"),
            "contamination_risk": "not_assessed_synthetic_fixture",
            "memorization_risk": "not_assessed_synthetic_fixture",
            "generator_exposed": False,
            "rewriter_exposed": False,
        }
    return {
        "sample_id": identifier,
        "cluster_id": identifier.rsplit("-", 1)[0],
        "split": split,
        "task": task,
        "language": language,
        "cohort": cohort,
        "input_sha256": _digest(identifier),
        "effective_detector_tokens": tokens,
        "length_bin": length_bin_for(tokens),
        "key_fingerprint": key,
        "task_checkers": task_entry["required_checker_kinds"],
        "metadata": metadata,
    }


def _complete_registry():
    protocol = load_protocol_registry()
    samples = []
    # Populate tuning partitions without sharing a prompt/document cluster.
    for split, key in (
        ("calibration", _digest("key-cal")),
        ("development", _digest("key-dev")),
    ):
        positive_id = f"{split}-fixture-positive"
        samples.append(
            _sample(
                positive_id,
                split=split,
                task="open_ended_prose",
                language="en",
                tokens=32,
                cohort="watermarked_positive",
                key=key,
            )
        )
        samples.append(
            _sample(
                f"{split}-fixture-null",
                split=split,
                task="open_ended_prose",
                language="en",
                tokens=32,
                cohort="matched_generator_null",
                key=key,
                paired=positive_id,
            )
        )
        # Paired rows share a cluster by definition.
        samples[-1]["cluster_id"] = samples[-2]["cluster_id"]

    representatives = [32, 96, 192, 384, 640]
    for task in [value["id"] for value in protocol["tasks"]]:
        for language in [value["id"] for value in protocol["languages"]]:
            for tokens in representatives:
                stem = f"final-{task}-{language}-{tokens}"
                positive_id = f"{stem}-positive"
                samples.append(
                    _sample(
                        positive_id,
                        split="final_test",
                        task=task,
                        language=language,
                        tokens=tokens,
                        cohort="watermarked_positive",
                        key=_digest("key-final"),
                    )
                )
                samples.append(
                    _sample(
                        f"{stem}-null",
                        split="final_test",
                        task=task,
                        language=language,
                        tokens=tokens,
                        cohort="matched_generator_null",
                        key=_digest("key-final"),
                        paired=positive_id,
                    )
                )
                samples.append(
                    _sample(
                        f"{stem}-human",
                        split="final_test",
                        task=task,
                        language=language,
                        tokens=tokens,
                        cohort="human_control",
                        key=None,
                    )
                )
                samples[-2]["cluster_id"] = samples[-3]["cluster_id"]
    return {
        "schema_version": "1.0",
        "protocol_registry_sha256": registry_sha256(protocol),
        "frozen_before_final_test": True,
        "freeze_record_sha256": _digest("freeze-v1"),
        "key_partitions": [
            {"key_fingerprint": _digest("key-cal"), "split": "calibration"},
            {"key_fingerprint": _digest("key-dev"), "split": "development"},
            {"key_fingerprint": _digest("key-final"), "split": "final_test"},
        ],
        "samples": samples,
    }


def test_protocol_registry_enforces_full_task_language_length_control_matrix():
    report = validate_sample_registry(_complete_registry())
    assert report["valid"] is True
    assert report["registry_complete"] is True
    assert report["human_control_count"] == 7 * 6 * 5
    for area in (
        "independent_splits",
        "matched_controls",
        "held_out_keys",
        "length_coverage",
        "task_coverage",
        "language_coverage",
    ):
        assert report["coverage"][area]["state"] == "complete"
    assert report["coverage"]["detector_statistics"]["state"] == "not_run"


def test_registry_rejects_raw_text_and_cross_split_cluster_leakage():
    value = _complete_registry()
    value["samples"][0]["text"] = "must not be published"
    with pytest.raises(ProtocolValidationError, match="text or credentials"):
        validate_sample_registry(value)

    value = _complete_registry()
    value["samples"][0]["metadata"]["input"] = "must not be published"
    with pytest.raises(ProtocolValidationError, match="text or credentials"):
        validate_sample_registry(value)

    value = _complete_registry()
    value["samples"][-1]["cluster_id"] = value["samples"][0]["cluster_id"]
    with pytest.raises(ProtocolValidationError, match="cross split"):
        validate_sample_registry(value)


def test_registry_requires_digest_key_fingerprints():
    value = _complete_registry()
    raw_key = "looks-public-but-could-be-a-secret"
    value["key_partitions"][0]["key_fingerprint"] = raw_key
    value["samples"][0]["key_fingerprint"] = raw_key
    value["samples"][1]["key_fingerprint"] = raw_key
    with pytest.raises(ProtocolValidationError, match="lowercase SHA-256"):
        validate_sample_registry(value)


def test_registry_rejects_hook_bearing_mapping_without_reflecting_it():
    secret = "PRIVATE-REGISTRY-HOOK"

    class HostileMapping(Mapping):
        def __getitem__(self, _key):
            raise AssertionError(secret)

        def __iter__(self):
            raise AssertionError(secret)

        def __len__(self):
            raise AssertionError(secret)

        def __str__(self):
            raise AssertionError(secret)

        def __repr__(self):
            raise AssertionError(secret)

    with pytest.raises(ProtocolValidationError, match="plain JSON") as captured:
        validate_sample_registry(HostileMapping())
    assert secret not in str(captured.value)


def test_registry_read_remains_bounded_if_file_grows_after_metadata_check(tmp_path, monkeypatch):
    path = tmp_path / "registry.json"
    monkeypatch.setattr(protocol_module, "MAX_REGISTRY_BYTES", 64)
    path.write_bytes(b"{" + b"x" * 64)
    real_fstat = protocol_module.os.fstat

    def stale_small_size(descriptor):
        info = real_fstat(descriptor)
        return SimpleNamespace(st_mode=info.st_mode, st_size=1)

    monkeypatch.setattr(protocol_module.os, "fstat", stale_small_size)
    with pytest.raises(ProtocolValidationError, match="size limit"):
        load_protocol_registry(path)


def test_matched_null_must_bind_the_same_generator_configuration():
    value = _complete_registry()
    null = next(item for item in value["samples"] if item["cohort"] == "matched_generator_null")
    null["metadata"]["decoding_config_sha256"] = _digest("different")
    with pytest.raises(ProtocolValidationError, match="decoding_config_sha256"):
        validate_sample_registry(value)


def test_human_inputs_are_hashed_and_text_is_separate_by_explicit_opt_in():
    control = {
        "id": "human-1",
        "cluster_id": "human-cluster-1",
        "text": "Locally supplied human-authored fixture.",
        "task": "open_ended_prose",
        "language": "en",
        "domain": "fixture",
        "license_id": "CC0-1.0",
        "source_date": "2025-01-02",
        "effective_detector_tokens": 32,
        "task_checkers": ["semantic", "factual", "protected_span"],
        "contamination_risk": "not_assessed_synthetic_fixture",
        "memorization_risk": "not_assessed_synthetic_fixture",
    }
    records, texts = human_control_records(
        [control],
        split="final_test",
        selection_rule_sha256=_digest("selection"),
        matching_rule_sha256=_digest("matching"),
    )
    assert texts == []
    assert "text" not in str(records)
    assert records[0]["metadata"]["generator_exposed"] is False

    _records, texts = human_control_records(
        [control],
        split="final_test",
        selection_rule_sha256=_digest("selection"),
        matching_rule_sha256=_digest("matching"),
        include_runtime_text=True,
    )
    assert texts == [control["text"]]


def test_required_length_sweep_touches_all_bins_without_zero_length():
    sweep = required_length_sweep()
    assert min(sweep) >= 1
    assert {length_bin_for(value) for value in sweep} == {
        "lt64",
        "64_127",
        "128_255",
        "256_511",
        "512_plus",
    }
