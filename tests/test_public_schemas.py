import copy

from jsonschema import Draft202012Validator

import dewatermark
from dewatermark.server import openapi_schema


def _validate(schema, value):
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)


def test_removal_and_receipt_examples_validate_against_packaged_schemas():
    result = dewatermark.remove(
        "he\u200bllo",
        mode="sanitize",
        config=dewatermark.DewatermarkConfig(local_lm_enabled=False),
    )
    assert result.receipt is not None
    serialized = result.to_dict()
    assert serialized["receipt"] == result.receipt.to_dict()
    _validate(dewatermark.removal_result_schema(), serialized)
    _validate(dewatermark.evidence_receipt_schema(), result.receipt.to_dict())


def test_packaged_openapi_document_matches_server_contract():
    assert dewatermark.openapi_document() == openapi_schema()
    assert dewatermark.public_schema("openapi") == openapi_schema()


def test_builtin_detector_capability_validates_against_public_schema():
    capability = dewatermark.detector_manifest("unicode")
    assert capability is not None
    _validate(dewatermark.detector_capability_schema(), capability.to_dict())


def test_command_detector_request_and_response_validate_against_protocol_schema():
    schema = dewatermark.command_detector_schema()
    configuration = "a" * 64
    request = {
        "protocol_version": "1.0",
        "action": "detect",
        "detector": "fixture",
        "configuration_sha256": configuration,
        "policy": {"allow_network": False, "allow_model_download": False},
        "text": "private text",
    }
    response = {
        "protocol_version": "1.0",
        "action": "detect.result",
        "detector": "fixture",
        "scheme": "fixture-v1",
        "status": "not_detected",
        "score": 0.1,
        "threshold": 1.0,
        "score_direction": "higher",
        "effective_tokens": 20,
        "configuration_sha256": configuration,
    }
    _validate(schema, request)
    _validate(schema, response)


def test_reference_benchmark_artifacts_validate_against_all_public_schemas():
    from evidence import create_reference_bundle, create_replication_record
    from reference_run import reference_observation_set, reference_sample_registry

    samples = reference_sample_registry()
    observations = reference_observation_set(samples)
    bundle = create_reference_bundle()
    replication = create_replication_record(
        source_bundle_id=bundle["bundle_id"],
        reproduced_bundle_id=bundle["bundle_id"],
        operator_id="fixture-independent-operator",
        organization="fixture-independent-lab",
        relationship="independent",
        disclosure="Synthetic schema fixture; no performance claim.",
        executed_at="2026-08-17T12:00:00Z",
        environment_sha256="1" * 64,
        command_sha256="2" * 64,
        outcome="exact_match",
    )
    for schema, value in (
        (dewatermark.benchmark_sample_registry_schema(), samples),
        (dewatermark.benchmark_observation_set_schema(), observations),
        (dewatermark.benchmark_evidence_bundle_schema(), bundle),
        (dewatermark.benchmark_replication_record_schema(), replication),
    ):
        _validate(schema, value)


def test_benchmark_schemas_reject_nested_extensions_and_public_raw_replay_fields():
    from evidence import create_reference_bundle, create_replication_record
    from reference_run import reference_observation_set, reference_sample_registry

    samples = reference_sample_registry()
    observations = reference_observation_set(samples)
    bundle = create_reference_bundle()
    replication = create_replication_record(
        source_bundle_id=bundle["bundle_id"],
        reproduced_bundle_id=bundle["bundle_id"],
        operator_id="fixture-operator",
        organization="fixture-lab",
        relationship="independent",
        disclosure="Synthetic schema fixture.",
        executed_at="2026-08-17T12:00:00Z",
        environment_sha256="1" * 64,
        command_sha256="2" * 64,
        outcome="exact_match",
    )

    invalid_samples = copy.deepcopy(samples)
    invalid_samples["samples"][0]["metadata"]["unexpected"] = True
    assert not Draft202012Validator(dewatermark.benchmark_sample_registry_schema()).is_valid(
        invalid_samples
    )

    invalid_observations = copy.deepcopy(observations)
    invalid_observations["observations"][0]["telemetry"]["unexpected"] = 1
    assert not Draft202012Validator(dewatermark.benchmark_observation_set_schema()).is_valid(
        invalid_observations
    )

    invalid_bundle = copy.deepcopy(bundle)
    invalid_bundle["reproduction"]["argv"] = ["private-command"]
    assert not Draft202012Validator(dewatermark.benchmark_evidence_bundle_schema()).is_valid(
        invalid_bundle
    )
    invalid_manifest = copy.deepcopy(bundle)
    invalid_manifest["manifest"]["note"] = "raw source prose"
    assert not Draft202012Validator(dewatermark.benchmark_evidence_bundle_schema()).is_valid(
        invalid_manifest
    )
    invalid_results = copy.deepcopy(bundle)
    invalid_results["results"]["verbatim"] = "raw candidate prose"
    assert not Draft202012Validator(dewatermark.benchmark_evidence_bundle_schema()).is_valid(
        invalid_results
    )

    invalid_replication = copy.deepcopy(replication)
    invalid_replication["operator"]["unexpected"] = True
    assert not Draft202012Validator(dewatermark.benchmark_replication_record_schema()).is_valid(
        invalid_replication
    )
