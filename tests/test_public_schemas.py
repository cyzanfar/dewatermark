import copy
import hashlib

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


def test_all_benchmark_execution_schemas_are_packaged_and_valid():
    functions = {
        "benchmark-comparator-registry": dewatermark.benchmark_comparator_registry_schema,
        "benchmark-protocol-manifest": dewatermark.benchmark_protocol_manifest_schema,
        "benchmark-run-config": dewatermark.benchmark_run_config_schema,
        "benchmark-input-corpus": dewatermark.benchmark_input_corpus_schema,
    }
    for name, function in functions.items():
        schema = function()
        Draft202012Validator.check_schema(schema)
        assert schema == dewatermark.public_schema(name)


def test_builtin_detector_capability_validates_against_public_schema():
    capability = dewatermark.detector_manifest("unicode")
    assert capability is not None
    _validate(dewatermark.detector_capability_schema(), capability.to_dict())


def test_localization_and_mitigation_results_validate_against_public_schemas():
    class Detector:
        def __init__(self, identifier):
            self.capability = dewatermark.CapabilityManifest(
                identifier=identifier,
                kind="detector",
                schemes=("schema-fixture",),
                calibrated=True,
                independent=True,
                metadata={
                    "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
                    "resource_accounting": "none",
                    "score_direction": "higher",
                    "threshold": 2.0,
                    "threshold_operator": ">=",
                    "watermark_target_sha256": "c" * 64,
                },
            )

        def available(self):
            return True

        def detect(self, text):
            score = float(text.count("blue"))
            return {
                "scheme": "schema-fixture",
                "status": "detected" if score >= 2 else "not_detected",
                "score": score,
                "threshold": 2.0,
                "score_direction": "higher",
                "threshold_operator": ">=",
                "configuration_sha256": self.capability.metadata["configuration_sha256"],
                "p_value": 0.001 if score >= 2 else 0.8,
            }

    class Strategy:
        capability = dewatermark.CapabilityManifest(
            identifier="schema-strategy",
            kind="transformer",
            metadata={"resource_accounting": "none"},
        )

        def available(self):
            return True

        def generate(self, text, *, context, **_options):
            return [text.replace("blue", "teal", 2)]

    class Verifier(Detector):
        def detect(self, text):
            return super().detect(text)

    source = "alpha blue beta blue gamma blue delta epsilon zeta eta theta"
    primary = Detector("schema-primary")
    verifier = Verifier("schema-verifier")
    localization = dewatermark.localize(
        source,
        dewatermark.DetectorSession(primary, max_queries=8),
        window_characters=48,
        stride_characters=24,
    )
    mitigation = dewatermark.mitigate(
        source,
        primary,
        [Strategy()],
        verifier_detectors=[verifier],
    )

    localized = localization.to_dict()
    _validate(dewatermark.localization_result_schema(), localized)
    impossible_localization = copy.deepcopy(localized)
    impossible_localization["status"] = "localized"
    impossible_localization["spans"] = []
    assert not Draft202012Validator(dewatermark.localization_result_schema()).is_valid(
        impossible_localization
    )
    serialized = mitigation.to_dict()
    _validate(dewatermark.mitigation_result_schema(), serialized)

    missing_text = copy.deepcopy(serialized)
    missing_text.pop("cleaned_text")
    assert list(
        Draft202012Validator(dewatermark.mitigation_result_schema()).iter_errors(missing_text)
    )

    impossible = copy.deepcopy(serialized)
    impossible["changed"] = False
    assert list(
        Draft202012Validator(dewatermark.mitigation_result_schema()).iter_errors(impossible)
    )

    forged = copy.deepcopy(serialized)
    forged["receipt"]["verification"]["verifiers"] = []
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["verification"]["primary_after"]["evidence"]["status"] = "detected"
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["primary_before"].pop("policy_sha256")
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["verification"]["primary_before"]["role"] = "verifier"
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["verification"]["verifiers"][0]["verification"].pop("before")
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["quality"]["passed"] = False
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["status"] = "rolled_back"
    forged["reason_code"] = "verification_inconclusive"
    forged["changed"] = False
    forged["cleaned_text"] = source
    forged["receipt"]["status"] = "rolled_back"
    forged["receipt"]["reason_code"] = "verification_inconclusive"
    forged["receipt"]["changed"] = False
    forged["receipt"]["output_sha256"] = forged["receipt"]["input_sha256"]
    forged["receipt"]["edit_characters"] = 0
    forged["receipt"]["edit_fraction"] = 0
    forged["receipt"].pop("selected_strategy")
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["reason_code"] = "held_out_residual"
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    forged = copy.deepcopy(serialized)
    forged["receipt"]["selected_strategy"] = ""
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(forged)

    openapi_receipt = openapi_schema()["components"]["schemas"]["MitigationResponse"]["properties"][
        "receipt"
    ]
    assert "$ref" in openapi_receipt


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
        "protocol_version": "1.1",
        "action": "detect.result",
        "detector": "fixture",
        "scheme": "fixture-v1",
        "status": "not_detected",
        "score": 0.1,
        "threshold": 1.0,
        "score_direction": "higher",
        "threshold_operator": ">=",
        "effective_tokens": 20,
        "configuration_sha256": configuration,
    }
    _validate(schema, request)
    _validate(schema, response)

    unknown = {**response, "private_debug": "not part of the protocol"}
    _validate(schema, unknown)
    legacy = {key: value for key, value in response.items() if key != "threshold_operator"}
    legacy["protocol_version"] = "1.0"
    legacy["legacy_extension"] = {"adapter": "v0.6-compatible"}
    _validate(schema, legacy)
    # A statically negotiated legacy detector may return a compatible forward
    # minor while retaining its 1.0 inclusive operator default. The standalone
    # response schema cannot see that manifest negotiation, so the echo remains
    # optional just like forward attribution metadata.
    _validate(schema, {**legacy, "protocol_version": "1.3"})
    for legacy_operator in (42, "<"):
        _validate(schema, {**legacy, "threshold_operator": legacy_operator})
    # The response schema is deliberately structural: only the runtime has the
    # static manifest needed to interpret or constrain extension-name echoes.
    _validate(schema, {**response, "threshold_operator": "<"})

    attribution_request = {
        **request,
        "protocol_version": "1.2",
        "attribution": {
            "kind": "token_character_spans",
            "maximum_attributions": 32,
        },
    }
    attribution_response = {
        **response,
        "protocol_version": "1.2",
        "attributions": [{"start": 0, "end": 7, "score": 2.5, "p_value": 0.01, "threshold": 1.0}],
    }
    _validate(schema, attribution_request)
    _validate(schema, attribution_response)
    assert not Draft202012Validator(schema).is_valid(
        {key: value for key, value in attribution_request.items() if key != "attribution"}
    )
    # A response can advertise a forward same-major minor to a 1.0/1.1
    # request, so the standalone schema cannot know whether attribution was
    # negotiated. The runtime requires it for every bound 1.2 contract.
    _validate(
        schema,
        {key: value for key, value in attribution_response.items() if key != "attributions"},
    )
    _validate(
        schema,
        {
            **attribution_response,
            "attributions": [{"start": 0, "end": 7, "score": 2.5, "text": "private text"}],
        },
    )
    assert not Draft202012Validator(schema).is_valid(
        {**attribution_request, "attribution": {"kind": "token_character_spans"}}
    )
    # Before 1.2, the new names remain unknown extension data and are ignored.
    _validate(schema, {**response, "attributions": {"text": "legacy extension"}})
    # Forward-minor labels can collide with extension names from an older
    # negotiated manifest. Published v1 accepted these values; runtime context,
    # not the standalone schema, decides whether they form a bound contract.
    _validate(
        schema,
        {
            **legacy,
            "protocol_version": "1.2",
            "threshold_operator": 42,
            "attributions": {"legacy": True},
        },
    )


def test_v1_detector_capability_remains_compatible_with_pre_07_manifests():
    base = {
        "identifier": "legacy-independent-detector",
        "kind": "detector",
        "version": "1",
        "schemes": ["legacy-scheme"],
        "description": "v0.6-compatible detector capability",
        "network_required": False,
        "model_download_possible": False,
        "requires_secret": False,
        "minimum_characters": 0,
        "calibrated": True,
        "independent": True,
    }

    for metadata in (
        {"score_direction": "higher"},
        {"threshold_operator": ">="},
        {"threshold_operator": 42},
        {"configuration_sha256": "legacy-extension-value"},
        {"implementation_sha256": "legacy-extension-value"},
        {"secret_binding": "operator_managed_file"},
    ):
        _validate(dewatermark.detector_capability_schema(), {**base, "metadata": metadata})


def test_command_strategy_request_and_response_validate_against_protocol_schema():
    schema = dewatermark.command_strategy_schema()
    configuration = "b" * 64
    context = {
        "round_index": 0,
        "invocation_index": 1,
        "random_seed": 7,
        "candidate_limit": 2,
        "detector_feedback": {
            "detector": "fixture-primary",
            "status": "detected",
            "score": 4.0,
            "threshold": 2.0,
            "p_value": 0.001,
            "detection_margin": 2.0,
            "localization": [{"start": 2, "end": 8}],
        },
        "source_localization": [{"start": 2, "end": 8}],
    }
    request = {
        "protocol_version": "1.0",
        "action": "generate",
        "strategy": "fixture-strategy",
        "configuration_sha256": configuration,
        "policy": {
            "allow_network": False,
            "allow_model_download": False,
            "max_candidates": 2,
            "max_candidate_characters": 1000,
            "max_aggregate_candidate_characters": 2000,
            "max_output_tokens": 500,
        },
        "context": context,
        "text": "private text",
    }
    response = {
        "protocol_version": "1.0",
        "action": "generate.result",
        "strategy": "fixture-strategy",
        "configuration_sha256": configuration,
        "candidates": ["candidate one", "candidate two"],
    }
    _validate(schema, request)
    _validate(schema, response)

    oversized = copy.deepcopy(request)
    oversized["policy"]["max_candidates"] = 1001
    assert not Draft202012Validator(schema).is_valid(oversized)

    oversized = copy.deepcopy(request)
    oversized["context"]["random_seed"] = 1 << 63
    assert not Draft202012Validator(schema).is_valid(oversized)


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
