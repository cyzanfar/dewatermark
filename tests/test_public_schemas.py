from jsonschema import Draft202012Validator

import dewatermark


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
