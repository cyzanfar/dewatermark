from resources import resource_snapshot, resource_telemetry, zero_network_telemetry


def test_resource_telemetry_is_explicit_about_measured_and_unknown_values():
    started = resource_snapshot()
    report = resource_telemetry(
        started,
        model_bytes=None,
        remote_queries=0,
        generated_tokens=12,
        estimated_cost_usd=0.0,
        operations={"detect": 2},
    )
    assert report["remote_queries"] == {
        "state": "measured",
        "value": 0,
        "unit": "queries",
    }
    assert report["model_size"]["state"] == "not_available"
    assert report["operation.detect"]["value"] == 2


def test_offline_reference_telemetry_is_deterministic_and_zero_cost():
    first = zero_network_telemetry(operations={"fixture": 1})
    assert first == zero_network_telemetry(operations={"fixture": 1})
    assert first["remote_queries"]["state"] == "declared"
    assert first["estimated_cost"]["value"] == 0.0
