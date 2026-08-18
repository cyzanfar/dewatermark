import os

from evidence import read_bundle, replay_bundle
from jsonschema import Draft202012Validator
from reference_run import write_reference_protocol_run


def test_reference_protocol_run_is_deterministic_offline_and_replayable(tmp_path):
    first = write_reference_protocol_run(tmp_path / "first")
    second = write_reference_protocol_run(tmp_path / "second")
    assert first["bundle_id"] == second["bundle_id"]
    assert first["observation_set_id"] == second["observation_set_id"]
    assert first["aggregate_sha256"] == second["aggregate_sha256"]
    bundle = read_bundle(tmp_path / "first" / "evidence.json")
    import json

    import dewatermark

    schema = dewatermark.benchmark_sample_registry_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(
        json.loads((tmp_path / "first" / "sample-registry.json").read_text(encoding="utf-8"))
    )
    assert bundle["purpose"] == "harness_conformance"
    assert bundle["claim_eligibility"]["comparative_performance_eligible"] is False
    plan = replay_bundle(bundle, workspace=tmp_path)
    assert plan["executed"] is False
    assert plan["recipe_available"] is True
    assert "argv" not in plan
    assert str(tmp_path) not in str(plan)


def test_builtin_reference_recipe_executes_from_a_fresh_workspace(tmp_path, monkeypatch):
    write_reference_protocol_run(tmp_path / "source")
    bundle = read_bundle(tmp_path / "source" / "evidence.json")
    # Built-ins resolve to the currently loaded package, not an ambient binary.
    monkeypatch.setenv("PATH", os.defpath)
    fresh_workspace = tmp_path / "fresh-workspace"
    result = replay_bundle(bundle, workspace=fresh_workspace, execute=True)
    assert result["executed"] is True
    assert result["reproduced_bundle_id"] == bundle["bundle_id"]
    assert (fresh_workspace / "reproduced" / "evidence.json").is_file()
