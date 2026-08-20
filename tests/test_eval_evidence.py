import hashlib
import json
import os
from collections.abc import Mapping
from types import SimpleNamespace

import evidence
import pytest
from comparisons import comparator_registry_sha256, load_comparator_registry
from evidence import (
    EvidenceValidationError,
    _validate_public_results,
    artifact_descriptor,
    create_bundle,
    create_reference_bundle,
    create_replication_record,
    main,
    read_bundle,
    replay_bundle,
    reproduction_descriptor,
    results_identity,
    validate_bundle,
    validate_replication_record,
    verified_claim_eligibility,
    write_bundle,
)
from jsonschema import Draft202012Validator
from observations import aggregate_observation_set, finalize_observation_set
from protocol import load_protocol_registry, validate_sample_registry
from public_codes import COVERAGE_COMPLETE_REASON_CODES_BY_AREA
from reference_run import (
    reference_observation_set,
    reference_sample_registry,
    write_reference_protocol_run,
)
from resources import zero_network_telemetry


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _write_public_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation requires POSIX")
def test_bounded_evidence_reader_rejects_fifo_without_blocking(tmp_path):
    path = tmp_path / "evidence.json"
    os.mkfifo(path)

    with pytest.raises(EvidenceValidationError, match="bounded regular file"):
        evidence._read_bounded_file(path, 1024, "not a bounded regular file")


def _write_comparator_bound_reference(directory):
    samples = reference_sample_registry()
    observations = reference_observation_set(samples)
    comparator = load_comparator_registry()
    observations["run_manifest"]["comparator_registry_sha256"] = comparator_registry_sha256(
        comparator
    )
    observations = finalize_observation_set(observations)
    sample_path = directory / "sample-registry.json"
    observation_path = directory / "observations.json"
    comparator_path = directory / "comparator-registry.json"
    _write_public_json(sample_path, samples)
    _write_public_json(observation_path, observations)
    _write_public_json(comparator_path, comparator)
    return sample_path, observation_path, comparator_path


def _write_v070_real_aggregate(directory):
    """Build the real-run 1.1 shape emitted before family binding existed."""
    samples = reference_sample_registry()
    samples.pop("registry_classification")
    for sample in samples["samples"]:
        metadata = sample["metadata"]
        if "generator_id" in metadata:
            metadata["generator_id"] = "operator-reference-generator"
    observations = reference_observation_set(samples)
    manifest = observations["run_manifest"]
    manifest["classification"] = "detector_scoped_real_adapter_benchmark"
    manifest.pop("fixture_sha256")
    assert manifest["aggregation_contract_version"] == "1.1"
    assert "watermark_family" not in manifest
    for index, detector in enumerate(observations["detectors"]):
        detector["manifest"] = {
            "family": "kgw",
            "implementation": f"operator-reference-{index}",
            "implementation_version": "1",
            "independent": True,
            "configuration_sha256": _digest(f"real-config-{index}"),
            "golden_conformance": {"passed": True},
        }
    observations = finalize_observation_set(observations)
    aggregate = aggregate_observation_set(
        observations,
        samples,
        bootstrap_replicates=50,
        bootstrap_seed=0,
    )
    sample_path = directory / "v070-sample-registry.json"
    observation_path = directory / "v070-observations.json"
    _write_public_json(sample_path, samples)
    _write_public_json(observation_path, observations)
    coverage = dict(aggregate["coverage"])
    coverage["artifact_handling"] = {
        "state": "complete",
        "reason": "source_artifacts_bound_by_digest",
    }
    public_results = dict(aggregate)
    public_results["score_tables"] = {
        name: {"sha256": table["sha256"], "records": len(table["records"])}
        for name, table in aggregate["score_tables"].items()
    }
    public_results["aggregate_sha256"] = results_identity(public_results)
    sample_report = validate_sample_registry(samples)
    return create_bundle(
        purpose="exploratory",
        manifest=manifest,
        protocol_coverage=coverage,
        results=public_results,
        resource_telemetry=aggregate["resource_telemetry"],
        reproduction=observations["reproduction"],
        artifacts=[
            artifact_descriptor(sample_path, root=directory),
            artifact_descriptor(observation_path, root=directory),
        ],
        sample_registry_sha256=sample_report["sample_registry_sha256"],
        sample_count=sample_report["sample_count"],
    )


def test_v070_real_aggregate_without_family_remains_verified(tmp_path):
    bundle = _write_v070_real_aggregate(tmp_path)

    report = validate_bundle(bundle, artifact_root=tmp_path)

    assert report["valid"] is True
    assert report["aggregate_verified"] is True


def test_reference_bundle_is_deterministic_content_addressed_and_non_claiming(tmp_path):
    first = create_reference_bundle()
    second = create_reference_bundle()
    assert first == second
    import dewatermark

    schema = dewatermark.benchmark_evidence_bundle_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(first)
    assert first["claim_eligibility"]["comparative_performance_eligible"] is False
    assert "non_claim_purpose:harness_conformance" in first["claim_eligibility"]["reason_codes"]
    path = tmp_path / "evidence.json"
    write_bundle(path, first)
    assert read_bundle(path)["bundle_id"] == first["bundle_id"]
    with pytest.raises(EvidenceValidationError, match="refusing to overwrite"):
        write_bundle(path, first)

    tampered = json.loads(json.dumps(first))
    tampered["results"]["attempted"] = 999
    with pytest.raises(EvidenceValidationError, match="digest mismatch"):
        validate_bundle(tampered, verify_artifacts=False)


def test_verify_cli_accepts_exactly_one_bundle_path(tmp_path, monkeypatch, capsys):
    path = tmp_path / "evidence.json"
    write_bundle(path, create_reference_bundle())
    monkeypatch.setattr("sys.argv", ["dewatermark-evidence", "verify", str(path)])
    main()
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True


def test_evidence_cli_redacts_hostile_validation_details(monkeypatch, capsys):
    secret = "PRIVATE-EVIDENCE-PATH-AND-TOKEN"

    def fail(_path):
        raise EvidenceValidationError(secret)

    monkeypatch.setattr(evidence, "read_bundle", fail)
    monkeypatch.setattr("sys.argv", ["dewatermark-evidence", "verify", secret])
    with pytest.raises(SystemExit):
        main()
    assert secret not in capsys.readouterr().err


def test_public_evidence_serializers_reject_hook_bearing_objects_without_invoking_them():
    secret = "PRIVATE-HOOK-PAYLOAD"

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

        def __deepcopy__(self, _memo):
            raise AssertionError(secret)

    fixture = create_reference_bundle()
    with pytest.raises(EvidenceValidationError, match="plain JSON") as captured:
        create_bundle(
            purpose="exploratory",
            manifest=HostileMapping(),
            protocol_coverage=fixture["protocol_coverage"],
            results={},
            resource_telemetry=fixture["resource_telemetry"],
            reproduction=fixture["reproduction"],
        )
    assert secret not in str(captured.value)


def test_replay_recipe_read_remains_bounded_if_file_grows_after_metadata_check(
    tmp_path, monkeypatch
):
    path = tmp_path / "recipe.json"
    path.write_bytes(b"{" + b"x" * evidence.MAX_REPLAY_RECIPE_BYTES)
    real_fstat = evidence.os.fstat

    def stale_small_size(descriptor):
        info = real_fstat(descriptor)
        return SimpleNamespace(st_mode=info.st_mode, st_size=1)

    monkeypatch.setattr(evidence.os, "fstat", stale_small_size)
    with pytest.raises(EvidenceValidationError, match="bounded regular file"):
        evidence.load_replay_recipe(path)


def test_bundle_refuses_content_credentials_and_omitted_coverage():
    fixture = create_reference_bundle()
    kwargs = {
        "purpose": "exploratory",
        "manifest": fixture["manifest"],
        "protocol_coverage": fixture["protocol_coverage"],
        "results": {"source_text": "private"},
        "resource_telemetry": fixture["resource_telemetry"],
        "reproduction": fixture["reproduction"],
    }
    with pytest.raises(EvidenceValidationError, match="text or credentials"):
        create_bundle(**kwargs)

    kwargs["results"] = {"output": "private"}
    with pytest.raises(EvidenceValidationError, match="text or credentials"):
        create_bundle(**kwargs)

    kwargs["results"] = {}
    kwargs["protocol_coverage"] = dict(fixture["protocol_coverage"])
    kwargs["protocol_coverage"].pop("held_out_keys")
    with pytest.raises(ValueError, match="omits"):
        create_bundle(**kwargs)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("note", "raw source prose under a benign-looking field", "unregistered field"),
        ("run_id", "sk-live-DEMO-private-credential", "private-looking value"),
        (
            "classification",
            "xoxb-" + "123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            "private-looking value",
        ),
        (
            "classification",
            "eyJabcdefghijk.abcdefghijk.abcdefghijk",
            "private-looking value",
        ),
    ],
)
def test_bundle_manifest_rejects_unregistered_fields_and_private_values(field, value, message):
    fixture = create_reference_bundle()
    with pytest.raises(EvidenceValidationError, match=message):
        create_bundle(
            purpose="exploratory",
            manifest={field: value},
            protocol_coverage=fixture["protocol_coverage"],
            results={},
            resource_telemetry=fixture["resource_telemetry"],
            reproduction=fixture["reproduction"],
        )


def test_bundle_results_use_a_closed_recursive_public_vocabulary():
    fixture = create_reference_bundle()
    for results in (
        {"verbatim": "raw source prose"},
        {"groups": {"public-group": {"note": "raw source prose"}}},
    ):
        with pytest.raises(EvidenceValidationError, match="unregistered field|public v1 contract"):
            create_bundle(
                purpose="exploratory",
                manifest=fixture["manifest"],
                protocol_coverage=fixture["protocol_coverage"],
                results=results,
                resource_telemetry=fixture["resource_telemetry"],
                reproduction=fixture["reproduction"],
            )


@pytest.mark.parametrize(
    "comparative",
    (
        {},
        {
            "method": "holm_bonferroni_exact_mcnemar",
            "alpha": -999,
            "tested_hypotheses": -5,
        },
    ),
)
def test_public_results_reject_malformed_or_unsupported_comparative_analysis(comparative):
    with pytest.raises(EvidenceValidationError, match="comparative analysis"):
        _validate_public_results({"comparative_analysis": comparative})


def test_public_results_bind_the_aggregate_identity_to_exact_content():
    results = {"classification": "synthetic_fixture", "failures": 0}
    results["aggregate_sha256"] = results_identity(results)
    _validate_public_results(results)
    results["failures"] = 1
    with pytest.raises(EvidenceValidationError, match="aggregate content digest"):
        _validate_public_results(results)


def test_artifact_digest_and_path_are_verified(tmp_path):
    aggregate = tmp_path / "aggregate.json"
    aggregate.write_text('{"aggregate":true}\n', encoding="utf-8")
    descriptor = artifact_descriptor(aggregate, root=tmp_path)
    fixture = create_reference_bundle()
    bundle = create_bundle(
        purpose="exploratory",
        manifest=fixture["manifest"],
        protocol_coverage=fixture["protocol_coverage"],
        results={},
        resource_telemetry=fixture["resource_telemetry"],
        reproduction=fixture["reproduction"],
        artifacts=[descriptor],
    )
    validate_bundle(bundle, artifact_root=tmp_path)
    aggregate.write_text('{"aggregate":false}\n', encoding="utf-8")
    with pytest.raises(EvidenceValidationError, match="digest mismatch"):
        validate_bundle(bundle, artifact_root=tmp_path)

    private = tmp_path / "private.json"
    private.write_text('{"source_text":"must-not-publish"}\n', encoding="utf-8")
    with pytest.raises(EvidenceValidationError, match="private-data fields"):
        artifact_descriptor(private, root=tmp_path)

    unregistered = tmp_path / "unregistered.json"
    unregistered.write_text('{"aggregate":true,"note":"raw source prose"}\n', encoding="utf-8")
    with pytest.raises(EvidenceValidationError, match="registered public contract"):
        artifact_descriptor(unregistered, root=tmp_path)


def test_observation_artifact_error_registry_is_strict_only_for_contract_1_1(tmp_path):
    samples = reference_sample_registry()
    observations = reference_observation_set(samples)
    row = observations["observations"][0]
    row.update(
        transformation_state="failed",
        quality_gate_passed=None,
        task_check_passed=None,
        error_class="TimeoutError",
    )
    observations = finalize_observation_set(observations)
    path = tmp_path / "strict-observations.json"
    _write_public_json(path, observations)

    with pytest.raises(EvidenceValidationError, match="registered host code"):
        artifact_descriptor(path, root=tmp_path)

    legacy = dict(observations)
    legacy["run_manifest"] = dict(observations["run_manifest"])
    for field in (
        "aggregation_contract_version",
        "bootstrap_replicates_count",
        "bootstrap_seed_count",
    ):
        legacy["run_manifest"].pop(field)
    legacy = finalize_observation_set(legacy)
    legacy_path = tmp_path / "legacy-observations.json"
    _write_public_json(legacy_path, legacy)

    assert artifact_descriptor(legacy_path, root=tmp_path)["canonical_sha256"]


def test_bundle_rejects_a_disconnected_sample_observation_result_graph(tmp_path):
    write_reference_protocol_run(tmp_path)
    sample_path = tmp_path / "sample-registry.json"
    observation_path = tmp_path / "observations.json"
    bundle = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    sample_registry = json.loads(sample_path.read_text(encoding="utf-8"))

    foreign_registry = json.loads(json.dumps(sample_registry))
    foreign_registry["freeze_record_sha256"] = _digest("foreign-freeze-record")
    foreign_observations = reference_observation_set(foreign_registry)
    observation_path.write_text(
        json.dumps(foreign_observations, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    mixed_results = dict(bundle["results"])
    mixed_results["observation_set_id"] = foreign_observations["observation_set_id"]
    mixed_results["aggregate_sha256"] = results_identity(mixed_results)
    mixed = create_bundle(
        purpose=bundle["purpose"],
        manifest=bundle["manifest"],
        protocol_coverage=bundle["protocol_coverage"],
        results=mixed_results,
        resource_telemetry=bundle["resource_telemetry"],
        reproduction=bundle["reproduction"],
        artifacts=[
            artifact_descriptor(sample_path, root=tmp_path),
            artifact_descriptor(observation_path, root=tmp_path),
        ],
        sample_registry_sha256=bundle["sample_registry"]["sha256"],
        sample_count=bundle["sample_registry"]["sample_count"],
    )
    with pytest.raises(EvidenceValidationError, match="artifact graph is inconsistent"):
        validate_bundle(mixed, artifact_root=tmp_path)


def test_bundle_rejects_forged_result_graph_identities(tmp_path):
    write_reference_protocol_run(tmp_path)
    bundle = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    sample_path = tmp_path / "sample-registry.json"
    observation_path = tmp_path / "observations.json"
    descriptors = [
        artifact_descriptor(sample_path, root=tmp_path),
        artifact_descriptor(observation_path, root=tmp_path),
    ]
    forged_results = dict(bundle["results"])
    forged_results["sample_registry_sha256"] = "f" * 64
    forged_results["aggregate_sha256"] = results_identity(forged_results)
    with pytest.raises(EvidenceValidationError, match="another sample registry"):
        create_bundle(
            purpose=bundle["purpose"],
            manifest=bundle["manifest"],
            protocol_coverage=bundle["protocol_coverage"],
            results=forged_results,
            resource_telemetry=bundle["resource_telemetry"],
            reproduction=bundle["reproduction"],
            artifacts=descriptors,
            sample_registry_sha256=bundle["sample_registry"]["sha256"],
            sample_count=bundle["sample_registry"]["sample_count"],
        )

    forged_results = dict(bundle["results"])
    forged_results["observation_set_id"] = "f" * 64
    forged_results["aggregate_sha256"] = results_identity(forged_results)
    forged = create_bundle(
        purpose=bundle["purpose"],
        manifest=bundle["manifest"],
        protocol_coverage=bundle["protocol_coverage"],
        results=forged_results,
        resource_telemetry=bundle["resource_telemetry"],
        reproduction=bundle["reproduction"],
        artifacts=descriptors,
        sample_registry_sha256=bundle["sample_registry"]["sha256"],
        sample_count=bundle["sample_registry"]["sample_count"],
    )
    with pytest.raises(EvidenceValidationError, match="artifact graph is inconsistent"):
        validate_bundle(forged, artifact_root=tmp_path)


def test_bound_aggregate_is_recomputed_and_coverage_cannot_be_laundered(tmp_path):
    write_reference_protocol_run(tmp_path)
    bundle = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    descriptors = [
        artifact_descriptor(tmp_path / "sample-registry.json", root=tmp_path),
        artifact_descriptor(tmp_path / "observations.json", root=tmp_path),
    ]

    forged_results = json.loads(json.dumps(bundle["results"]))
    group = next(iter(forged_results["groups"].values()))
    group["attempt_outcomes"]["accepted"] = 999
    forged_results["aggregate_sha256"] = results_identity(forged_results)
    forged = create_bundle(
        purpose=bundle["purpose"],
        manifest=bundle["manifest"],
        protocol_coverage=bundle["protocol_coverage"],
        results=forged_results,
        resource_telemetry=bundle["resource_telemetry"],
        reproduction=bundle["reproduction"],
        artifacts=descriptors,
        sample_registry_sha256=bundle["sample_registry"]["sha256"],
        sample_count=bundle["sample_registry"]["sample_count"],
    )
    with pytest.raises(EvidenceValidationError, match="do not reproduce"):
        validate_bundle(forged, artifact_root=tmp_path)

    forged_coverage = json.loads(json.dumps(bundle["protocol_coverage"]))
    forged_coverage["detector_statistics"] = {
        "state": "complete",
        "reason": "fixed_fpr_stable_independent_complete",
    }
    forged = create_bundle(
        purpose=bundle["purpose"],
        manifest=bundle["manifest"],
        protocol_coverage=forged_coverage,
        results=bundle["results"],
        resource_telemetry=bundle["resource_telemetry"],
        reproduction=bundle["reproduction"],
        artifacts=descriptors,
        sample_registry_sha256=bundle["sample_registry"]["sha256"],
        sample_count=bundle["sample_registry"]["sample_count"],
    )
    with pytest.raises(EvidenceValidationError, match="coverage does not match"):
        validate_bundle(forged, artifact_root=tmp_path)

    report = validate_bundle(bundle, artifact_root=tmp_path)
    assert report["aggregate_verified"] is True


def test_assemble_inherits_bound_bootstrap_settings_and_rejects_overrides(
    tmp_path, monkeypatch, capsys
):
    write_reference_protocol_run(tmp_path)
    sample_path = tmp_path / "sample-registry.json"
    observation_path = tmp_path / "observations.json"
    output_path = tmp_path / "assembled.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--output",
            str(output_path),
        ],
    )
    main()
    capsys.readouterr()
    assembled = read_bundle(output_path)
    assert assembled["manifest"]["bootstrap_replicates_count"] == 50
    assert assembled["manifest"]["bootstrap_seed_count"] == 0

    mismatch_path = tmp_path / "mismatched-bootstrap.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--output",
            str(mismatch_path),
            "--bootstrap-replicates",
            "51",
        ],
    )
    with pytest.raises(SystemExit):
        main()
    assert not mismatch_path.exists()


def test_assemble_uses_legacy_bootstrap_defaults(tmp_path, monkeypatch, capsys):
    import observations as observation_module

    samples = reference_sample_registry()
    observations = reference_observation_set(samples)
    for field in (
        "aggregation_contract_version",
        "bootstrap_replicates_count",
        "bootstrap_seed_count",
    ):
        observations["run_manifest"].pop(field)
    observations = finalize_observation_set(observations)
    sample_path = tmp_path / "sample-registry.json"
    observation_path = tmp_path / "observations.json"
    output_path = tmp_path / "legacy-assembled.json"
    _write_public_json(sample_path, samples)
    _write_public_json(observation_path, observations)

    captured = {}
    real_aggregate = observation_module.aggregate_observation_set

    def capture_aggregate(value, sample_registry, **kwargs):
        captured.update(kwargs)
        return real_aggregate(value, sample_registry, **kwargs)

    monkeypatch.setattr(observation_module, "aggregate_observation_set", capture_aggregate)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--output",
            str(output_path),
        ],
    )
    main()
    capsys.readouterr()
    assert captured["bootstrap_replicates"] == 500
    assert captured["bootstrap_seed"] == 0
    read_bundle(output_path)


def test_assemble_requires_matching_bound_comparator_and_publishes_its_artifact(
    tmp_path, monkeypatch, capsys
):
    sample_path, observation_path, comparator_path = _write_comparator_bound_reference(tmp_path)

    missing_path = tmp_path / "missing-comparator.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--output",
            str(missing_path),
        ],
    )
    with pytest.raises(SystemExit):
        main()
    assert not missing_path.exists()
    capsys.readouterr()

    mismatched_comparator = load_comparator_registry(comparator_path)
    mismatched_comparator["registry_id"] = "dewatermark-comparators-v1-mismatch"
    mismatched_path = tmp_path / "mismatched-comparator.json"
    _write_public_json(mismatched_path, mismatched_comparator)
    mismatch_output = tmp_path / "mismatched-comparator-evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--comparator-registry",
            str(mismatched_path),
            "--output",
            str(mismatch_output),
        ],
    )
    with pytest.raises(SystemExit):
        main()
    assert not mismatch_output.exists()
    capsys.readouterr()

    output_path = tmp_path / "comparator-evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--comparator-registry",
            str(comparator_path),
            "--output",
            str(output_path),
        ],
    )
    main()
    capsys.readouterr()
    assembled = read_bundle(output_path)
    assert "comparative_analysis" in assembled["results"]
    assert {item["path"] for item in assembled["artifacts"]} == {
        sample_path.name,
        observation_path.name,
        comparator_path.name,
    }
    assert validate_bundle(assembled, artifact_root=tmp_path)["artifact_count"] == 3


def test_strict_bundle_rejects_stripped_comparator_analysis_and_artifact(
    tmp_path, monkeypatch, capsys
):
    sample_path, observation_path, comparator_path = _write_comparator_bound_reference(tmp_path)
    output_path = tmp_path / "comparator-evidence.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-evidence",
            "assemble",
            "--sample-registry",
            str(sample_path),
            "--observations",
            str(observation_path),
            "--comparator-registry",
            str(comparator_path),
            "--output",
            str(output_path),
        ],
    )
    main()
    capsys.readouterr()
    assembled = read_bundle(output_path)
    stripped_results = json.loads(json.dumps(assembled["results"]))
    stripped_results.pop("comparative_analysis")
    stripped_results["aggregate_sha256"] = results_identity(stripped_results)
    comparator_digest = assembled["manifest"]["comparator_registry_sha256"]
    stripped_artifacts = [
        item for item in assembled["artifacts"] if item["canonical_sha256"] != comparator_digest
    ]
    with pytest.raises(EvidenceValidationError, match="declaration and analysis"):
        create_bundle(
            purpose=assembled["purpose"],
            manifest=assembled["manifest"],
            protocol_coverage=assembled["protocol_coverage"],
            results=stripped_results,
            resource_telemetry=assembled["resource_telemetry"],
            reproduction=assembled["reproduction"],
            artifacts=stripped_artifacts,
            sample_registry_sha256=assembled["sample_registry"]["sha256"],
            sample_count=assembled["sample_registry"]["sample_count"],
        )


def test_replay_is_plan_only_by_default_and_execution_scrubs_secrets(tmp_path, monkeypatch):
    seed = create_reference_bundle()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "seed.json").write_text(json.dumps(seed), encoding="utf-8")
    (workspace / "copy.py").write_text(
        "import os,shutil\n"
        "assert os.getenv('PRIVATE_REPLAY_TOKEN') is None\n"
        "shutil.copyfile('seed.json','replayed.json')\n",
        encoding="utf-8",
    )
    recipe = {
        "schema_version": "1.0",
        "argv": ["python", "copy.py"],
        "working_directory": "workspace",
        "result_bundle_path": "replayed.json",
    }
    source = create_bundle(
        purpose="harness_conformance",
        manifest={"fixture_sha256": _digest("replay")},
        protocol_coverage=seed["protocol_coverage"],
        results={},
        resource_telemetry=zero_network_telemetry(),
        reproduction=reproduction_descriptor(
            recipe,
            timeout_seconds=10,
            network_required=False,
            model_download_required=False,
        ),
    )
    plan = replay_bundle(source, workspace=tmp_path)
    assert plan["executed"] is False
    assert "argv" not in plan
    assert str(tmp_path) not in json.dumps(plan)
    assert not (workspace / "replayed.json").exists()
    monkeypatch.setenv("PRIVATE_REPLAY_TOKEN", "must-not-leak")
    result = replay_bundle(source, workspace=tmp_path, recipe=recipe, execute=True)
    assert result["executed"] is True
    assert result["reproduced_bundle_id"] == seed["bundle_id"]


def test_replay_rejects_dangling_result_symlink_before_process_launch(tmp_path):
    seed = create_reference_bundle()
    selected_workspace = tmp_path / "selected"
    run_directory = selected_workspace / "workspace"
    run_directory.mkdir(parents=True)
    (run_directory / "seed.json").write_text(json.dumps(seed), encoding="utf-8")
    (run_directory / "copy.py").write_text(
        "from pathlib import Path\n"
        "import shutil\n"
        "Path('process-launched').write_text('yes', encoding='utf-8')\n"
        "shutil.copyfile('seed.json', 'replayed.json')\n",
        encoding="utf-8",
    )
    recipe = {
        "schema_version": "1.0",
        "argv": ["python", "copy.py"],
        "working_directory": "workspace",
        "result_bundle_path": "replayed.json",
    }
    source = create_bundle(
        purpose="harness_conformance",
        manifest={"fixture_sha256": _digest("dangling-replay-output")},
        protocol_coverage=seed["protocol_coverage"],
        results={},
        resource_telemetry=zero_network_telemetry(),
        reproduction=reproduction_descriptor(
            recipe,
            timeout_seconds=10,
            network_required=False,
            model_download_required=False,
        ),
    )
    outside = selected_workspace / "outside.json"
    output = run_directory / "replayed.json"
    output.symlink_to(outside)
    assert output.is_symlink() and not output.exists()

    with pytest.raises(EvidenceValidationError, match="symbolic link"):
        replay_bundle(source, workspace=selected_workspace, recipe=recipe, execute=True)

    assert not outside.exists()
    assert not (run_directory / "process-launched").exists()


def test_replay_recipe_rejects_tampering_private_args_and_path_escape(tmp_path):
    fixture = create_reference_bundle()
    recipe = {
        "schema_version": "1.0",
        "argv": ["python", "run.py"],
        "working_directory": ".",
        "result_bundle_path": "result.json",
    }
    source = create_bundle(
        purpose="harness_conformance",
        manifest={"fixture_sha256": _digest("replay-policy")},
        protocol_coverage=fixture["protocol_coverage"],
        results={},
        resource_telemetry=fixture["resource_telemetry"],
        reproduction=reproduction_descriptor(
            recipe,
            timeout_seconds=10,
            network_required=False,
            model_download_required=False,
        ),
    )
    tampered = dict(recipe)
    tampered["argv"] = ["python", "other.py"]
    with pytest.raises(EvidenceValidationError, match="digest does not match"):
        replay_bundle(source, workspace=tmp_path, recipe=tampered, execute=True)

    private = dict(recipe)
    private["argv"] = ["python", "run.py", "--api-key", "not-public"]
    with pytest.raises(EvidenceValidationError, match="private-data"):
        reproduction_descriptor(
            private,
            timeout_seconds=10,
            network_required=False,
            model_download_required=False,
        )

    escaping = dict(recipe)
    escaping["result_bundle_path"] = "../result.json"
    with pytest.raises(EvidenceValidationError, match="escape"):
        reproduction_descriptor(
            escaping,
            timeout_seconds=10,
            network_required=False,
            model_download_required=False,
        )


def test_replication_is_cross_bound_and_independence_fails_closed():
    source = create_reference_bundle()
    record = create_replication_record(
        source_bundle_id=source["bundle_id"],
        reproduced_bundle_id=source["bundle_id"],
        operator_id="researcher-orcid-or-public-id",
        organization="independent-lab",
        relationship="independent",
        disclosure="No financial or organizational relationship with the authors.",
        executed_at="2026-08-17T12:00:00Z",
        environment_sha256=_digest("environment"),
        command_sha256=_digest("command"),
        outcome="exact_match",
    )
    result = validate_replication_record(record, source_bundle=source, reproduced_bundle=source)
    import dewatermark

    schema = dewatermark.benchmark_replication_record_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)
    assert result["independence_metadata_satisfied"] is True
    assert result["cryptographic_attestation_verified"] is False
    assert (
        verified_claim_eligibility(source, [(record, source)])["comparative_performance_eligible"]
        is False
    )

    related = create_replication_record(
        source_bundle_id=source["bundle_id"],
        reproduced_bundle_id=source["bundle_id"],
        operator_id="author",
        organization="original-org",
        relationship="original_operator",
        disclosure="Original benchmark operator.",
        executed_at="2026-08-17T12:00:00Z",
        environment_sha256=_digest("environment"),
        command_sha256=_digest("command"),
        outcome="exact_match",
    )
    assert (
        validate_replication_record(related, source_bundle=source, reproduced_bundle=source)[
            "independence_metadata_satisfied"
        ]
        is False
    )


@pytest.mark.parametrize(
    ("field", "secret"),
    (
        ("disclosure", "sk-live-PRIVATEREPLICATIONDISCLOSURE123456789"),
        ("operator_id", "eyJabcdefghijk.abcdefghijk.abcdefghijk"),
        ("organization", "https://user:password@example.test/lab"),
    ),
)
def test_replication_rejects_private_values_before_publishing(field, secret):
    fixture = create_reference_bundle()
    values = {
        "source_bundle_id": fixture["bundle_id"],
        "reproduced_bundle_id": fixture["bundle_id"],
        "operator_id": "independent-operator",
        "organization": "independent-lab",
        "relationship": "independent",
        "disclosure": "No relationship.",
        "executed_at": "2026-08-18T12:00:00Z",
        "environment_sha256": _digest("environment"),
        "command_sha256": _digest("command"),
        "outcome": "failed",
    }
    values[field] = secret
    with pytest.raises(EvidenceValidationError, match="private-looking") as captured:
        create_replication_record(**values)
    assert secret not in str(captured.value)


def test_frozen_complete_bundle_needs_verified_independent_replication():
    fixture = create_reference_bundle()
    complete = {
        area: {
            "state": "complete",
            "reason": sorted(COVERAGE_COMPLETE_REASON_CODES_BY_AREA[area])[0],
        }
        for area in load_protocol_registry()["coverage_areas"]
        if area != "independent_replication"
    }
    complete["independent_replication"] = {
        "state": "not_run",
        "reason": "independent_replication_not_attached",
    }
    # The source cannot self-attest replication, even if an assembler supplied
    # a complete declaration; cross-binding happens below.
    source = create_bundle(
        purpose="frozen_evaluation",
        manifest={"fixture_sha256": _digest("frozen")},
        protocol_coverage=complete,
        results={"aggregate_sha256": results_identity({})},
        resource_telemetry=fixture["resource_telemetry"],
        reproduction=fixture["reproduction"],
    )
    assert source["claim_eligibility"]["comparative_performance_eligible"] is False
    record = create_replication_record(
        source_bundle_id=source["bundle_id"],
        reproduced_bundle_id=source["bundle_id"],
        operator_id="independent",
        organization="separate-lab",
        relationship="independent",
        disclosure="No relationship.",
        executed_at="2026-08-17T12:00:00Z",
        environment_sha256=_digest("other-environment"),
        command_sha256=_digest("command"),
        outcome="exact_match",
    )
    eligibility = verified_claim_eligibility(source, [(record, source)])
    assert eligibility["comparative_performance_eligible"] is False
    assert eligibility["core_protocol_complete"] is True
    assert eligibility["independent_replication_verified"] is False
