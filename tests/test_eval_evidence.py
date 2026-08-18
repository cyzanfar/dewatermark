import hashlib
import json
from collections.abc import Mapping
from types import SimpleNamespace

import evidence
import pytest
from evidence import (
    EvidenceValidationError,
    artifact_descriptor,
    create_bundle,
    create_reference_bundle,
    create_replication_record,
    main,
    read_bundle,
    replay_bundle,
    reproduction_descriptor,
    validate_bundle,
    validate_replication_record,
    verified_claim_eligibility,
    write_bundle,
)
from jsonschema import Draft202012Validator
from protocol import load_protocol_registry
from public_codes import COVERAGE_COMPLETE_REASON_CODES_BY_AREA
from resources import zero_network_telemetry


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


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
        results={"aggregate_sha256": _digest("results")},
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
