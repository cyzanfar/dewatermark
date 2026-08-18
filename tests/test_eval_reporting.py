from argparse import Namespace

import pytest
import run_eval
from run_eval import _composite_success, _mode_metrics, _transform_population, write_results


def test_unicode_only_report_does_not_imply_statistical_samples_ran(tmp_path):
    output = tmp_path / "results.md"
    args = Namespace(
        date="2026-08-17",
        local_lm="fixture/model",
        samples=100,
        null_samples=1000,
        lengths=None,
        length=220,
        seed=13,
    )
    write_results(
        [{"family": "fixture", "removed": 1, "total": 1, "rate": 1.0}],
        None,
        args,
        output,
    )
    rendered = output.read_text(encoding="utf-8")
    assert "Statistical suite: not run" in rendered
    assert "100 positives" not in rendered


def test_mode_reporting_includes_cluster_fixed_fpr_and_all_attempt_denominators():
    calibration = [float(index) for index in range(100)]
    row = _mode_metrics(
        [100.0, 100.0, 100.0],
        [0.0, 100.0, 0.0],
        [0.0] * 100,
        [0.0] * 100,
        calibration,
        calibration,
        [1.0, 1.0, 1.0],
        [],
        [True, False, False],
        float("nan"),
        [],
        [],
        positive_cluster_ids=["a", "a", "b"],
        null_cluster_ids=[f"null-{index}" for index in range(100)],
        bootstrap_replicates=10,
    )
    assert row["fixed_fpr_inference@0.01"]["estimable"] is True
    assert "cluster" in row["auroc_interval_method"]
    composite = _composite_success(
        [100.0, 100.0, 100.0],
        [0.0, 100.0, 0.0],
        [
            {"state": "accepted"},
            {"state": "failed"},
            {"state": "abstained"},
        ],
        [True, False, False],
        row,
    )
    assert composite["all_attempt_outcomes"]["attempted_denominator"] == 3
    assert composite["all_attempt_outcomes"]["failed"] == 1
    assert composite["all_attempt_outcomes"]["abstained"] == 1


def test_transform_failures_never_publish_hostile_exception_names_or_messages(monkeypatch, capsys):
    secret = "PRIVATE-PATH-AND-TOKEN"
    hostile_error = type(secret, (RuntimeError,), {})

    def fail(_text, _mode):
        raise hostile_error(secret)

    monkeypatch.setattr(run_eval, "_remove_with_outcome", fail)
    candidates, outcomes = _transform_population(
        ["local text"],
        "sanitize",
        label=secret,
        failure_policy="continue",
    )
    captured = capsys.readouterr()
    assert candidates == ["local text"]
    assert outcomes[0]["error"] == "transformation_exception"
    assert secret not in captured.err


def test_adapter_parser_errors_redact_hostile_exception_details(monkeypatch, capsys):
    secret = "PRIVATE-ADAPTER-CREDENTIAL"

    def fail(_spec):
        raise ValueError(secret)

    monkeypatch.setattr(run_eval.CommandScheme, "from_spec", fail)
    monkeypatch.setattr("sys.argv", ["dewatermark-eval", "--adapter", secret, "--skip-statistical"])
    with pytest.raises(SystemExit):
        run_eval.main()
    assert secret not in capsys.readouterr().err


def test_existing_checkpoint_error_does_not_echo_private_path(tmp_path, monkeypatch, capsys):
    checkpoint = tmp_path / "PRIVATE-CHECKPOINT-NAME.jsonl"
    checkpoint.write_text("occupied\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "dewatermark-eval",
            "--skip-statistical",
            "--skip-unicode",
            "--checkpoint",
            str(checkpoint),
        ],
    )
    with pytest.raises(SystemExit):
        run_eval.main()
    assert str(checkpoint) not in capsys.readouterr().err
