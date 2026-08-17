import json

from dewatermark.cli import EXIT_OK, EXIT_USAGE, main


def test_cli_two_phase_assurance_roundtrip(capsys):
    source = "he\u200bllo"
    assert main(["inspect", source]) == EXIT_OK
    inspection = json.loads(capsys.readouterr().out)
    assert inspection["input_sha256"]
    assert inspection["unicode"]["total_flags"] == 1

    assert main(["plan", source, "--mode", "sanitize"]) == EXIT_OK
    planned = json.loads(capsys.readouterr().out)
    assert planned["plan_digest"]
    assert planned["permissions"]["allow_network"] is False

    assert (
        main(
            [
                "apply",
                source,
                "--mode",
                "sanitize",
                "--plan-digest",
                planned["plan_digest"],
                "--consent",
            ]
        )
        == EXIT_OK
    )
    applied = json.loads(capsys.readouterr().out)
    assert applied["result"]["cleaned_text"] == "hello"
    assert applied["output_sha256"] != applied["input_sha256"]

    assert main(["verify", source, "hello"]) == EXIT_OK
    verified = json.loads(capsys.readouterr().out)
    assert verified["verification_status"] == "verified_cleared"


def test_cli_apply_requires_matching_plan_and_consent(capsys):
    assert (
        main(
            [
                "apply",
                "he\u200bllo",
                "--mode",
                "sanitize",
                "--plan-digest",
                "0" * 64,
            ]
        )
        == EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["status"] == "failed"
    assert "consent" in payload["error"]


def test_cli_binds_detector_and_verification_policy(capsys):
    source = "plain text"
    assert (
        main(
            [
                "plan",
                source,
                "--mode",
                "sanitize",
                "--detector",
                "anthropic-claude",
                "--require-verified",
            ]
        )
        == EXIT_OK
    )
    planned = json.loads(capsys.readouterr().out)
    assert planned["detector"] == "anthropic-claude"
    assert planned["policy"]["config"]["require_verified"] is True


def test_cli_scanner_baseline_roundtrip(tmp_path, capsys):
    target = tmp_path / "sample.txt"
    target.write_text("he\u200bllo", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    assert main(["check", str(target), "--write-baseline", str(baseline)]) == 1
    capsys.readouterr()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload["fingerprints"]
    assert (
        main(
            [
                "check",
                str(target),
                "--baseline",
                str(baseline),
                "--new-only",
            ]
        )
        == EXIT_OK
    )
    assert "No suspicious Unicode" in capsys.readouterr().out
