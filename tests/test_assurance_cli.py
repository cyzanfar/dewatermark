import io
import json
import os
import subprocess
import sys
from pathlib import Path

import dewatermark.cli as cli
from dewatermark.cli import EXIT_OK, EXIT_PROCESSING, EXIT_USAGE, main


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


def test_cli_two_phase_roundtrip_across_fresh_processes(tmp_path):
    root = Path(__file__).parents[1]
    source = tmp_path / "source.txt"
    source.write_text("he\u200bllo", encoding="utf-8")
    env = os.environ.copy()
    python_paths = [str(root / "src"), str(root / "eval")]
    if env.get("PYTHONPATH"):
        python_paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_paths)
    command = [sys.executable, "-m", "dewatermark"]

    first = subprocess.run(
        [*command, "plan", "--input", str(source), "--mode", "sanitize"],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    second = subprocess.run(
        [*command, "plan", "--input", str(source), "--mode", "sanitize"],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    planned = json.loads(first.stdout)
    assert json.loads(second.stdout)["plan_digest"] == planned["plan_digest"]

    applied = subprocess.run(
        [
            *command,
            "apply",
            "--input",
            str(source),
            "--mode",
            "sanitize",
            "--plan-digest",
            planned["plan_digest"],
            "--consent",
        ],
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert applied.returncode == EXIT_OK, applied.stderr
    assert json.loads(applied.stdout)["result"]["cleaned_text"] == "hello"


def test_cli_failed_removal_uses_processing_exit(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_remove_one",
        lambda *_args, **_kwargs: {
            "schema_version": "1.0",
            "cleaned_text": "source",
            "report": {"status": "failed"},
        },
    )

    assert main(["remove", "source", "--mode", "sanitize", "--format", "json"]) == (EXIT_PROCESSING)
    assert json.loads(capsys.readouterr().out)["report"]["status"] == "failed"


def test_cli_refuses_oversized_input_before_reading_it_all(tmp_path, monkeypatch, capsys):
    source = tmp_path / "large.txt"
    source.write_bytes(b"private-material")
    monkeypatch.setattr(cli, "_MAX_CLI_TEXT_BYTES", 4)

    assert main(["sanitize", "--input", str(source)]) == EXIT_USAGE
    error = json.loads(capsys.readouterr().err)
    assert error == {"status": "failed", "error": "input exceeds the supported size limit"}


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


def test_cli_scanner_config_excludes_and_records_effective_policy(tmp_path, capsys):
    (tmp_path / "keep.txt").write_text("he\u200bllo", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("he\u200bllo", encoding="utf-8")
    config = tmp_path / ".dewatermark.toml"
    config.write_text(
        """[scan]
exclude = ["skip.txt", ".dewatermark.toml"]
extensions = ["txt"]
max_file_bytes = 8192
""",
        encoding="utf-8",
    )
    assert main(["check", str(tmp_path), "--config", str(config), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["files_scanned"] == 1
    assert report["finding_count"] == 1
    assert report["configuration"]["exclude_patterns"] == [
        ".dewatermark.toml",
        "skip.txt",
    ]
    assert report["configuration"]["extensions"] == [".txt"]
    assert report["configuration"]["max_file_bytes"] == 8192


def test_cli_scanner_discovers_policy_from_single_target_repo(tmp_path, monkeypatch, capsys):
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "keep.txt").write_text("he\u200bllo", encoding="utf-8")
    (repository / "skip.txt").write_text("he\u200bllo", encoding="utf-8")
    (repository / ".dewatermark.toml").write_text(
        "[scan]\nexclude = ['skip.txt', '.dewatermark.toml']\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert main(["check", str(repository), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["files_scanned"] == 1
    assert Path(report["findings"][0]["path"]).name == "keep.txt"


def test_cli_stdin_path_applies_target_repository_excludes(tmp_path, monkeypatch, capsys):
    repository = tmp_path / "target"
    generated = repository / "src" / "generated"
    generated.mkdir(parents=True)
    (repository / ".dewatermark.toml").write_text(
        "[scan]\nexclude = ['src/generated/**']\nextensions = ['py']\n", encoding="utf-8"
    )
    source_path = generated / "buffer.py"
    monkeypatch.setattr(sys, "stdin", io.StringIO("he\u200bllo"))
    assert main(["check", "--stdin-path", str(source_path), "--format", "json"]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["files_scanned"] == 0
    assert report["findings"] == []


def test_cli_scanner_bounds_standard_input(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("private-material"))
    assert main(["check", "--max-file-bytes", "4", "--format", "json"]) == EXIT_USAGE
    assert json.loads(capsys.readouterr().err) == {
        "status": "failed",
        "error": "standard input exceeds max file bytes",
    }


def test_cli_detector_workflow_and_openapi_schema(capsys):
    assert main(["detectors", "list"]) == EXIT_OK
    listed = json.loads(capsys.readouterr().out)
    assert listed["side_effect_free"] is True
    assert any(
        item["identifier"] == "research-reference/kgw-word-v1" for item in listed["detectors"]
    )

    assert main(["detectors", "doctor"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["passed"] is True

    assert main(["detectors", "conformance", "--scheme", "kgw"]) == EXIT_OK
    conformance = json.loads(capsys.readouterr().out)
    assert conformance["passed"] is True
    assert len(conformance["cases"]) == 2

    assert main(["detectors", "packs"]) == EXIT_OK
    packs = json.loads(capsys.readouterr().out)
    assert {item["name"] for item in packs["packs"]} == {"kgw", "synthid"}

    assert main(["schema", "--kind", "openapi"]) == EXIT_OK
    openapi = json.loads(capsys.readouterr().out)
    assert openapi["openapi"].startswith("3.")
    assert "/plan" in openapi["paths"]


def test_cli_agent_skill_path_and_safe_install(tmp_path, capsys):
    assert main(["skill", "path"]) == EXIT_OK
    located = json.loads(capsys.readouterr().out)
    assert Path(located["path"]).joinpath("SKILL.md").is_file()

    output = tmp_path / "agent-skill"
    assert main(["skill", "install", "--output", str(output)]) == EXIT_OK
    installed = json.loads(capsys.readouterr().out)
    assert installed["files"] == ["SKILL.md", "agents/openai.yaml"]
    assert (output / "agents" / "openai.yaml").is_file()
    assert main(["skill", "install", "--output", str(output)]) == EXIT_USAGE
    assert "invalid input" in capsys.readouterr().err
