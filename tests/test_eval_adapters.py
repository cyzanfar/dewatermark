import json
import sys
import time
from argparse import Namespace

import pytest
from adapters import AdapterContractError, CommandScheme, _split_command
from manifest import (
    IncompatibleResumeError,
    append_checkpoint,
    completed_lengths,
    content_addressed_score_table,
    ensure_resume_compatible,
    environment_manifest,
    finalize_manifest,
)


def _sidecar(name="test", family="greenlist", source="fixture", minimum=2):
    digest = "a" * 64
    return {
        "schema_version": "1.0",
        "id": name,
        "family": family,
        "source": source,
        "implementation": "fixture-adapter",
        "implementation_version": "fixture-commit-1",
        "independent": True,
        "vendor_validated": False,
        "score_direction": "higher",
        "minimum_effective_tokens": minimum,
        "configuration_sha256": digest,
        "model_revision": "model-commit-1",
        "tokenizer_revision": "tokenizer-commit-1",
        "network_required": False,
        "model_download_required": False,
        "golden_conformance": {
            "passed": True,
            "vectors_sha256": "b" * 64,
            "report_sha256": "c" * 64,
        },
    }


def test_command_adapter_versioned_contract(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text(
        "import json,sys\n"
        "p=json.load(sys.stdin)\n"
        "assert p['protocol_version']=='1.0'\n"
        "r={'protocol_version':'1.0'}\n"
        "r.update({'text':'generated'} if p['action']=='generate' else "
        "({'score':2.5} if p['action']=='detect' else {'available':True}))\n"
        "json.dump(r,sys.stdout)\n",
        encoding="utf-8",
    )
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    assert adapter.generate("prompt", None, None, 10, 1) == "generated"
    assert adapter.detect("text", None) == 2.5
    assert adapter.capabilities()["available"] is True


def test_windows_command_parser_preserves_paths_and_quotes():
    command = '"C:\\Program Files\\Python\\python.exe" "C:\\Temp\\adapter.py"'
    assert _split_command(command, windows=True) == (
        "C:\\Program Files\\Python\\python.exe",
        "C:\\Temp\\adapter.py",
    )


@pytest.mark.parametrize(
    "command",
    [
        "python adapter.py --token private",
        "python adapter.py --api-key=private",
        "python adapter.py https://user:password@example.test/run",
    ],
)
def test_adapter_command_refuses_credential_arguments(command):
    with pytest.raises(ValueError, match="cannot carry credentials"):
        _split_command(command)


def test_adapter_command_allows_public_key_fingerprints():
    command = "python adapter.py --key-fingerprint sha256-public"
    assert _split_command(command)[-2:] == ("--key-fingerprint", "sha256-public")


def test_manifest_checkpoint_resume(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    append_checkpoint(
        path, {"event": "length.completed", "length": 100, "results": {"KGW@100": {"ok": True}}}
    )
    assert completed_lengths(path)[100]["KGW@100"]["ok"]
    manifest = environment_manifest(Namespace(seed=1, output=tmp_path / "out.md"))
    assert manifest["schema_version"] == "1.0"
    assert manifest["arguments"]["seed"] == 1


def test_content_addressed_resume_rejects_changed_inputs(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    first = finalize_manifest(environment_manifest(Namespace(seed=1, output=tmp_path / "a")))
    append_checkpoint(path, {"event": "run.started", "run_id": first["run_id"], "manifest": first})
    ensure_resume_compatible(path, first)
    changed = finalize_manifest(environment_manifest(Namespace(seed=2, output=tmp_path / "b")))
    with pytest.raises(IncompatibleResumeError, match="mismatch"):
        ensure_resume_compatible(path, changed)


def test_checkpoints_are_strict_json(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    append_checkpoint(path, {"event": "metric", "unavailable": float("nan")})
    raw = path.read_text(encoding="utf-8")
    assert "NaN" not in raw
    assert json.loads(raw)["unavailable"] is None


def test_adapter_enforces_capability_policy_and_redacts_stderr(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text(
        "import json,sys\n"
        "p=json.load(sys.stdin)\n"
        "if p['action']=='capabilities':\n"
        " json.dump({'network_required':True},sys.stdout)\n"
        "else:\n"
        " print('secret-token',file=sys.stderr);sys.exit(9)\n",
        encoding="utf-8",
    )
    adapter = CommandScheme.from_spec(f"test|fixture|source|{sys.executable} {script}")
    with pytest.raises(AdapterContractError, match="allow-network"):
        adapter.capabilities()
    adapter.allow_network = True
    adapter._capabilities = None
    with pytest.raises(RuntimeError) as error:
        adapter.detect("text", None)
    assert "secret-token" not in str(error.value)


def test_static_sidecar_discovery_does_not_execute_adapter(tmp_path):
    marker = tmp_path / "executed"
    script = tmp_path / "adapter.py"
    script.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('x')\n", encoding="utf-8"
    )
    sidecar = tmp_path / "adapter.py.manifest.json"
    sidecar.write_text(json.dumps(_sidecar()), encoding="utf-8")
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    manifest = adapter.manifest()
    assert manifest["independent"] is True
    assert manifest["sidecar_sha256"]
    assert manifest["executable_digests"]
    assert not marker.exists()


def test_independence_fails_closed_without_complete_sidecar(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text("pass\n", encoding="utf-8")
    sidecar = tmp_path / "adapter.py.manifest.json"
    incomplete = _sidecar()
    incomplete["model_revision"] = "latest"
    incomplete["golden_conformance"] = {"passed": False}
    sidecar.write_text(json.dumps(incomplete), encoding="utf-8")
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    manifest = adapter.manifest()
    assert manifest["independent"] is False
    assert any("model_revision" in value for value in manifest["reproducibility_blockers"])
    assert any("golden" in value for value in manifest["reproducibility_blockers"])


def test_independent_adapter_enforces_response_identity_and_effective_length(tmp_path):
    script = tmp_path / "adapter.py"
    manifest = _sidecar(minimum=3)
    script.write_text(
        "import json,sys\n"
        "p=json.load(sys.stdin)\n"
        f"m={manifest!r}\n"
        "base={'protocol_version':'1.0','configuration_sha256':m['configuration_sha256'],"
        "'model_revision':m['model_revision'],'tokenizer_revision':m['tokenizer_revision']}\n"
        "if p['action']=='capabilities': base['manifest']=m\n"
        "elif p['action']=='detect': base.update(score=2.0,effective_tokens=1)\n"
        "else: base.update(text='a b c',requested_tokens=p['max_new_tokens'],effective_tokens=3)\n"
        "json.dump(base,sys.stdout)\n",
        encoding="utf-8",
    )
    sidecar = tmp_path / "adapter.py.manifest.json"
    sidecar.write_text(json.dumps(manifest), encoding="utf-8")
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    assert adapter.generate("prompt", None, None, 3, 1) == "a b c"
    assert adapter.generation_metadata()["effective_tokens"] == 3
    with pytest.raises(AdapterContractError, match="minimum effective length") as error:
        adapter.detect("short", None)
    assert error.value.__cause__ is None


def test_adapter_subprocess_does_not_inherit_ambient_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVATE_TEST_API_KEY", "do-not-inherit")
    script = tmp_path / "adapter.py"
    script.write_text(
        "import json,os,sys\n"
        "json.dump({'protocol_version':'1.0','leaked':os.getenv('PRIVATE_TEST_API_KEY')},sys.stdout)\n",
        encoding="utf-8",
    )
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    assert adapter.capabilities()["leaked"] is None


def test_content_addressed_score_tables_never_accept_text():
    first = content_addressed_score_table([{"sample": 0, "source_score": 1.0}])
    second = content_addressed_score_table([{"source_score": 1.0, "sample": 0}])
    assert first["sha256"] == second["sha256"]
    with pytest.raises(ValueError, match="source text"):
        content_addressed_score_table([{"sample": 0, "source_text": "private"}])


def test_resume_refuses_unpinned_statistical_model(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    manifest = environment_manifest(
        Namespace(skip_statistical=False, model_revision=None, output=tmp_path / "out")
    )
    manifest = finalize_manifest(manifest)
    append_checkpoint(
        path, {"event": "run.started", "run_id": manifest["run_id"], "manifest": manifest}
    )
    with pytest.raises(IncompatibleResumeError, match="not safely resumable"):
        ensure_resume_compatible(path, manifest)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_adapter_stream_overflow_terminates_process_and_redacts_output(tmp_path, stream):
    script = tmp_path / "adapter.py"
    script.write_text(
        "import sys,time\n"
        f"sys.{stream}.write('private-adapter-output-' * 10000)\n"
        f"sys.{stream}.flush()\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    adapter.max_response_bytes = 128
    adapter.max_stderr_bytes = 128
    started = time.monotonic()
    with pytest.raises(AdapterContractError, match="output limit") as error:
        adapter.capabilities()
    assert time.monotonic() - started < 2
    assert "private-adapter-output" not in str(error.value)
    assert error.value.__cause__ is None


def test_adapter_timeout_covers_entire_exchange_and_redacts_output(tmp_path):
    script = tmp_path / "adapter.py"
    script.write_text(
        "import sys,time\n"
        "sys.stderr.write('private-timeout-output')\n"
        "sys.stderr.flush()\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    adapter = CommandScheme.from_spec(f"test|greenlist|fixture|{sys.executable} {script}")
    adapter.timeout = 0.05
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="timed out") as error:
        adapter.capabilities()
    assert time.monotonic() - started < 2
    assert "private-timeout-output" not in str(error.value)
    assert error.value.__cause__ is None
