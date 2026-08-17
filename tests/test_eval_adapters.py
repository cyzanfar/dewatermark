import sys
from argparse import Namespace

from adapters import CommandScheme
from manifest import append_checkpoint, completed_lengths, environment_manifest


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


def test_manifest_checkpoint_resume(tmp_path):
    path = tmp_path / "checkpoint.jsonl"
    append_checkpoint(
        path, {"event": "length.completed", "length": 100, "results": {"KGW@100": {"ok": True}}}
    )
    assert completed_lengths(path)[100]["KGW@100"]["ok"]
    manifest = environment_manifest(Namespace(seed=1, output=tmp_path / "out.md"))
    assert manifest["schema_version"] == "1.0"
    assert manifest["arguments"]["seed"] == 1
