import json
from argparse import Namespace

import pytest
from manifest import (
    IncompatibleResumeError,
    _records,
    _tree_sha256,
    append_checkpoint,
    environment_manifest,
    json_safe,
)


def test_source_tree_identity_ignores_interpreter_cache_files(tmp_path):
    source = tmp_path / "package"
    source.mkdir()
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    expected = _tree_sha256(source)

    cache = source / "__pycache__"
    cache.mkdir()
    (cache / "module.cpython-999.pyc").write_bytes(b"machine-specific bytecode")
    (source / ".DS_Store").write_bytes(b"machine-specific metadata")

    assert _tree_sha256(source) == expected


def test_manifest_never_records_or_hashes_adapter_command_credentials():
    secret = "private-low-entropy-token"
    manifest = environment_manifest(
        Namespace(
            adapter=[f"fixture|family|source|python adapter.py --token {secret}"],
            cross_detector=[],
            skip_statistical=True,
        )
    )
    rendered = json.dumps(manifest, sort_keys=True)
    assert secret not in rendered
    assert "spec_sha256" not in rendered
    assert manifest["arguments"]["adapter"] == [{"name": "fixture"}]

    malformed = environment_manifest(
        Namespace(adapter=[secret], cross_detector=[], skip_statistical=True)
    )
    assert secret not in json.dumps(malformed, sort_keys=True)
    assert malformed["arguments"]["adapter"] == [{"name": "<redacted>"}]


def test_manifest_projection_does_not_invoke_or_reflect_arbitrary_objects(tmp_path):
    secret = "PRIVATE_MANIFEST_CREDENTIAL_8675309"

    class PrivateObject:
        def __repr__(self):
            raise AssertionError("manifest invoked an arbitrary representation")

    projected = json_safe(
        {
            "object": PrivateObject(),
            "nested": {"api_key": secret},
            "path": tmp_path / secret,
        }
    )
    rendered = json.dumps(projected, sort_keys=True)
    assert secret not in rendered
    assert "PrivateObject" not in rendered

    manifest = environment_manifest(
        Namespace(seed=1, private_api_key=secret, output=tmp_path / secret)
    )
    assert secret not in json.dumps(manifest, sort_keys=True)


def test_manifest_hashes_host_local_model_paths_but_keeps_registry_ids():
    private_path = "/Users/alice/private/models/reviewed-nli"
    manifest = environment_manifest(
        Namespace(local_lm=private_path, adapter=[], cross_detector=[], skip_statistical=True)
    )
    rendered = json.dumps(manifest, sort_keys=True)
    assert private_path not in rendered
    assert manifest["arguments"]["local_lm"].startswith("path-sha256:")

    public = environment_manifest(
        Namespace(
            local_lm="Qwen/Qwen2.5-0.5B-Instruct",
            adapter=[],
            cross_detector=[],
            skip_statistical=True,
        )
    )
    assert public["arguments"]["local_lm"] == "Qwen/Qwen2.5-0.5B-Instruct"


def test_checkpoints_are_bounded_and_reject_symlinks(tmp_path, monkeypatch):
    import manifest as manifest_module

    monkeypatch.setattr(manifest_module, "MAX_CHECKPOINT_BYTES", 32)
    oversized = tmp_path / "oversized.jsonl"
    oversized.write_text("x" * 33, encoding="utf-8")
    with pytest.raises(IncompatibleResumeError):
        _records(oversized)

    target = tmp_path / "target.jsonl"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "checkpoint.jsonl"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        return
    with pytest.raises(IncompatibleResumeError):
        append_checkpoint(link, {"event": "run.started"})
