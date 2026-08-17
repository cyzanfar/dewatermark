import json
from argparse import Namespace

from manifest import _tree_sha256, environment_manifest


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
