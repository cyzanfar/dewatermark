"""Distribution contract tests run against artifacts produced by ``build``.

Set ``DEWATERMARK_DIST_DIR`` to a wheel/sdist directory. Normal editable test
runs skip these checks; the package job makes them mandatory after building.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

import pytest

SKILL_FILES = {
    "SKILL.md",
    "agents/openai.yaml",
}
SCHEMA_FILES = {
    "command-detector-protocol-v1.json",
    "detector-capability-v1.json",
    "evidence-receipt-v1.json",
    "removal-result-v1.json",
}
FORBIDDEN_PARTS = {".env", ".git", "__pycache__", ".DS_Store"}


def _dist_dir() -> Path:
    configured = os.environ.get("DEWATERMARK_DIST_DIR")
    if not configured:
        pytest.skip("set DEWATERMARK_DIST_DIR to validate built distributions")
    path = Path(configured).resolve()
    if not path.is_dir():
        pytest.fail(f"DEWATERMARK_DIST_DIR is not a directory: {path}")
    return path


def _assert_safe_members(names: list[str]) -> None:
    assert names
    for name in names:
        path = PurePosixPath(name)
        assert not path.is_absolute(), f"absolute archive member: {name}"
        assert ".." not in path.parts, f"traversal archive member: {name}"
        assert not FORBIDDEN_PARTS.intersection(path.parts), f"forbidden archive member: {name}"
        assert not name.endswith((".pyc", ".pyo")), f"bytecode in distribution: {name}"


def test_wheel_contains_agent_skill_and_declared_extras() -> None:
    wheels = sorted(_dist_dir().glob("dewatermark-*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, found {wheels}"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        _assert_safe_members(names)
        prefix = "dewatermark/skills/remove-text-watermarks/"
        packaged = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        assert SKILL_FILES <= packaged
        schema_prefix = "dewatermark/data/schemas/"
        packaged_schemas = {
            name.removeprefix(schema_prefix) for name in names if name.startswith(schema_prefix)
        }
        assert SCHEMA_FILES <= packaged_schemas
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1
        metadata = archive.read(metadata_names[0]).decode("utf-8")

    for extra in ("agents", "dev", "eval", "local"):
        assert f"Provides-Extra: {extra}" in metadata
    assert "Requires-Dist: mcp" in metadata
    assert "extra == 'agents'" in metadata


def test_sdist_contains_agent_skill_and_security_policy() -> None:
    sdists = sorted(_dist_dir().glob("dewatermark-*.tar.gz"))
    assert len(sdists) == 1, f"expected exactly one sdist, found {sdists}"
    with tarfile.open(sdists[0], mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _assert_safe_members(names)
        assert all(member.isfile() or member.isdir() for member in members), (
            "sdist must not contain links or special files"
        )

    skill_suffix = "/skills/remove-text-watermarks/"
    packaged = {
        name.split(skill_suffix, 1)[1]
        for name in names
        if skill_suffix in name and not name.endswith("/")
    }
    assert SKILL_FILES <= packaged
    assert any(name.endswith("/SECURITY.md") for name in names)
