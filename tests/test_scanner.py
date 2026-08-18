import os
from pathlib import Path

import dewatermark.scanner_config as scanner_config_module
from dewatermark.scanner import (
    baseline_fingerprints,
    changed_lines_from_unified_diff,
    path_is_selected,
    scan_paths,
    scan_text,
    to_sarif,
)
from dewatermark.scanner_config import (
    ScannerConfig,
    find_scanner_config,
    load_scanner_config,
    resolve_scanner_config,
)


def test_scan_text_has_locations():
    finding = scan_text("ok\nhe\u200bllo", "demo.txt")[0]
    assert (finding.path, finding.line, finding.column) == ("demo.txt", 2, 3)
    assert finding.codepoint == "U+200B"


def test_scan_paths_and_fix(tmp_path: Path):
    target = tmp_path / "sample.md"
    target.write_text("he\u200bllo", encoding="utf-8")
    report = scan_paths([tmp_path], fix=True)
    assert report.files_scanned == 1
    assert len(report.findings) == 1
    assert target.read_text(encoding="utf-8") == "hello"


def test_sarif_shape():
    report = scan_paths([])
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "dewatermark"


def test_informational_unicode_is_not_a_default_scanner_finding():
    assert scan_text("Привет мир 👩‍💻 فارسی‌نویسی") == ()


def test_contextual_typography_requires_explicit_opt_in():
    assert scan_text("A\u00a0B") == ()
    finding = scan_text("A\u00a0B", dispositions={"contextual"})[0]
    assert finding.disposition == "contextual"


def test_scanner_rejects_fail_open_direct_api_policies():
    try:
        scan_paths([], max_file_bytes=-1)
    except ValueError as exc:
        assert "max_file_bytes" in str(exc)
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("negative size limit must fail closed")

    try:
        scan_text("plain", dispositions={"unsupported"})
    except ValueError as exc:
        assert "dispositions" in str(exc)
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("unknown dispositions must fail closed")


def test_baseline_suppression_and_changed_line_filters():
    source = "old\u200b\nnew\u200b\n"
    initial = scan_paths([])
    first = scan_text(source, "demo.txt")
    baseline = baseline_fingerprints(type(initial)(1, first))
    assert scan_text(source, "demo.txt", baseline=baseline, new_only=True) == ()
    assert len(scan_text(source, "demo.txt", changed_lines={2})) == 1
    assert scan_text(source, "demo.txt", suppressions={"U+200B"}) == ()


def test_unified_diff_hook_extracts_target_lines():
    diff = """--- a/demo.txt
+++ b/demo.txt
@@ -1,2 +1,3 @@
 old
+new
 keep
"""
    assert changed_lines_from_unified_diff(diff) == {"demo.txt": frozenset({2})}


def test_safe_fix_is_atomic_and_preserves_bom_crlf_and_mode(tmp_path: Path):
    target = tmp_path / "sample.txt"
    target.write_bytes(b"\xef\xbb\xbfhello\xe2\x80\x8b\r\nnext\r\n")
    target.chmod(0o640)
    report = scan_paths([target], fix=True)
    assert target.read_bytes() == b"\xef\xbb\xbfhello\r\nnext\r\n"
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o640
    assert report.fixed_files == (str(target),)
    assert len(report.edits) == 1
    assert report.edits[0].original_codepoints == ("U+200B",)
    assert report.edits[0].accepted is True


def test_scan_paths_supports_extensions_and_relative_exclude_globs(tmp_path: Path):
    (tmp_path / "keep.txt").write_text("he\u200bllo", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("he\u200bllo", encoding="utf-8")
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "data.txt").write_text("he\u200bllo", encoding="utf-8")
    (tmp_path / "notes.custom").write_text("he\u200bllo", encoding="utf-8")

    report = scan_paths(
        [tmp_path],
        exclude_patterns=("skip.txt", "generated\\**"),
        extensions=("custom",),
    )
    assert report.files_scanned == 1
    assert [Path(item.path).name for item in report.findings] == ["notes.custom"]
    assert report.to_dict()["configuration"]["exclude_patterns"] == [
        "generated/**",
        "skip.txt",
    ]
    assert report.to_dict()["configuration"]["extensions"] == [".custom"]


def test_in_memory_path_selection_is_anchored_to_policy_root(tmp_path: Path):
    nested = tmp_path / "src" / "generated" / "sample.py"
    assert not path_is_selected(
        nested,
        root=tmp_path,
        exclude_patterns=("src/generated/**",),
        extensions=("py",),
    )
    assert path_is_selected(
        tmp_path / "src" / "keep.py",
        root=tmp_path,
        exclude_patterns=("src/generated/**",),
        extensions=("py",),
    )


def test_scanner_config_load_discovery_and_defaults(tmp_path: Path):
    config_path = tmp_path / ".dewatermark.toml"
    config_path.write_text(
        """[scan]
exclude = ["generated/**", "*.min.js"]
extensions = ["txt", ".md"]
max_file_bytes = 4096
dispositions = ["actionable", "contextual"]
suppressions = ["U+FEFF"]
""",
        encoding="utf-8",
    )
    nested = tmp_path / "src" / "nested"
    nested.mkdir(parents=True)
    assert find_scanner_config(nested) == config_path
    config = resolve_scanner_config(start=nested)
    assert config == ScannerConfig(
        exclude=("generated/**", "*.min.js"),
        extensions=(".txt", ".md"),
        max_file_bytes=4096,
        dispositions=("actionable", "contextual"),
        suppressions=("U+FEFF",),
        source=str(config_path),
    )


def test_scanner_config_reads_pyproject_and_rejects_unknown_keys(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
[tool.dewatermark.scan]
exclude = ["vendor/**"]
""",
        encoding="utf-8",
    )
    assert load_scanner_config(pyproject).exclude == ("vendor/**",)
    bad = tmp_path / "bad.toml"
    bad.write_text("[scan]\nsecret = 'nope'\n", encoding="utf-8")
    try:
        load_scanner_config(bad)
    except ValueError as exc:
        assert "unsupported keys" in str(exc)
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("unknown scanner config keys must fail closed")


def test_scanner_config_can_disable_discovery(tmp_path: Path):
    (tmp_path / ".dewatermark.toml").write_text(
        "[scan]\nexclude = ['private/**']\n", encoding="utf-8"
    )
    assert resolve_scanner_config(start=tmp_path, discover=False) == ScannerConfig()


def test_scanner_config_rejects_symlinked_policy(tmp_path: Path):
    target = tmp_path / "target.toml"
    target.write_text("[scan]\nexclude = []\n", encoding="utf-8")
    link = tmp_path / ".dewatermark.toml"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        return

    try:
        load_scanner_config(link)
    except ValueError as exc:
        assert "regular file" in str(exc)
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("symlinked policy must fail closed")


def test_scanner_config_discovery_bounds_pyproject_reads(tmp_path: Path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.dewatermark.scan]\nexclude = ['generated/**']\n", encoding="utf-8"
    )
    monkeypatch.setattr(scanner_config_module, "MAX_CONFIG_BYTES", 8)
    assert find_scanner_config(tmp_path) is None
