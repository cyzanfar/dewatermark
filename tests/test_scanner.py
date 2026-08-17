from pathlib import Path

from dewatermark.scanner import (
    baseline_fingerprints,
    changed_lines_from_unified_diff,
    scan_paths,
    scan_text,
    to_sarif,
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
    assert target.stat().st_mode & 0o777 == 0o640
    assert report.fixed_files == (str(target),)
    assert len(report.edits) == 1
    assert report.edits[0].original_codepoints == ("U+200B",)
    assert report.edits[0].accepted is True
