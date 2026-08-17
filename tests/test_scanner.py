from pathlib import Path

from dewatermark.scanner import scan_paths, scan_text, to_sarif


def test_scan_text_has_locations():
    finding = scan_text("ok\nhe\u200bllo", "demo.txt")[0]
    assert (finding.path, finding.line, finding.column) == ("demo.txt", 2, 3)
    assert finding.codepoint == "U+200B"


def test_scan_paths_and_fix(tmp_path: Path):
    target = tmp_path / "sample.md"
    target.write_text("he\u200bllo")
    report = scan_paths([tmp_path], fix=True)
    assert report.files_scanned == 1
    assert len(report.findings) == 1
    assert target.read_text() == "hello"


def test_sarif_shape():
    report = scan_paths([])
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "dewatermark"
