import json
import shutil
import subprocess
from pathlib import Path

import pytest

from dewatermark.unicode import UNICODE_POLICY_VERSION, analyze, sanitize, sanitize_with_edits

ROOT = Path(__file__).parents[1]
CASES = json.loads((ROOT / "tests/fixtures/unicode_golden.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_python_safe_policy_golden(case):
    cleaned, _ = sanitize(case["input"], profile="safe")
    assert cleaned == case["safe"]


def test_legitimate_scripts_and_emoji_are_informational():
    for source in ("Привет мир", "Αθήνα", "فارسی", "👩‍💻", "❤️"):
        report = analyze(source)["unicode"]
        assert report["total_flags"] == 0
        assert report["actionable_count"] == 0


def test_mixed_script_token_is_actionable():
    report = analyze("p\u0430ypal")["unicode"]
    assert report["actionable_count"] == 1
    assert report["findings"][0]["disposition"] == "actionable"


def test_generated_browser_policy_is_current():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is not installed")
    generated = subprocess.run(
        [node, "web/generate-policy.mjs"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
    ).stdout
    assert generated == (ROOT / "web/unicode-policy.mjs").read_text(encoding="utf-8")
    assert f'POLICY_VERSION = "{UNICODE_POLICY_VERSION}"' in generated


def test_browser_and_python_safe_sanitizers_match_golden_corpus():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is not installed")
    script = """
import { sanitizeTextWithReport } from './web/sanitizer.mjs';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const cases = JSON.parse(input);
process.stdout.write(JSON.stringify(cases.map((item) => sanitizeTextWithReport(item.input))));
"""
    completed = subprocess.run(
        [node, "--input-type=module", "--eval", script],
        cwd=ROOT,
        input=json.dumps(CASES, ensure_ascii=False),
        check=True,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
    )
    browser = json.loads(completed.stdout)
    for case, result in zip(CASES, browser):
        python_cleaned, python_counts, python_edits = sanitize_with_edits(
            case["input"], profile="safe"
        )
        assert result["cleanedText"] == python_cleaned == case["safe"]
        assert result["counts"] == python_counts
        assert [
            (item["category"], item["action"])
            for item in result["edits"]
            if item["category"] != "normalization"
        ] == [
            (item["category"], item["action"])
            for item in python_edits
            if item["category"] != "normalization"
        ]
        assert any(item["category"] == "normalization" for item in result["edits"]) == any(
            item["category"] == "normalization" for item in python_edits
        )
        assert result["changed"] is bool(python_edits)
        assert result["policyVersion"] == UNICODE_POLICY_VERSION
