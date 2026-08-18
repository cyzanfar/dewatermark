from dewatermark.chunking import chunk_text, split_for_config
from dewatermark.config import DewatermarkConfig
from dewatermark.models import CapabilityManifest
from dewatermark.quality import (
    QualityReport,
    distinct_1_ratio,
    evaluate_candidate,
    evaluate_quality,
)


def test_quality_accepts_fact_preserving_rewrite():
    source = "On June 3, revenue was 25%. See https://example.com/report."
    candidate = "Revenue was 25% on June 3. See https://example.com/report."
    report = evaluate_quality(source, candidate)
    assert report.passed


def test_quality_rejects_dropped_number_and_url():
    report = evaluate_quality(
        "Revenue was 25%. See https://example.com/report.",
        "Revenue increased considerably.",
    )
    assert not report.passed
    assert report.missing_numbers == ["25%"]
    assert report.missing_urls


def test_quality_rejects_placeholder_and_repetition():
    report = evaluate_quality("one two three four", "[BLANK] same same same same")
    assert not report.passed
    assert report.unresolved_placeholders
    assert distinct_1_ratio("same " * 20) < 0.35


def test_optional_semantic_gate():
    class Semantic:
        capability = CapabilityManifest(identifier="test-semantic", kind="semantic_scorer")

        def __call__(self, _source, _candidate):
            return 0.2

    report = evaluate_quality(
        "alpha beta gamma",
        "one two three",
        semantic_scorer=Semantic(),
        min_semantic_score=0.8,
    )
    assert not report.passed
    assert report.semantic_score == 0.2


def test_chunking_preserves_text_exactly():
    text = ("First sentence. Second sentence.\n\n" * 40).strip()
    chunks = chunk_text(text, 256)
    assert len(chunks) > 1
    assert "".join(chunks) == text
    assert all(len(c) <= 256 for c in chunks)


def test_injected_quality_gate_and_chunker():
    class Gate:
        capability = CapabilityManifest(identifier="test-gate", kind="quality_gate")

        def evaluate(self, _source, _candidate):
            return QualityReport(True, 1.0, 1.0)

    class Chunker:
        capability = CapabilityManifest(identifier="test-chunker", kind="chunker")

        def split(self, text, _max_chars):
            return [text[:2], text[2:]]

    cfg = DewatermarkConfig(quality_gate=Gate(), chunker=Chunker())
    assert evaluate_candidate("a", "b", cfg).passed
    # External gates are additive and cannot erase deterministic failures.
    bypass = evaluate_candidate("a", "completely different", cfg)
    assert not bypass.passed
    assert bypass.gate_outcomes[0].status == "abstained"
    assert split_for_config("abcd", cfg) == ["ab", "cd"]


def test_fenced_code_and_markdown_structure_are_protected():
    source = "# Title\n\n- one\n- two\n\n```python\nprint('safe')\n```\n"
    changed_code = "# Title\n\n- one\n- two\n\n```python\nprint('unsafe')\n```\n"
    assert "fenced code blocks changed" in evaluate_quality(source, changed_code).structure_errors

    changed_list = "## Title\n\n1. one\n2. two\n\n```python\nprint('safe')\n```\n"
    report = evaluate_quality(source, changed_list)
    assert "Markdown heading structure changed" in report.structure_errors
    assert "Markdown list structure changed" in report.structure_errors
