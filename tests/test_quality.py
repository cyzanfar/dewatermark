from dewatermark.chunking import chunk_text, split_for_config
from dewatermark.config import DewatermarkConfig
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
    report = evaluate_quality(
        "alpha beta gamma",
        "one two three",
        semantic_scorer=lambda _a, _b: 0.2,
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
        def evaluate(self, _source, _candidate):
            return QualityReport(True, 1.0, 1.0)

    class Chunker:
        def split(self, text, _max_chars):
            return [text[:2], text[2:]]

    cfg = DewatermarkConfig(quality_gate=Gate(), chunker=Chunker())
    assert evaluate_candidate("a", "completely different", cfg).passed
    assert split_for_config("abcd", cfg) == ["ab", "cd"]
