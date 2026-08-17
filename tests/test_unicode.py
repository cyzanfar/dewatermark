"""Tests for dewatermark.unicode — ported from the original _self_test() plus
extras. No torch/LLM needed."""

import pytest

import dewatermark
from dewatermark.unicode import analyze, reverse_edits, sanitize, sanitize_with_edits

ZWSP, CYR_A, CYR_E = "\u200b", "\u0430", "\u0435"


@pytest.mark.parametrize(
    "dirty,expected",
    [
        (f"he{ZWSP}llo", "hello"),  # zero_width
        ("a\u202eb", "ab"),  # bidi
        ("hi\U000e0041", "hi"),  # tags_block
        ("a b", "a b"),  # nbsp_space
        (f"committ{CYR_E}{CYR_E}", "committee"),  # homoglyph_cyrillic
        ("Ｈｅｌｌｏ", "Hello"),  # fullwidth_nfkc
        ("\U0001d407\U0001d41e\U0001d425\U0001d425\U0001d428", "Hello"),  # math_alnum_nfkc
        ("The quick brown fox.", "The quick brown fox."),  # clean_idempotent
        ("naïve café résumé", "naïve café résumé"),  # accented_latin_preserved
    ],
)
def test_sanitize_cases(dirty, expected):
    got, _ = sanitize(dirty, profile="aggressive")
    assert got == expected


def test_non_latin_preserved():
    russian = "привет мир"
    got, _ = sanitize(russian)
    assert got == russian


def test_reanalyze_zero_flags_after_sanitize():
    dirty = f"The{ZWSP} qu\u0456ck brown fox"
    clean, _ = sanitize(dirty, profile="aggressive")
    assert analyze(clean)["unicode"]["total_flags"] == 0


def test_analyze_flags_zwsp():
    result = analyze(f"he{ZWSP}llo")
    findings = result["unicode"]["findings"]
    zwsp_findings = [f for f in findings if f["codepoint"] == "U+200B"]
    assert len(zwsp_findings) == 1
    assert zwsp_findings[0]["category"] == "zero_width"
    assert zwsp_findings[0]["count"] == 1
    assert result["unicode"]["total_flags"] == 1
    assert result["stats"]["invisible_char_count"] == 1


def test_sanitize_idempotent():
    dirty = f"a{ZWSP}b\u200bc\u2005d"
    once, _ = sanitize(dirty)
    twice, _ = sanitize(once)
    assert once == twice


def test_exotic_space_normalization():
    # NBSP, narrow no-break space, ideographic space -> regular space
    got, by_category = sanitize("a b c　d")
    assert got == "a b c d"
    assert by_category.get("exotic_space") == 3


def test_top_level_sanitize_returns_str():
    assert dewatermark.sanitize(f"he{ZWSP}llo") == "hello"


def test_safe_profile_preserves_semantic_unicode():
    source = "👩‍💻 فارسی‌نویسی ‮RTL‬ Ａ а"
    got, _ = sanitize(source, profile="safe")
    assert "👩‍💻" in got
    assert "فارسی‌نویسی" in got
    assert "Ａ" in got
    assert "а" in got


def test_aggressive_profile_is_explicitly_lossy():
    got, _ = sanitize("Ａ p\u0430ypal", profile="aggressive")
    assert got == "A paypal"


def test_invalid_profile_rejected():
    with pytest.raises(ValueError):
        sanitize("text", profile="unknown")


@pytest.mark.parametrize("profile", ["safe", "aggressive"])
@pytest.mark.parametrize(
    "source",
    [
        "a\u200bb",
        "e\u0301",
        "A\u200be\u0301",
        "ｆｏｏ",
        "p\u0430ypal",
        "👩\u200d💻",
    ],
)
def test_edit_manifest_reverses_every_transformation(profile, source):
    cleaned, _counts, edits = sanitize_with_edits(source, profile=profile)
    assert reverse_edits(cleaned, edits) == source


def test_edit_manifest_rejects_a_different_cleaned_document():
    cleaned, _counts, edits = sanitize_with_edits("a\u200bb")
    with pytest.raises(ValueError, match="does not match"):
        reverse_edits(cleaned + "changed", edits)
