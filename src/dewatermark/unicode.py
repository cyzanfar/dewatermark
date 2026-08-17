"""Deterministic detection and stripping of Unicode steganographic watermarks.

Scanner that classifies suspicious codepoints into the categories defined by the
API contract, produces an annotated rendering with visible marker tokens, and
sanitizes text. Sanitization is a strict pipeline whose ORDER is load-bearing:

  1. strip/normalize the explicit format classes (zero-width, variation
     selectors, Tags block, bidi controls, soft hyphen, exotic spaces) FIRST, so
     a hidden fingerprint is never carried into normalization;
  2. NFKC-normalize, folding fullwidth forms, Mathematical Alphanumeric Symbols,
     compatibility ligatures, etc. back to their canonical ASCII/Latin forms;
  3. map remaining cross-script homoglyphs (Cyrillic/Greek/... look-alikes) back
     to ASCII via the UTS#39 confusables skeleton, guarded by a dominant-script
     check so genuinely non-Latin text is left intact.
"""

import re
import unicodedata
from typing import Literal

from .confusables_data import CONFUSABLES_TO_ASCII

CATEGORY_LABELS = {
    "zero_width": "Zero-width character",
    "variation_selector": "Variation selector",
    "tags_block": "Tags block character",
    "exotic_space": "Exotic space",
    "homoglyph": "Homoglyph (confusable)",
    "bidi_control": "Bidirectional control",
    "soft_hyphen": "Soft hyphen",
    "other_invisible": "Other invisible character",
}

RISK_BY_CATEGORY = {
    "zero_width": "high",
    "tags_block": "high",
    "bidi_control": "high",
    "variation_selector": "medium",
    "homoglyph": "medium",
    "other_invisible": "medium",
    "exotic_space": "low",
    "soft_hyphen": "low",
}

EXPLANATIONS = {
    "zero_width": "Invisible zero-width character commonly used to encode payload bits.",
    "variation_selector": "Invisible glyph selector; VS1-VS16 / VS17-VS256 can encode 4 or 8 bits each.",
    "tags_block": "Deprecated Tags block codepoint; invisible and usable as a covert data channel.",
    "exotic_space": "Non-standard whitespace; normalized to a regular space.",
    "homoglyph": "Visually identical to a Latin letter but a different script; classic spoofing/watermarking vector.",
    "bidi_control": "Bidirectional override/embed control; can hide or reorder text (Trojan Source).",
    "soft_hyphen": "Invisible unless line-broken; often used to alter tokenization.",
    "other_invisible": "Invisible formatting character with no legitimate use in plain text.",
}

# cp -> (category, action, short_token) for the explicit format classes.
# action: "delete" | "space"  (homoglyphs are handled separately, via NFKC +
# the confusables skeleton, so they are NOT in this table).
_TABLE: dict[int, tuple[str, str, str]] = {}


def _register(cps, category, action, token):
    for cp in cps:
        resolved = token[cp] if isinstance(token, dict) else token
        _TABLE[cp] = (category, action, resolved)


_register(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF],
    "zero_width",
    "delete",
    {0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ", 0xFEFF: "BOM"},
)
_register([0x2061, 0x2062, 0x2063, 0x2064], "other_invisible", "delete", "INVOP")
_register(
    range(0xFE00, 0xFE10),
    "variation_selector",
    "delete",
    {cp: f"VS{cp - 0xFE00 + 1}" for cp in range(0xFE00, 0xFE10)},
)
_register(
    range(0xE0100, 0xE01F0),
    "variation_selector",
    "delete",
    {cp: f"VS{cp - 0xE0100 + 17}" for cp in range(0xE0100, 0xE01F0)},
)
_register(
    range(0xE0000, 0xE0080),
    "tags_block",
    "delete",
    {cp: f"TAG_{cp - 0xE0000:X}" for cp in range(0xE0000, 0xE0080)},
)
_register(
    [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F],
    "bidi_control",
    "delete",
    "BIDI",
)
_register([0x00AD], "soft_hyphen", "delete", "SHY")
_register([0x180E], "other_invisible", "delete", "MVS")
_register(
    [0x00A0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000],
    "exotic_space",
    "space",
    {
        0x00A0: "NBSP",
        0x1680: "OGHAM",
        0x2000: "ENQ",
        0x2001: "EMQ",
        0x2002: "ENSP",
        0x2003: "EMSP",
        0x2004: "3EMSP",
        0x2005: "4EMSP",
        0x2006: "6EMSP",
        0x2007: "FIGSP",
        0x2008: "PUNCSP",
        0x2009: "THINSP",
        0x200A: "HAIRSP",
        0x2028: "LSEP",
        0x2029: "PSEP",
        0x202F: "NNBSP",
        0x205F: "MMSP",
        0x3000: "IDSP",
    },
)

# Letter-only confusables drive DETECTION (a confusable digit or punctuation
# mark alone is rarely an attack signal, but a cross-script letter is the classic
# homoglyph vector). Sanitization still folds every confusable it maps.
_CONFUSABLE_LETTERS = frozenset(
    cp for cp in CONFUSABLES_TO_ASCII if unicodedata.category(chr(cp)).startswith("L")
)


def _codepoint(ch):
    return f"U+{ord(ch):04X}"


def _char_name(ch):
    try:
        return unicodedata.name(ch)
    except ValueError:
        return f"<unassigned {_codepoint(ch)}>"


def _classify(ch):
    """Return (category, action, token) for a char, or None if it is ordinary.

    action is one of "delete" | "space" | "homoglyph" (homoglyph carries the
    ASCII skeleton as its replacement string)."""
    cp = ord(ch)
    entry = _TABLE.get(cp)
    if entry is not None:
        return entry
    if cp in _CONFUSABLE_LETTERS:
        return ("homoglyph", "homoglyph", CONFUSABLES_TO_ASCII[cp])
    return None


def analyze(text):
    """Scan text once; return findings, annotated text, and stats."""
    hits: dict[int, list[int]] = {}  # cp -> list of positions
    annotated = []
    for pos, ch in enumerate(text):
        entry = _classify(ch)
        if entry is None:
            annotated.append(ch)
            continue
        category, action, token = entry
        display = token if action != "homoglyph" else f"{_script_tag(ch)}_{token.upper()}"
        hits.setdefault(ord(ch), []).append(pos)
        annotated.append(f"⟨{display}⟩")

    findings = []
    for cp in sorted(hits):
        ch = chr(cp)
        category = _classify(ch)[0]
        positions = hits[cp]
        findings.append(
            {
                "category": category,
                "codepoint": _codepoint(ch),
                "char": ch,
                "name": _char_name(ch),
                "count": len(positions),
                "positions": positions,
                "risk": RISK_BY_CATEGORY[category],
                "explanation": EXPLANATIONS[category],
            }
        )

    def _count(category):
        return sum(f["count"] for f in findings if f["category"] == category)

    stats = {
        "char_count": len(text),
        "invisible_char_count": sum(
            f["count"] for f in findings if f["category"] not in ("exotic_space", "homoglyph")
        ),
        "exotic_space_count": _count("exotic_space"),
        "homoglyph_count": _count("homoglyph"),
    }
    return {
        "unicode": {
            "total_flags": sum(f["count"] for f in findings),
            "findings": findings,
            "annotated_text": "".join(annotated),
        },
        "stats": stats,
    }


def _script_tag(ch):
    cp = ord(ch)
    if 0x0400 <= cp <= 0x052F:
        return "CYR"
    if (0x0370 <= cp <= 0x03FF) or (0x1F00 <= cp <= 0x1FFF):
        return "GRK"
    if 0x0530 <= cp <= 0x058F:
        return "ARM"
    return "CONF"


def _dominant_is_latin(text):
    """True when ASCII-Latin letters are at least as common as non-ASCII letters.

    English/Latin input is Latin-dominant, so we can safely fold every cross-script
    confusable; text that is mostly another script is not, and we fall back to a
    conservative mixed-script rule that only touches tokens already mixing scripts.
    """
    ascii_latin = non_ascii = 0
    for ch in text:
        if not ch.isalpha():
            continue
        if ord(ch) < 0x80:
            ascii_latin += 1
        else:
            non_ascii += 1
    return ascii_latin >= non_ascii


def _skeleton_confusables(text):
    """Fold cross-script confusables to their ASCII skeleton. Returns (text, count)."""
    count = 0

    def _map_token(token):
        nonlocal count
        out = []
        for ch in token:
            repl = CONFUSABLES_TO_ASCII.get(ord(ch))
            if repl is not None:
                out.append(repl)
                count += 1
            else:
                out.append(ch)
        return "".join(out)

    if _dominant_is_latin(text):
        return _map_token(text), count

    # Non-Latin-dominant: only rewrite tokens that already mix an ASCII-Latin
    # letter with a confusable (the hallmark of a homoglyph substitution).
    out = []
    for token in re.split(r"(\s+)", text):
        if not token or token.isspace():
            out.append(token)
            continue
        has_ascii_latin = any(c.isalpha() and ord(c) < 0x80 for c in token)
        has_confusable = any(ord(c) in CONFUSABLES_TO_ASCII for c in token)
        out.append(_map_token(token) if (has_ascii_latin and has_confusable) else token)
    return "".join(out), count


SanitizeProfile = Literal["safe", "aggressive"]

# Characters with established, common semantic/rendering uses.  They remain
# suspicious in forensic output, but deleting them from arbitrary natural text
# is unsafe: ZWJ/ZWNJ participate in shaping, variation selectors in emoji and
# ideographs, bidi controls in RTL text, and SHY in typography.
_CONTEXT_SENSITIVE = frozenset(
    {
        0x200C,
        0x200D,
        0x2060,
        0x00AD,
        0x180E,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0x2028,
        0x2029,
        *range(0xFE00, 0xFE10),
        *range(0xE0100, 0xE01F0),
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0x200E,
        0x200F,
    }
)


def sanitize(text: str, profile: SanitizeProfile = "safe"):
    """Sanitize Unicode covert channels.

    ``safe`` is suitable for arbitrary user text: it strips unambiguous covert
    controls and normalizes exotic spaces, while preserving shaping controls,
    variation selectors, bidi controls, compatibility characters, and
    confusables.  ``aggressive`` retains the historical behavior (NFKC plus a
    UTS #39-derived skeleton) and is intentionally lossy; use it only for text
    known to be Latin prose.

    Returns ``(cleaned_text, by_category_counts)``.
    """
    if profile not in ("safe", "aggressive"):
        raise ValueError("'profile' must be 'safe' or 'aggressive'.")
    by_category: dict[str, int] = {}

    # 1. Strip the explicit format classes BEFORE normalization so nothing hidden
    #    is folded into surviving text.
    valid_emoji_tags: set[int] = set()
    if profile == "safe":
        start = None
        for pos, ch in enumerate(text):
            if ord(ch) == 0x1F3F4:
                start = pos
            elif start is not None and ord(ch) == 0xE007F:
                valid_emoji_tags.update(range(start + 1, pos + 1))
                start = None
            elif start is not None and not 0xE0020 <= ord(ch) <= 0xE007E:
                start = None

    stripped = []
    for pos, ch in enumerate(text):
        entry = _TABLE.get(ord(ch))
        if entry is None:
            stripped.append(ch)
            continue
        category, action, _ = entry
        if profile == "safe" and (
            ord(ch) in _CONTEXT_SENSITIVE
            or pos in valid_emoji_tags
            or (ord(ch) == 0xFEFF and pos == 0)
        ):
            stripped.append(ch)
            continue
        by_category[category] = by_category.get(category, 0) + 1
        if action == "delete":
            continue
        if action == "space":
            stripped.append(" ")
    cleaned = "".join(stripped)

    if profile == "safe":
        # NFC preserves semantic compatibility distinctions while still making
        # canonically equivalent text stable.
        return unicodedata.normalize("NFC", cleaned), by_category

    # 2. Aggressive compatibility folding. This is deliberately not the default.
    normalized = unicodedata.normalize("NFKC", cleaned)

    # 3. Cross-script homoglyph skeleton (dominant-script guarded).
    skeletoned, homoglyph_count = _skeleton_confusables(normalized)
    if homoglyph_count:
        by_category["homoglyph"] = by_category.get("homoglyph", 0) + homoglyph_count

    return skeletoned, by_category
