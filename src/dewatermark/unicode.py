"""Context-aware Unicode artifact inspection and deterministic sanitation.

The conservative profile is intended for arbitrary Unicode text.  It removes
only unambiguous covert characters, preserves valid emoji/script/bidi uses, and
normalizes the small set of spaces covered by the public API.  The aggressive
profile remains an explicitly lossy Latin-prose transform.

The machine-readable :mod:`unicode_policy.json` file is the canonical policy
shared with the browser build.  Existing result keys are retained; v2 adds
per-occurrence disposition, byte/grapheme offsets, and reversible edit data.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Literal, Sequence

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
    "zero_width": "Invisible zero-width character that may encode data or affect shaping.",
    "variation_selector": "Glyph selector with legitimate emoji/ideograph uses and covert-channel capacity.",
    "tags_block": "Tags-block codepoint used by valid subdivision flags and by covert payloads.",
    "exotic_space": "Non-standard whitespace that the conservative sanitizer normalizes when safe.",
    "homoglyph": "Character with an ASCII confusable; mixed-script tokens may indicate spoofing.",
    "bidi_control": "Bidirectional control that may be valid in RTL text or may reorder displayed source.",
    "soft_hyphen": "Conditional hyphen with legitimate typography and tokenization effects.",
    "other_invisible": "Invisible formatting character whose meaning depends on its context.",
}

Disposition = Literal["actionable", "contextual", "informational"]
SanitizeProfile = Literal["safe", "aggressive"]

_POLICY_PATH = Path(__file__).with_name("unicode_policy.json")
with _POLICY_PATH.open(encoding="utf-8") as _policy_file:
    UNICODE_POLICY: dict[str, Any] = json.load(_policy_file)
UNICODE_POLICY_VERSION = str(UNICODE_POLICY["policy_version"])
UNICODE_POLICY_SHA256 = hashlib.sha256(
    json.dumps(UNICODE_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()

# cp -> (category, aggressive action, marker token, conservative rule)
_TABLE: dict[int, tuple[str, str, str, str]] = {}
for _rule in UNICODE_POLICY["rules"]:
    _start = int(_rule["start"], 16)
    _end = int(_rule["end"], 16)
    for _cp in range(_start, _end + 1):
        _TABLE[_cp] = (
            str(_rule["category"]),
            str(_rule["action"]),
            str(_rule["token"]),
            str(_rule["safe"]),
        )

_CONFUSABLE_LETTERS = frozenset(
    cp for cp in CONFUSABLES_TO_ASCII if unicodedata.category(chr(cp)).startswith("L")
)
_DISPOSITION_ORDER: dict[Disposition, int] = {
    "informational": 0,
    "contextual": 1,
    "actionable": 2,
}
_RTL_BIDI = frozenset({"R", "AL", "AN"})


def _codepoint(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def _char_name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return f"<unassigned {_codepoint(ch)}>"


def _script(ch: str) -> str:
    """Return a stable, deliberately coarse script label using stdlib data."""
    if not ch or not (ch.isalpha() or unicodedata.category(ch).startswith("M")):
        return "Common"
    name = _char_name(ch)
    for prefix, script in (
        ("LATIN", "Latin"),
        ("CYRILLIC", "Cyrillic"),
        ("GREEK", "Greek"),
        ("ARMENIAN", "Armenian"),
        ("HEBREW", "Hebrew"),
        ("ARABIC", "Arabic"),
        ("SYRIAC", "Syriac"),
        ("THAANA", "Thaana"),
        ("DEVANAGARI", "Devanagari"),
        ("BENGALI", "Bengali"),
        ("GURMUKHI", "Gurmukhi"),
        ("GUJARATI", "Gujarati"),
        ("ORIYA", "Oriya"),
        ("TAMIL", "Tamil"),
        ("TELUGU", "Telugu"),
        ("KANNADA", "Kannada"),
        ("MALAYALAM", "Malayalam"),
        ("SINHALA", "Sinhala"),
        ("THAI", "Thai"),
        ("LAO", "Lao"),
        ("TIBETAN", "Tibetan"),
        ("MYANMAR", "Myanmar"),
        ("GEORGIAN", "Georgian"),
        ("HANGUL", "Hangul"),
        ("HIRAGANA", "Hiragana"),
        ("KATAKANA", "Katakana"),
        ("CJK", "Han"),
        ("IDEOGRAPH", "Han"),
        ("KHMER", "Khmer"),
    ):
        if name.startswith(prefix):
            return script
    if unicodedata.category(ch).startswith("M"):
        return "Inherited"
    return "Other"


def _script_tag(ch: str) -> str:
    return {
        "Cyrillic": "CYR",
        "Greek": "GRK",
        "Armenian": "ARM",
    }.get(_script(ch), "CONF")


def _is_emojiish(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2600 <= cp <= 0x27FF
        or 0x2300 <= cp <= 0x23FF
        or cp in {0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D}
    )


def _nearest_base(text: str, position: int, direction: int) -> str:
    index = position + direction
    for _ in range(8):
        if not 0 <= index < len(text):
            return ""
        ch = text[index]
        cp = ord(ch)
        if (
            unicodedata.category(ch).startswith("M")
            or cp in {0x200C, 0x200D}
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF
        ):
            index += direction
            continue
        return ch
    return ""


def _meaningful_join_control(text: str, position: int) -> bool:
    left = _nearest_base(text, position, -1)
    right = _nearest_base(text, position, 1)
    if ord(text[position]) == 0x200D and _is_emojiish(left) and _is_emojiish(right):
        return True
    left_script, right_script = _script(left), _script(right)
    return left_script == right_script and left_script not in {
        "Common",
        "Inherited",
        "Latin",
        "Other",
    }


def _meaningful_variation(text: str, position: int) -> bool:
    left = _nearest_base(text, position, -1)
    immediate_right = text[position + 1] if position + 1 < len(text) else ""
    cp = ord(text[position])
    if not left:
        return False
    if _is_emojiish(left):
        return True
    if cp >= 0xE0100:
        return _script(left) == "Han"
    if cp == 0xFE0F and left in "#*0123456789" and ord(immediate_right or "\0") == 0x20E3:
        return True
    # Standardized variation sequences are overwhelmingly non-ASCII.  Keeping
    # them avoids corrupting mathematical symbols and ideographic variants.
    return ord(left) >= 0x80


def _has_rtl_context(text: str, position: int) -> bool:
    start, end = max(0, position - 64), min(len(text), position + 65)
    return any(unicodedata.bidirectional(ch) in _RTL_BIDI for ch in text[start:end])


def _valid_emoji_tag_positions(text: str) -> set[int]:
    """Positions belonging to a syntactically valid emoji tag sequence."""
    valid: set[int] = set()
    position = 0
    while position < len(text):
        if ord(text[position]) != 0x1F3F4:
            position += 1
            continue
        cursor = position + 1
        while cursor < len(text) and 0xE0020 <= ord(text[cursor]) <= 0xE007E:
            cursor += 1
        if cursor > position + 1 and cursor < len(text) and ord(text[cursor]) == 0xE007F:
            valid.update(range(position + 1, cursor + 1))
            position = cursor
        position += 1
    return valid


def _token_span(text: str, position: int) -> tuple[int, int]:
    def belongs(ch: str) -> bool:
        return ch == "_" or ch.isalnum() or unicodedata.category(ch).startswith("M")

    start, end = position, position + 1
    while start and belongs(text[start - 1]):
        start -= 1
    while end < len(text) and belongs(text[end]):
        end += 1
    return start, end


def _homoglyph_disposition(text: str, position: int) -> tuple[Disposition, str]:
    start, end = _token_span(text, position)
    token = text[start:end]
    scripts = {
        script for ch in token if (script := _script(ch)) not in {"Common", "Inherited", "Other"}
    }
    if "Latin" in scripts and len(scripts) > 1:
        return "actionable", "cross-script token mixes Latin with an ASCII confusable"
    if len(scripts) > 1:
        return "contextual", "token mixes multiple writing systems"
    return "informational", "confusable occurs in a single-script token"


def _occurrence_disposition(
    text: str,
    position: int,
    category: str,
    valid_emoji_tags: set[int],
) -> tuple[Disposition, str]:
    cp = ord(text[position])
    if category == "homoglyph":
        return _homoglyph_disposition(text, position)
    if category == "zero_width":
        if cp == 0xFEFF and position == 0:
            return "informational", "leading Unicode byte-order mark"
        if cp in {0x200C, 0x200D} and _meaningful_join_control(text, position):
            return "informational", "valid emoji or script-shaping join control"
        if cp in {0x2060}:
            return "contextual", "word-joining behavior may be intentional"
        return "actionable", "no recognized shaping or document-boundary context"
    if category == "variation_selector":
        if _meaningful_variation(text, position):
            return "informational", "selector follows a compatible emoji or non-ASCII base"
        return "actionable", "selector has no recognized glyph-selection context"
    if category == "tags_block":
        if position in valid_emoji_tags:
            return "informational", "member of a syntactically valid emoji tag sequence"
        return "actionable", "tag is outside a valid emoji tag sequence"
    if category == "bidi_control":
        if _has_rtl_context(text, position):
            return "contextual", "bidirectional control occurs near strong RTL text"
        return "actionable", "bidirectional control occurs without nearby RTL text"
    if category == "exotic_space":
        return "contextual", "spacing distinction may be typographic"
    if category == "soft_hyphen":
        return "contextual", "conditional hyphen may be intentional typography"
    if cp in {0x115F, 0x1160, 0x17B4, 0x17B5}:
        left = _nearest_base(text, position, -1)
        right = _nearest_base(text, position, 1)
        if _script(left) in {"Hangul", "Khmer"} or _script(right) in {"Hangul", "Khmer"}:
            return "informational", "format character occurs in its native script"
    return "contextual", "format character requires application-specific interpretation"


def _display_token(cp: int, category: str, action: str, token: str) -> str:
    if action == "homoglyph":
        return f"{_script_tag(chr(cp))}_{token.upper()}"
    if category == "variation_selector":
        number = cp - 0xFE00 + 1 if cp <= 0xFE0F else cp - 0xE0100 + 17
        return f"VS{number}"
    if category == "tags_block":
        return f"TAG_{cp - 0xE0000:X}"
    return token


def _classify(ch: str) -> tuple[str, str, str, str] | None:
    entry = _TABLE.get(ord(ch))
    if entry is not None:
        return entry
    if ord(ch) in _CONFUSABLE_LETTERS:
        return ("homoglyph", "homoglyph", CONFUSABLES_TO_ASCII[ord(ch)], "mixed_script")
    return None


def _grapheme_indices(text: str) -> list[int]:
    """Return extended-grapheme-like indices without adding a runtime dependency."""
    indices: list[int] = []
    current = -1
    previous = ""
    regional_count = 0
    for ch in text:
        cp = ord(ch)
        continuing = current >= 0 and (
            unicodedata.category(ch).startswith("M")
            or cp in {0x200C, 0x200D}
            or ord(previous or "\0") == 0x200D
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF
            or 0x1F3FB <= cp <= 0x1F3FF
            or 0xE0000 <= cp <= 0xE007F
            or cp == 0x20E3
        )
        if 0x1F1E6 <= cp <= 0x1F1FF:
            continuing = current >= 0 and regional_count % 2 == 1
            regional_count += 1
        else:
            regional_count = 0
        if not continuing:
            current += 1
        indices.append(current)
        previous = ch
    return indices


def analyze(text: str) -> dict[str, Any]:
    """Analyze Unicode artifacts with contextual per-occurrence evidence.

    ``unicode.total_flags`` remains the compatibility field, but excludes
    observations confidently recognized as legitimate.  All observations are
    still present in ``findings`` and counted by ``observations_total``.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    valid_emoji_tags = _valid_emoji_tag_positions(text)
    graphemes = _grapheme_indices(text)
    byte_offsets: list[int] = []
    byte_offset = 0
    for ch in text:
        byte_offsets.append(byte_offset)
        byte_offset += len(ch.encode("utf-8"))

    hits: dict[int, list[dict[str, Any]]] = {}
    annotated: list[str] = []
    for position, ch in enumerate(text):
        entry = _classify(ch)
        if entry is None:
            annotated.append(ch)
            continue
        category, action, token, _ = entry
        disposition, context = _occurrence_disposition(text, position, category, valid_emoji_tags)
        occurrence = {
            "position": position,
            "byte_offset": byte_offsets[position],
            "grapheme_index": graphemes[position],
            "disposition": disposition,
            "context": context,
        }
        hits.setdefault(ord(ch), []).append(occurrence)
        annotated.append(f"⟨{_display_token(ord(ch), category, action, token)}⟩")

    findings: list[dict[str, Any]] = []
    for cp in sorted(hits):
        ch = chr(cp)
        category = _classify(ch)[0]  # type: ignore[index]
        occurrences = hits[cp]
        disposition = max(
            (item["disposition"] for item in occurrences),
            key=lambda value: _DISPOSITION_ORDER[value],
        )
        disposition_counts = {
            key: sum(item["disposition"] == key for item in occurrences)
            for key in ("actionable", "contextual", "informational")
        }
        findings.append(
            {
                "category": category,
                "codepoint": _codepoint(ch),
                "char": ch,
                "name": _char_name(ch),
                "count": len(occurrences),
                "positions": [item["position"] for item in occurrences],
                "risk": RISK_BY_CATEGORY[category],
                "explanation": EXPLANATIONS[category],
                "disposition": disposition,
                "actionable": disposition == "actionable",
                "disposition_counts": disposition_counts,
                "occurrences": occurrences,
            }
        )

    def count_category(category: str) -> int:
        return sum(finding["count"] for finding in findings if finding["category"] == category)

    disposition_totals = {
        key: sum(finding["disposition_counts"][key] for finding in findings)
        for key in ("actionable", "contextual", "informational")
    }
    suspicious_total = disposition_totals["actionable"] + disposition_totals["contextual"]
    invisible_suspicious = sum(
        occurrence["disposition"] != "informational"
        for finding in findings
        if finding["category"] not in ("exotic_space", "homoglyph")
        for occurrence in finding["occurrences"]
    )
    return {
        "unicode": {
            "total_flags": suspicious_total,
            "observations_total": sum(disposition_totals.values()),
            "actionable_count": disposition_totals["actionable"],
            "contextual_count": disposition_totals["contextual"],
            "informational_count": disposition_totals["informational"],
            "findings": findings,
            "annotated_text": "".join(annotated),
            "policy_version": UNICODE_POLICY_VERSION,
        },
        "stats": {
            "char_count": len(text),
            "grapheme_count": graphemes[-1] + 1 if graphemes else 0,
            "utf8_byte_count": byte_offset,
            "invisible_char_count": invisible_suspicious,
            "invisible_observation_count": sum(
                finding["count"]
                for finding in findings
                if finding["category"] not in ("exotic_space", "homoglyph")
            ),
            "exotic_space_count": count_category("exotic_space"),
            "homoglyph_count": count_category("homoglyph"),
        },
    }


def _dominant_is_latin(text: str) -> bool:
    latin = non_latin = 0
    for ch in text:
        script = _script(ch)
        if script == "Latin":
            latin += 1
        elif script not in {"Common", "Inherited", "Other"}:
            non_latin += 1
    return latin >= non_latin


def _skeleton_confusables(text: str) -> tuple[str, int]:
    count = 0

    def map_token(token: str) -> str:
        nonlocal count
        out: list[str] = []
        for ch in token:
            replacement = CONFUSABLES_TO_ASCII.get(ord(ch))
            if replacement is not None:
                out.append(replacement)
                count += 1
            else:
                out.append(ch)
        return "".join(out)

    if _dominant_is_latin(text):
        return map_token(text), count
    out: list[str] = []
    for token in re.split(r"(\s+)", text):
        if not token or token.isspace():
            out.append(token)
            continue
        has_latin = any(_script(ch) == "Latin" for ch in token)
        has_confusable = any(ord(ch) in CONFUSABLES_TO_ASCII for ch in token)
        out.append(map_token(token) if has_latin and has_confusable else token)
    return "".join(out), count


def _safe_preserve(
    text: str,
    position: int,
    safe_rule: str,
    valid_emoji_tags: set[int],
) -> bool:
    if safe_rule == "preserve":
        return True
    if safe_rule in {"delete", "space"}:
        return False
    if safe_rule == "leading_bom":
        return position == 0
    if safe_rule == "join_context":
        return _meaningful_join_control(text, position)
    if safe_rule == "variation_context":
        return _meaningful_variation(text, position)
    if safe_rule == "emoji_tag_context":
        return position in valid_emoji_tags
    if safe_rule == "bidi_context":
        return _has_rtl_context(text, position)
    if safe_rule == "script_context":
        disposition, _ = _occurrence_disposition(
            text, position, _TABLE[ord(text[position])][0], valid_emoji_tags
        )
        return disposition == "informational"
    return False


def _edit(
    *,
    position: int,
    output_position: int,
    byte_offset: int,
    original: str,
    replacement: str,
    category: str,
    action: str,
    reason: str,
    stage: str = "policy",
) -> dict[str, Any]:
    return {
        "position": position,
        "output_position": output_position,
        "byte_offset": byte_offset,
        "original": original,
        "replacement": replacement,
        "original_codepoints": [_codepoint(ch) for ch in original],
        "replacement_codepoints": [_codepoint(ch) for ch in replacement],
        "category": category,
        "action": action,
        "reason": reason,
        "stage": stage,
        "reversible": True,
    }


def _diff_edits(before: str, after: str, category: str, stage: str) -> list[dict[str, Any]]:
    edits: list[dict[str, Any]] = []
    byte_offsets = [0]
    for ch in before:
        byte_offsets.append(byte_offsets[-1] + len(ch.encode("utf-8")))
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    for opcode, start, end, replacement_start, replacement_end in matcher.get_opcodes():
        if opcode == "equal":
            continue
        original = before[start:end]
        replacement = after[replacement_start:replacement_end]
        edits.append(
            _edit(
                position=start,
                output_position=replacement_start,
                byte_offset=byte_offsets[start],
                original=original,
                replacement=replacement,
                category=category,
                action=opcode,
                reason=f"{stage} transformed canonically related text",
                stage=stage,
            )
        )
    return edits


def _bind_edits(
    edits: Sequence[dict[str, Any]], source: str, cleaned: str
) -> tuple[dict[str, Any], ...]:
    """Bind a reversible edit list to the exact source and output documents."""
    if not edits:
        return ()
    source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    cleaned_sha256 = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    return tuple(
        {
            **item,
            "manifest_input_sha256": source_sha256,
            "manifest_output_sha256": cleaned_sha256,
        }
        for item in edits
    )


def sanitize_with_edits(
    text: str,
    profile: SanitizeProfile = "safe",
    *,
    normalize: bool = True,
) -> tuple[str, dict[str, int], tuple[dict[str, Any], ...]]:
    """Sanitize and return a reversible, ordered edit manifest.

    ``normalize=False`` is useful for source-file fixes: it guarantees that the
    only changes are policy findings explicitly represented in the manifest.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if profile not in ("safe", "aggressive"):
        raise ValueError("'profile' must be 'safe' or 'aggressive'.")

    valid_emoji_tags = _valid_emoji_tag_positions(text)
    by_category: dict[str, int] = {}
    edits: list[dict[str, Any]] = []
    stripped: list[str] = []
    byte_offset = 0
    output_position = 0
    for position, ch in enumerate(text):
        entry = _TABLE.get(ord(ch))
        if entry is None:
            stripped.append(ch)
            byte_offset += len(ch.encode("utf-8"))
            output_position += 1
            continue
        category, action, _, safe_rule = entry
        if profile == "safe" and _safe_preserve(text, position, safe_rule, valid_emoji_tags):
            stripped.append(ch)
            byte_offset += len(ch.encode("utf-8"))
            output_position += 1
            continue
        replacement = "" if action == "delete" else " "
        disposition, reason = _occurrence_disposition(text, position, category, valid_emoji_tags)
        edits.append(
            _edit(
                position=position,
                output_position=output_position,
                byte_offset=byte_offset,
                original=ch,
                replacement=replacement,
                category=category,
                action=action,
                reason=f"{disposition}: {reason}",
            )
        )
        by_category[category] = by_category.get(category, 0) + 1
        stripped.append(replacement)
        byte_offset += len(ch.encode("utf-8"))
        output_position += len(replacement)
    cleaned = "".join(stripped)

    if profile == "safe":
        if normalize:
            normalized = unicodedata.normalize("NFC", cleaned)
            edits.extend(_diff_edits(cleaned, normalized, "normalization", "NFC"))
            cleaned = normalized
        return cleaned, by_category, _bind_edits(edits, text, cleaned)

    if normalize:
        normalized = unicodedata.normalize("NFKC", cleaned)
        edits.extend(_diff_edits(cleaned, normalized, "normalization", "NFKC"))
    else:
        normalized = cleaned
    skeletoned, homoglyph_count = _skeleton_confusables(normalized)
    edits.extend(_diff_edits(normalized, skeletoned, "homoglyph", "confusable_skeleton"))
    if homoglyph_count:
        by_category["homoglyph"] = by_category.get("homoglyph", 0) + homoglyph_count
    return skeletoned, by_category, _bind_edits(edits, text, skeletoned)


def sanitize(text: str, profile: SanitizeProfile = "safe") -> tuple[str, dict[str, int]]:
    """Sanitize Unicode covert channels and return text plus edit counts."""
    cleaned, counts, _ = sanitize_with_edits(text, profile=profile)
    return cleaned, counts


def reverse_edits(cleaned_text: str, edits: Sequence[dict[str, Any]]) -> str:
    """Best-effort reversal of a manifest returned by :func:`sanitize_with_edits`.

    Edits are replayed by stage in reverse order.  A mismatch fails closed so a
    manifest can never silently corrupt a different document.
    """
    items = tuple(edits)
    if items:
        expected_output = items[0].get("manifest_output_sha256")
        declared_outputs = {item.get("manifest_output_sha256") for item in items}
        if len(declared_outputs) != 1:
            raise ValueError("edit manifest contains inconsistent output bindings")
        if (
            isinstance(expected_output, str)
            and hashlib.sha256(cleaned_text.encode("utf-8")).hexdigest() != expected_output
        ):
            raise ValueError("edit manifest does not match cleaned text")
    value = cleaned_text
    for item in reversed(items):
        position = int(item.get("output_position", item["position"]))
        original = str(item["original"])
        replacement = str(item["replacement"])
        if value[position : position + len(replacement)] != replacement:
            raise ValueError("edit manifest does not match cleaned text")
        value = value[:position] + original + value[position + len(replacement) :]
    if items:
        expected_input = items[0].get("manifest_input_sha256")
        declared_inputs = {item.get("manifest_input_sha256") for item in items}
        if len(declared_inputs) != 1:
            raise ValueError("edit manifest contains inconsistent input bindings")
        if (
            isinstance(expected_input, str)
            and hashlib.sha256(value.encode("utf-8")).hexdigest() != expected_input
        ):
            raise ValueError("edit manifest does not reconstruct its bound source")
    return value
