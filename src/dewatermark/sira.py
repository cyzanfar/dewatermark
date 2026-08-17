"""SIRA — Self-Information Rewrite Attack (arXiv:2505.05190).

Score every token's self-information under the local reference LM, mask the
top-epsilon most-surprising tokens (the ones most likely to carry a green-list
watermark), then regenerate just those spans via an LLM infill call, conditioned
on the surrounding text. Single pass; leaves low-surprisal tokens verbatim.
BIRA is the negative-bias counterpart; SIRA is the mask-and-regenerate one.
"""

from __future__ import annotations

from typing import Optional

from . import scoring
from .chunking import split_for_config
from .config import DewatermarkConfig, resolve
from .paraphraser import chat
from .prompt_safety import INERT_DATA_INSTRUCTION, inert_block, inert_blocks
from .quality import evaluate_candidate
from .request_context import checkpoint, public_quality_report, safe_error

# Absolute cap on masked spans. The infill goes to the remote LLM; reasoning
# models slow down superlinearly in the blank count, so keep it small enough to
# finish in time.
_MAX_MASK = 96

_REFERENCE_SYSTEM = (
    "Rewrite the delimited source at a similar length. Preserve every fact, name, "
    "number, URL, quotation, and negation. Output only the rewrite. "
    f"{INERT_DATA_INSTRUCTION}"
)

_INFILL_SYSTEM = (
    "You are a precise text-infilling engine. The user's text contains one or more "
    "[BLANK] placeholders. Replace EACH [BLANK] with a natural word or short phrase "
    "that fits the surrounding context and preserves the original meaning. Do NOT "
    "change, reorder, add, or remove any other text. Do NOT leave any [BLANK]. "
    "Use the supplied REFERENCE to recover information, but retain all unmasked "
    "source text exactly. Output ONLY the completed text, nothing else. "
    f"{INERT_DATA_INSTRUCTION}"
)


def _protected(token_str: str) -> bool:
    """Tokens we never blank: whitespace/punctuation-only, or containing digits."""
    s = token_str.strip()
    if not s:
        return True
    if any(ch.isdigit() for ch in s):
        return True
    if not any(ch.isalpha() for ch in s):
        return True
    return False


def select_mask(
    si: list[dict], epsilon: float = 0.3, max_mask: int = _MAX_MASK
) -> list[tuple[int, int]]:
    """Char spans of the top-epsilon highest-surprisal, non-protected tokens."""
    cand = [t for t in si if not _protected(t["token_str"]) and t["end"] > t["start"]]
    if not cand:
        return []
    cand.sort(key=lambda t: t["surprisal_bits"], reverse=True)
    k = min(max_mask, max(1, int(round(len(cand) * epsilon))))
    return sorted((t["start"], t["end"]) for t in cand[:k])


def _snap_to_words(text: str, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Expand each span to the enclosing whitespace-delimited word so we never
    regenerate a fragment in the middle of a word."""
    snapped = []
    for start, end in spans:
        while start > 0 and not text[start - 1].isspace():
            start -= 1
        while end < len(text) and not text[end].isspace():
            end += 1
        snapped.append((start, end))
    return sorted(set(snapped))


def merged_spans(text: str, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Word-snap and merge spans separated only by whitespace into single masks."""
    spans = _snap_to_words(text, spans)
    if not spans:
        return []
    merged = [list(spans[0])]
    for start, end in spans[1:]:
        gap = text[merged[-1][1] : start]
        if start <= merged[-1][1] or gap.strip() == "":
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def build_template(text: str, spans: list[tuple[int, int]]) -> tuple[str, int]:
    """[BLANK]-placeholder view of the masked text (used by tests / inspection)."""
    merged = merged_spans(text, spans)
    if not merged:
        return text, 0
    out, prev = [], 0
    for start, end in merged:
        out.append(text[prev:start])
        out.append("[BLANK]")
        prev = end
    out.append(text[prev:])
    return "".join(out), len(merged)


def sira_rewrite(
    text: str, epsilon: float = 0.3, config: Optional[DewatermarkConfig] = None
) -> tuple[str, dict]:
    """Mask top-epsilon surprisal tokens and regenerate them via LLM infill.

    Returns (rewritten_text, detail). Falls back to the original text on any
    failure so the pipeline never loses content.
    """
    cfg = resolve(config)
    checkpoint()
    base_detail = {"stage": "sira", "implementation": "sira_proxy", "epsilon": epsilon}
    try:
        chunks = split_for_config(text, cfg)
    except Exception as exc:
        base_detail["error"] = safe_error("SIRA chunking", exc)
        base_detail["warning"] = "kept original"
        return text, base_detail
    if len(chunks) > 1:
        outputs, children = [], []
        for chunk in chunks:
            out, child = sira_rewrite(chunk, epsilon, cfg)
            outputs.append(out)
            children.append(child)
        combined = "".join(outputs)
        detail = {
            "stage": "sira",
            "implementation": "sira_proxy",
            "chunked": True,
            "chunks": len(chunks),
            "children": children,
        }
        failures = sum(bool(child.get("error") or child.get("warning")) for child in children)
        detail["chunk_failures"] = failures
        try:
            quality = evaluate_candidate(text, combined, cfg)
        except Exception as exc:
            detail["error"] = safe_error("whole-document quality evaluation", exc)
            detail["warning"] = "kept original"
            return text, detail
        detail["whole_document_quality"] = public_quality_report(quality)
        if not quality.passed:
            detail["warning"] = "combined rewrite failed whole-document quality gates"
            return text, detail
        if failures:
            detail["warning"] = f"{failures} of {len(chunks)} chunks were unchanged or failed"
        return combined, detail
    detail = base_detail
    required_calls = 3 if cfg.resolved_lm_backend == "fireworks" else 2
    if cfg.max_remote_calls < required_calls:
        detail["error"] = f"SIRA requires a remote-call budget of at least {required_calls}"
        detail["warning"] = "kept original"
        return text, detail
    try:
        si = scoring.self_information(text, cfg)
    except Exception as exc:
        detail["error"] = safe_error("SIRA scorer", exc)
        detail["warning"] = "kept original"
        return text, detail
    if not si:
        detail["warning"] = "no scorable tokens; text unchanged"
        return text, detail

    try:
        spans = select_mask(si, epsilon)
        template, n_blanks = build_template(text, spans)
    except Exception as exc:
        detail["error"] = safe_error("SIRA mask selection", exc)
        detail["warning"] = "kept original"
        return text, detail
    detail["masked_tokens"] = len(spans)
    detail["blanks"] = n_blanks
    if n_blanks == 0:
        detail["warning"] = "nothing to mask"
        return text, detail
    infill_ready = cfg.llm_api_key or cfg.resolved_lm_backend == "fireworks"
    if not infill_ready:
        detail["warning"] = "no LLM key for infill; kept original"
        return text, detail

    # No max_tokens: reasoning models return empty content when the completion
    # budget is capped. Fail fast (45s) rather than hang: SIRA needs a quick
    # non-reasoning infill model; where the configured model is slow, it degrades
    # to a graceful no-op and BIAS-INVERSION (local) is the better choice.
    try:
        reference = chat(
            _REFERENCE_SYSTEM,
            inert_block(text),
            temperature=1.0,
            timeout=60,
            config=cfg,
        )
        prompt = (
            "<SOURCE>\n<REFERENCE>\n"
            + inert_blocks(source=template, reference=reference)
            + "\n</REFERENCE>\n</SOURCE>"
        )
        filled = chat(_INFILL_SYSTEM, prompt, temperature=1.0, timeout=60, config=cfg)
    except Exception as exc:
        detail["error"] = safe_error("SIRA infill", exc)
        detail["warning"] = "infill timed out/failed; kept original (use bias_inversion)"
        return text, detail

    try:
        quality = evaluate_candidate(text, filled, cfg)
    except Exception as exc:
        detail["error"] = safe_error("SIRA quality evaluation", exc)
        detail["warning"] = "kept original"
        return text, detail
    detail["quality"] = public_quality_report(quality)
    detail["reference_tokens"] = len(reference.split())
    if not quality.passed:
        detail["warning"] = "infill failed deterministic quality gates; kept original"
        return text, detail
    detail["tokens_after"] = len(filled.split())
    return filled, detail
