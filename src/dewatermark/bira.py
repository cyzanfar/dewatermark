"""BIRA — Bias-Inversion Rewrite Attack (arXiv:2509.23019).

Estimate a proxy green-list G-hat from the watermarked text via per-token
self-information (high-surprisal tokens are the ones a green-list watermark most
likely promoted), then locally re-generate the text while applying a NEGATIVE
decoding-time logit bias (-beta) to every token ID in G-hat. This directly
demotes the tokens that carry the detection signal — a single-pass, reference-free
scrub that needs only logit access to a local model (unlike SIRA, which routes
through the remote infill API).

A ~0.5B local model (default) demonstrates the mechanism on CPU; set LOCAL_LM to a
~7-8B instruct model to approach the published quality/evasion numbers.
"""

from __future__ import annotations

from typing import Optional

from . import scoring
from .chunking import split_for_config
from .config import DewatermarkConfig, resolve
from .prompt_safety import INERT_DATA_INSTRUCTION, inert_block
from .quality import evaluate_candidate
from .request_context import (
    checkpoint,
    current_request_context,
    public_quality_report,
    safe_error,
)


class BIRALogitsProcessor:
    """Subtract `beta` from the logits of every proxy-green token at each step."""

    def __init__(self, green_ids, beta: float):
        self.green_ids = green_ids
        self.beta = beta

    def __call__(self, input_ids, scores):
        if self.green_ids is not None and self.beta:
            green_ids = (
                self.green_ids.to(scores.device)
                if hasattr(self.green_ids, "to")
                else self.green_ids
            )
            scores[:, green_ids] -= self.beta
        return scores


def estimate_green(
    text: str, quantile: float = 0.7, config: Optional[DewatermarkConfig] = None
) -> list[int]:
    """Proxy green-list: token IDs whose surprisal is at/above `quantile` here."""
    si = scoring.self_information(text, config)
    if not si:
        return []
    bits = sorted(t["surprisal_bits"] for t in si)
    thresh = bits[min(int(len(bits) * quantile), len(bits) - 1)]
    return sorted({t["token_id"] for t in si if t["surprisal_bits"] >= thresh})


_REWRITE_SYSTEM = (
    "Rewrite the user's text in your own words. Preserve every fact, name, number, "
    "and the overall meaning exactly. Do not add commentary or disclaimers. Output "
    f"only the rewritten text. {INERT_DATA_INSTRUCTION}"
)


def bira_rewrite(
    text: str,
    beta: float = 6.0,
    quantile: float = 0.7,
    max_new_tokens: Optional[int] = None,
    max_restarts: int = 3,
    bias_backoff: float = 0.65,
    config: Optional[DewatermarkConfig] = None,
) -> tuple[str, dict]:
    """Rewrite `text` with a negative bias on the proxy-green token IDs.

    Dispatches to the Fireworks API backend when configured (no local model);
    otherwise runs the local transformers path below."""
    cfg = resolve(config)
    checkpoint()
    base_detail = {
        "stage": "bias_inversion",
        "implementation": "bira_proxy",
        "beta": beta,
        "quantile": quantile,
    }
    try:
        chunks = split_for_config(text, cfg)
    except Exception as exc:
        base_detail["error"] = safe_error("BIRA chunking", exc)
        base_detail["warning"] = "kept original"
        return text, base_detail
    if len(chunks) > 1:
        outputs, children = [], []
        for chunk in chunks:
            out, child = bira_rewrite(
                chunk, beta, quantile, max_new_tokens, max_restarts, bias_backoff, cfg
            )
            outputs.append(out)
            children.append(child)
        combined = "".join(outputs)
        detail = {
            "stage": "bias_inversion",
            "implementation": "bira_proxy",
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
    if cfg.resolved_lm_backend == "fireworks":
        from . import fireworks

        return fireworks.bira_rewrite(
            text, beta, quantile, cfg, max_restarts=max_restarts, bias_backoff=bias_backoff
        )

    detail = base_detail
    try:
        tok, model = scoring.load(cfg)
    except scoring.ScorerUnavailable as exc:
        detail["error"] = safe_error("local model unavailable", exc)
        return text, detail

    import torch
    from transformers import LogitsProcessorList

    try:
        green = estimate_green(text, quantile, cfg)
    except scoring.ScorerUnavailable as exc:
        detail["error"] = safe_error("local scoring failed", exc)
        detail["warning"] = "kept original"
        return text, detail
    detail["green_size"] = len(green)

    messages = [
        {"role": "system", "content": _REWRITE_SYSTEM},
        {"role": "user", "content": inert_block(text)},
    ]
    try:
        inputs = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt")
        if hasattr(inputs, "input_ids"):
            inputs = inputs.input_ids
    except Exception:
        inputs = tok(inert_block(text), return_tensors="pt").input_ids
    inputs = inputs.to(next(model.parameters()).device)

    green_t = torch.tensor(green, dtype=torch.long) if green else None
    budget = min(cfg.max_output_tokens, max_new_tokens or min(1024, int(inputs.shape[-1]) + 320))
    attempts = []
    current_beta = beta
    for restart in range(max(1, max_restarts)):
        checkpoint()
        lp = (
            LogitsProcessorList([BIRALogitsProcessor(green_t, current_beta)])
            if green_t is not None
            else None
        )
        context = current_request_context()
        reserved = budget
        reservation_made = False
        try:
            if context is not None:
                reserved = context.reserve_output_tokens(budget)
                reservation_made = True
            with scoring.inference_lock(cfg), torch.no_grad():
                out = model.generate(
                    inputs,
                    max_new_tokens=reserved,
                    do_sample=True,
                    temperature=1.0,
                    top_p=0.95,
                    logits_processor=lp,
                    pad_token_id=tok.eos_token_id,
                )
        except Exception as exc:
            if context is not None and reservation_made:
                # Generation failures rarely report partial usage. Charge the
                # conservative ceiling so retries cannot bypass the shared
                # request budget.
                context.reconcile_local_generation(reserved)
            attempts.append(
                {
                    "restart": restart,
                    "beta": round(current_beta, 3),
                    "error": safe_error("local generation", exc),
                }
            )
            current_beta *= bias_backoff
            continue
        generated_tokens = max(0, int(out.shape[-1]) - int(inputs.shape[-1]))
        if context is not None:
            context.reconcile_local_generation(generated_tokens)
        try:
            rewritten = tok.decode(out[0][inputs.shape[-1] :], skip_special_tokens=True).strip()
            quality = evaluate_candidate(text, rewritten, cfg)
        except Exception as exc:
            attempts.append(
                {
                    "restart": restart,
                    "beta": round(current_beta, 3),
                    "error": safe_error("local candidate evaluation", exc),
                }
            )
            current_beta *= bias_backoff
            continue
        public_quality = public_quality_report(quality)
        attempts.append(
            {"restart": restart, "beta": round(current_beta, 3), "quality": public_quality}
        )
        if quality.passed:
            detail["attempts"] = attempts
            detail["effective_beta"] = current_beta
            detail["tokens_after"] = len(rewritten.split())
            detail["quality"] = public_quality
            return rewritten, detail
        current_beta *= bias_backoff

    detail["attempts"] = attempts
    detail["warning"] = "all local rewrites failed deterministic quality gates; kept original"
    return text, detail
