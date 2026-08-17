"""Self-contained KGW (Kirchenbauer et al., arXiv:2301.10226) soft watermark.

Implements the "LeftHash / selfhash" scheme with context width h=1: the green
list for the next token is a pseudo-random gamma-fraction of the vocabulary,
seeded by the hash of the previous token. A bias of delta is added to green
logits at generation time. Detection recomputes green-list membership per
token and scores z = (|G| - gamma*T) / sqrt(T*gamma*(1-gamma)), skipping
duplicate bigram contexts (as in the reference implementation) so repeated
n-grams cannot inflate the score.

Run as a script for a smoke self-test (loads a small HF model on CPU).
"""

from __future__ import annotations

import argparse
import os

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

GAMMA = 0.25
DELTA = 2.0
HASH_KEY = 15485863  # large prime, as in the reference implementation
DEFAULT_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"


def _green_list(prev_token_id: int, vocab_size: int, gamma: float):
    """Seeded green-list partition: h=1 LeftHash on the previous token."""
    import torch

    rng = torch.Generator()
    rng.manual_seed(HASH_KEY * int(prev_token_id))
    greenlist_size = int(vocab_size * gamma)
    perm = torch.randperm(vocab_size, generator=rng)
    return perm[:greenlist_size]


class KGWLogitsProcessor:
    """Adds +delta to green-list logits, seeded by the previous token."""

    def __init__(self, vocab_size: int, gamma: float = GAMMA, delta: float = DELTA):
        self.vocab_size = vocab_size
        self.gamma = gamma
        self.delta = delta

    def __call__(self, input_ids, scores):
        # input_ids: (batch, seq); scores: (batch, vocab). Batch is 1 here.
        green = _green_list(input_ids[0, -1].item(), self.vocab_size, self.gamma)
        scores = scores.clone()
        scores[0, green] += self.delta
        return scores


def load_model(
    model_name: str = DEFAULT_MODEL,
    revision: str | None = None,
    allow_download: bool = False,
):
    """Load tokenizer + model for CPU generation (float32, small models only)."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        model_name, revision=revision, local_files_only=not allow_download
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        revision=revision,
        dtype=torch.float32,
        local_files_only=not allow_download,
    )
    model.eval()
    return tokenizer, model


def generate(
    prompt: str,
    tokenizer,
    model,
    max_new_tokens: int = 300,
    temperature: float = 0.7,
    watermarked: bool = True,
    gamma: float = GAMMA,
    delta: float = DELTA,
    seed: int | None = None,
) -> str:
    """Generate text, optionally with the KGW watermark applied."""
    import torch

    if seed is not None:
        torch.manual_seed(seed)

    messages = [{"role": "user", "content": prompt}]
    try:
        inputs = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        )
        if hasattr(inputs, "input_ids"):
            inputs = inputs.input_ids
    except Exception:
        inputs = tokenizer(prompt, return_tensors="pt").input_ids

    logits_processor = None
    if watermarked:
        from transformers import LogitsProcessorList

        logits_processor = LogitsProcessorList([KGWLogitsProcessor(len(tokenizer), gamma, delta)])

    with torch.no_grad():
        output_ids = model.generate(
            inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            temperature=temperature,
            top_p=0.95,
            logits_processor=logits_processor,
            pad_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(output_ids[0][inputs.shape[-1] :], skip_special_tokens=True)


def detect(
    text: str,
    tokenizer,
    gamma: float = GAMMA,
) -> dict:
    """KGW z-score over unique bigram contexts.

    Returns dict with z, green_hits (|G|), scored_tokens (T) and a
    `flagged` boolean at the z > 4 decision threshold.
    """
    import math

    token_ids = tokenizer(text, return_tensors="pt", add_special_tokens=False).input_ids[0]
    vocab_size = len(tokenizer)

    seen_contexts: set[tuple[int, int]] = set()
    green_hits = 0
    scored = 0
    for i in range(1, len(token_ids)):
        prev_tok, tok = int(token_ids[i - 1]), int(token_ids[i])
        if (prev_tok, tok) in seen_contexts:
            continue
        seen_contexts.add((prev_tok, tok))
        scored += 1
        green = _green_list(prev_tok, vocab_size, gamma)
        if bool((green == tok).any()):
            green_hits += 1

    if scored == 0:
        return {"z": 0.0, "green_hits": 0, "scored_tokens": 0, "flagged": False}

    expected = gamma * scored
    denom = math.sqrt(scored * gamma * (1 - gamma))
    z = (green_hits - expected) / denom
    return {
        "z": z,
        "green_hits": green_hits,
        "scored_tokens": scored,
        "flagged": z > 4.0,
    }


def _self_test(model_name: str, max_new_tokens: int, allow_download: bool) -> None:
    tokenizer, model = load_model(model_name, allow_download=allow_download)
    prompt = "Write a short paragraph about the history of the printing press."

    wm_text = generate(prompt, tokenizer, model, max_new_tokens=max_new_tokens, seed=0)
    z_wm = detect(wm_text, tokenizer)
    print(
        f"[watermarked] tokens_scored={z_wm['scored_tokens']} z={z_wm['z']:.2f} "
        f"flagged={z_wm['flagged']}"
    )
    assert z_wm["z"] > 4.0, f"expected watermarked text z > 4, got {z_wm['z']:.2f}"

    plain_text = generate(
        prompt, tokenizer, model, max_new_tokens=max_new_tokens, watermarked=False, seed=0
    )
    z_plain = detect(plain_text, tokenizer)
    print(
        f"[plain]       tokens_scored={z_plain['scored_tokens']} z={z_plain['z']:.2f} "
        f"flagged={z_plain['flagged']}"
    )
    assert abs(z_plain["z"]) < 4.0, f"expected plain text |z| < 4, got {z_plain['z']:.2f}"

    print("KGW self-test OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KGW watermark self-test")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-new-tokens", type=int, default=120)
    parser.add_argument("--allow-model-download", action="store_true")
    args = parser.parse_args()
    _self_test(args.model, args.max_new_tokens, args.allow_model_download)
