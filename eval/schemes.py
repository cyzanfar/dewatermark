"""Watermark schemes for the efficacy harness — three distinct families so a
removal win can't be a single-scheme artifact:

  KGW      context-dependent green-list   (Kirchenbauer, arXiv:2301.10226)
  Unigram  fixed global green-list        (Zhao, arXiv:2306.17439)
  EXP      context-hash Gumbel, distortion-free  (Aaronson; Kuditipudi arXiv:2307.15593)

Each scheme exposes:
  generate(prompt, tok, model, max_new_tokens, seed, watermarked) -> str
  detect(text, tok) -> float          # higher = more watermarked
  flag_threshold                      # nominal single-sample flag line (calibration
                                      # in metrics.py is what the report actually uses)

SIR/SemStamp (need a trained embedding model) and SynthID-Text tournament sampling
are documented as future rows in RESULTS.md; they require infrastructure beyond a
self-contained CPU harness.
"""

from __future__ import annotations

import hashlib
import json
import math
import random

try:
    from . import kgw  # type: ignore
except ImportError:  # direct ``python eval/run_eval.py`` compatibility
    import kgw  # type: ignore

load_model = kgw.load_model


def generate_plain(prompt, tok, model, n, seed):
    seed_everything(seed)
    return kgw.generate(prompt, tok, model, max_new_tokens=n, watermarked=False, seed=seed)


GAMMA = 0.25
DELTA = 2.0
UNIGRAM_KEY = 2718281829
EXP_KEY = 1618033988
EXP_DECODING = {
    "do_sample": True,
    "temperature": 0.7,
    "top_p": 0.95,
}
_DEFAULT_STRENGTH = {"KGW": DELTA, "Unigram": DELTA}
_STRENGTH = dict(_DEFAULT_STRENGTH)


def seed_everything(seed: int) -> None:
    """Seed every RNG used by bundled schemes and request deterministic kernels."""
    random.seed(seed)
    try:
        import numpy

        numpy.random.seed(seed % (2**32))
    except ImportError:
        pass
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        torch.use_deterministic_algorithms(True, warn_only=True)
    except ImportError:
        pass


def sample_seed(root_seed: int, *coordinates: object) -> int:
    """Derive a deterministic 63-bit seed independent of loop ordering.

    A seed is a truncated cryptographic identity, not a counter.  Keeping the
    high bit clear makes the value portable across RNGs that accept signed
    64-bit seeds while retaining substantially more collision resistance than
    the previous 31-bit reduction.
    """
    value = json.dumps([root_seed, *coordinates], sort_keys=True, separators=(",", ":"))
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big") & ((1 << 63) - 1)


def _configuration_sha256(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


# Public partition labels are independent random values, not hashes of the small
# integer reference keys. Publishing a key-derived digest would give an offline
# oracle for guessing those keys. These fixed CSPRNG-generated IDs identify the
# bundled fixture configurations without revealing anything about key material.
_OPAQUE_KEY_IDS = {
    "KGW": "4a8161a4fe3ec7f1b01b4751d52fcdfbb23a1791494c0f532bc40bfe57669fe7",
    "Unigram": "bece4875328daed16f9fb07d2fb287f44382cc6e2b3b3ff8797a208da0228220",
    "EXP": "eadb1902b9c377239dc78b5c4fcf3d9dedfc22ca8d9993e5eda3e5d010fb59ed",
}


def _set_strength(name):
    return lambda value: _STRENGTH.__setitem__(name, float(value))


def reset_strengths() -> None:
    """Reset mutable calibration state for deterministic repeated runs."""
    _STRENGTH.clear()
    _STRENGTH.update(_DEFAULT_STRENGTH)


# --------------------------------------------------------------------------- KGW
def kgw_generate(prompt, tok, model, n, seed, watermarked=True):
    seed_everything(seed)
    return kgw.generate(
        prompt,
        tok,
        model,
        max_new_tokens=n,
        watermarked=watermarked,
        seed=seed,
        delta=_STRENGTH["KGW"],
    )


def kgw_detect(text, tok):
    return kgw.detect(text, tok)["z"]


# ----------------------------------------------------------------------- Unigram
def _unigram_green(vocab_size, gamma=GAMMA):
    import torch

    g = torch.Generator()
    g.manual_seed(UNIGRAM_KEY)
    return torch.randperm(vocab_size, generator=g)[: int(vocab_size * gamma)]


class _UnigramProcessor:
    def __init__(self, vocab_size, gamma=GAMMA, delta=DELTA):
        self.green = None
        self.vocab_size = vocab_size
        self.gamma = gamma
        self.delta = delta

    def __call__(self, input_ids, scores):
        if self.green is None:
            self.green = _unigram_green(self.vocab_size, self.gamma)
        scores = scores.clone()
        scores[0, self.green] += self.delta
        return scores


def unigram_generate(prompt, tok, model, n, seed, watermarked=True):
    import torch
    from transformers import LogitsProcessorList

    if not watermarked:
        return generate_plain(prompt, tok, model, n, seed)
    seed_everything(seed)
    messages = [{"role": "user", "content": prompt}]
    try:
        inputs = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt")
        if hasattr(inputs, "input_ids"):
            inputs = inputs.input_ids
    except Exception:
        inputs = tok(prompt, return_tensors="pt").input_ids
    lp = LogitsProcessorList([_UnigramProcessor(len(tok), delta=_STRENGTH["Unigram"])])
    with torch.no_grad():
        out = model.generate(
            inputs,
            max_new_tokens=n,
            do_sample=True,
            temperature=0.7,
            top_p=0.95,
            logits_processor=lp,
            pad_token_id=tok.eos_token_id,
        )
    return tok.decode(out[0][inputs.shape[-1] :], skip_special_tokens=True)


def unigram_detect(text, tok, gamma=GAMMA):
    ids = tok(text, return_tensors="pt", add_special_tokens=False).input_ids[0]
    green = set(_unigram_green(len(tok), gamma).tolist())
    if ids.numel() == 0:
        return 0.0
    hits = sum(1 for t in ids.tolist() if t in green)
    T = ids.numel()
    denom = math.sqrt(T * gamma * (1 - gamma))
    return (hits - gamma * T) / denom if denom else 0.0


# --------------------------------------------------------------------------- EXP
def _exp_uniforms(prev_token_id, vocab_size):
    import torch

    g = torch.Generator()
    g.manual_seed(EXP_KEY * int(prev_token_id) + 7)
    return torch.rand(vocab_size, generator=g)


class _EXPProcessor:
    def __call__(self, input_ids, scores):
        import torch

        vocab = scores.shape[-1]
        u = _exp_uniforms(int(input_ids[0, -1].item()), vocab)
        probs = torch.softmax(scores[0], dim=-1).clamp_min(1e-12)
        # Gumbel key: choose argmax_v u_v^(1/p_v)  ==  argmax_v log(u_v)/p_v
        key = torch.log(u.clamp_min(1e-12)) / probs
        choice = int(torch.argmax(key).item())
        forced = torch.full_like(scores, -1e9)
        forced[0, choice] = 0.0
        return forced


def exp_generate(prompt, tok, model, n, seed, watermarked=True):
    import torch
    from transformers import LogitsProcessorList

    seed_everything(seed)
    messages = [{"role": "user", "content": prompt}]
    try:
        inputs = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt")
        if hasattr(inputs, "input_ids"):
            inputs = inputs.input_ids
    except Exception:
        inputs = tok(prompt, return_tensors="pt").input_ids
    # The matched plain control follows this exact path with the exact same
    # decoding arguments.  Presence of the watermark processor is the only
    # generation-configuration difference between the two conditions.
    lp = LogitsProcessorList([_EXPProcessor()]) if watermarked else None
    with torch.no_grad():
        out = model.generate(
            inputs,
            max_new_tokens=n,
            **EXP_DECODING,
            logits_processor=lp,
            pad_token_id=tok.eos_token_id,
        )
    return tok.decode(out[0][inputs.shape[-1] :], skip_special_tokens=True)


def exp_detect(text, tok):
    ids = tok(text, return_tensors="pt", add_special_tokens=False).input_ids[0]
    if ids.numel() < 2:
        return 0.0
    total, n = 0.0, 0
    ids_l = ids.tolist()
    for i in range(1, len(ids_l)):
        u = _exp_uniforms(ids_l[i - 1], len(tok))
        val = float(u[ids_l[i]].item())
        total += -math.log(max(1e-12, 1.0 - val))
        n += 1
    # Normalize to a ~z-like statistic: null mean of -log(1-U) is 1, var is 1.
    return (total / n - 1.0) * math.sqrt(n) if n else 0.0


SCHEMES = {
    "KGW": {
        "generate": kgw_generate,
        "detect": kgw_detect,
        "flag_threshold": 4.0,
        "family": "context green-list",
        "source": "internal reference",
        "independent": False,
        "set_strength": _set_strength("KGW"),
        "manifest": {
            "schema_version": "1.0",
            "id": "kgw-left-hash-h1",
            "family": "context green-list",
            "source": "https://arxiv.org/abs/2301.10226",
            "implementation": "bundled-independent-reimplementation",
            "implementation_version": "1",
            "independent": False,
            "vendor_validated": False,
            "score_direction": "higher",
            "minimum_tokens": 2,
            # Legacy field name; the value is a random non-secret public ID.
            "key_fingerprint": _OPAQUE_KEY_IDS["KGW"],
            "configuration_sha256": _configuration_sha256(
                {"gamma": GAMMA, "context_width": 1, "duplicate_bigrams": "ignored"}
            ),
            "calibration": {"method": "held_out_empirical_null", "threshold_operator": ">"},
        },
    },
    "Unigram": {
        "generate": unigram_generate,
        "detect": unigram_detect,
        "flag_threshold": 4.0,
        "family": "fixed green-list",
        "source": "internal reference",
        "independent": False,
        "set_strength": _set_strength("Unigram"),
        "manifest": {
            "schema_version": "1.0",
            "id": "unigram-fixed-greenlist",
            "family": "fixed green-list",
            "source": "https://arxiv.org/abs/2306.17439",
            "implementation": "bundled-independent-reimplementation",
            "implementation_version": "1",
            "independent": False,
            "vendor_validated": False,
            "score_direction": "higher",
            "minimum_tokens": 1,
            # Legacy field name; the value is a random non-secret public ID.
            "key_fingerprint": _OPAQUE_KEY_IDS["Unigram"],
            "configuration_sha256": _configuration_sha256({"gamma": GAMMA}),
            "calibration": {"method": "held_out_empirical_null", "threshold_operator": ">"},
        },
    },
    "EXP": {
        "generate": exp_generate,
        "detect": exp_detect,
        "flag_threshold": 4.0,
        "family": "simplified previous-token Gumbel reference",
        "source": "internal approximation",
        "independent": False,
        "manifest": {
            "schema_version": "1.0",
            "id": "exp-prev-token-approximation",
            "family": "Gumbel distortion-free",
            "source": "https://arxiv.org/abs/2307.15593",
            "implementation": "bundled-simplified-approximation",
            "implementation_version": "1",
            "independent": False,
            "vendor_validated": False,
            "score_direction": "higher",
            "minimum_tokens": 2,
            # Legacy field name; the value is a random non-secret public ID.
            "key_fingerprint": _OPAQUE_KEY_IDS["EXP"],
            "configuration_sha256": _configuration_sha256(
                {"context_width": 1, "decoding": EXP_DECODING}
            ),
            "matched_control": {
                "generation_arguments": dict(EXP_DECODING),
                "only_difference": "logits_processor",
            },
            "calibration": {"method": "held_out_empirical_null", "threshold_operator": ">"},
            "limitations": ["not_official_exp_its_implementation"],
        },
    },
}


def scheme_manifests(names: list[str] | None = None) -> dict[str, dict]:
    """Return static, JSON-safe identities without loading models."""
    selected = names if names is not None else list(SCHEMES)
    return {name: dict(SCHEMES[name]["manifest"]) for name in selected}


if __name__ == "__main__":
    tok, model = load_model()
    prompt = "Explain how the printing press changed the spread of information."
    for name, sc in SCHEMES.items():
        wm = sc["generate"](prompt, tok, model, 120, 1, True)
        pl = generate_plain(prompt, tok, model, 120, 2)
        print(
            f"{name:8s} watermarked score={sc['detect'](wm, tok):6.2f}  "
            f"plain score={sc['detect'](pl, tok):6.2f}"
        )
