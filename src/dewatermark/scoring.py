"""Local causal-LM self-information (surprisal) scoring.

Green-list / distribution-shift watermarks (KGW, Unigram, SynthID tournament)
push generation toward pseudo-random "green" tokens. Those tokens are, on
average, ones the *base* model found less likely — i.e. higher self-information
(surprisal) -log2 p(token | prefix) under an un-watermarked reference LM. Scoring
every token localizes the ones most likely to carry the watermark, which is the
targeting signal the open-loop paraphraser never had:

  * SIRA (sira.py) masks the top-epsilon highest-surprisal tokens and refills them.
  * BIRA (bira.py) applies a negative decoding-time bias to the proxy-green IDs.

torch/transformers are imported lazily and the model is cached process-wide, so
importing this module is cheap and the sanitize-only path never loads a model.
"""

from __future__ import annotations

import gc
import math
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from .config import DewatermarkConfig, resolve
from .exceptions import BackendUnavailableError

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

_lock = threading.Lock()
_state: OrderedDict[str, dict] = OrderedDict()


class ScorerUnavailable(BackendUnavailableError):
    """Raised when the scoring model cannot be loaded (deps missing / disabled)."""


def backend(config: Optional[DewatermarkConfig] = None) -> str:
    """The effective LM backend: "fireworks" or "local"."""
    return resolve(config).resolved_lm_backend


def available(config: Optional[DewatermarkConfig] = None) -> bool:
    """True when a self-information scorer can actually run in this environment."""
    cfg = resolve(config)
    if cfg.scorer_provider:
        from .providers import get_provider

        try:
            return bool(get_provider(cfg.scorer_provider)(cfg).available())
        except Exception:
            return False
    if cfg.resolved_lm_backend == "fireworks":
        from . import fireworks

        return fireworks.available(cfg)
    if not cfg.local_lm_enabled:
        return False
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except Exception:
        return False
    return cfg.allow_model_download or model_cached(cfg.local_lm)


def model_cached(model_name: str) -> bool:
    """Check local model availability without network access or model loading."""
    if Path(model_name).expanduser().exists():
        return True
    try:
        from huggingface_hub import try_to_load_from_cache

        return isinstance(try_to_load_from_cache(model_name, "config.json"), str)
    except Exception:
        return False


def load(config: Optional[DewatermarkConfig] = None):
    """Load and cache (tokenizer, model) for the configured local LM."""
    cfg = resolve(config)
    if not cfg.local_lm_enabled:
        raise ScorerUnavailable("local_lm_enabled is false")
    with _lock:
        if cfg.local_lm in _state:
            entry = _state.pop(cfg.local_lm)
            _state[cfg.local_lm] = entry
            return entry["tok"], entry["model"]
        evicted = False
        while len(_state) >= cfg.model_cache_size:
            _state.popitem(last=False)
            evicted = True
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except Exception as exc:  # pragma: no cover - env dependent
            raise ScorerUnavailable(f"torch/transformers unavailable: {exc}") from exc
        if evicted:
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            if getattr(torch, "mps", None) and hasattr(torch.mps, "empty_cache"):
                torch.mps.empty_cache()
        try:
            local_only = not cfg.allow_model_download
            tok = AutoTokenizer.from_pretrained(cfg.local_lm, local_files_only=local_only)
            if torch.cuda.is_available():
                device = torch.device("cuda")
                dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
            elif getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
                device, dtype = torch.device("mps"), torch.float16
            else:
                device, dtype = torch.device("cpu"), torch.float32
            model = AutoModelForCausalLM.from_pretrained(
                cfg.local_lm, dtype=dtype, local_files_only=local_only
            )
            model.to(device)
        except Exception as exc:
            raise ScorerUnavailable(f"could not load local model {cfg.local_lm!r}: {exc}") from exc
        model.eval()
        _state[cfg.local_lm] = {
            "tok": tok,
            "model": model,
            "name": cfg.local_lm,
            "device": str(device),
            "dtype": str(dtype),
            "inference_lock": threading.RLock(),
        }
        return tok, model


def inference_lock(config: Optional[DewatermarkConfig] = None):
    """Return the per-model lock used to bound concurrent accelerator work."""
    cfg = resolve(config)
    load(cfg)
    with _lock:
        return _state[cfg.local_lm]["inference_lock"]


def self_information(text: str, config: Optional[DewatermarkConfig] = None) -> list[dict]:
    """Per-token surprisal under the reference LM.

    Returns a list of dicts (one per scored token, skipping the first which has no
    left context): {token_id, token_str, start, end, surprisal_bits}. `start`/`end`
    are character offsets into `text` (empty when the tokenizer lacks offsets).
    """
    cfg = resolve(config)
    if cfg.scorer_provider:
        from .providers import get_provider

        try:
            return list(get_provider(cfg.scorer_provider)(cfg).self_information(text))
        except Exception as exc:
            raise ScorerUnavailable(
                f"scorer provider {cfg.scorer_provider!r} failed: {exc}"
            ) from exc
    if cfg.resolved_lm_backend == "fireworks":
        from . import fireworks

        try:
            return fireworks.self_information(text, cfg)
        except fireworks.FireworksError as exc:
            raise ScorerUnavailable(str(exc)) from exc

    tok, model = load(cfg)  # raises ScorerUnavailable before torch is needed below
    import torch

    try:
        enc = tok(text, return_tensors="pt", return_offsets_mapping=True, add_special_tokens=False)
        offsets = enc.offset_mapping[0].tolist()
    except (TypeError, ValueError, KeyError):
        enc = tok(text, return_tensors="pt", add_special_tokens=False)
        offsets = None
    device = next(model.parameters()).device
    ids = enc.input_ids[0].to(device)
    if ids.numel() < 2:
        return []

    try:
        with inference_lock(cfg), torch.no_grad():
            logits = model(ids.unsqueeze(0)).logits[0]
    except Exception as exc:
        raise ScorerUnavailable(f"local scoring failed: {exc}") from exc
    logprobs = torch.log_softmax(logits, dim=-1)

    out = []
    cursor = 0
    for i in range(1, ids.numel()):
        tid = int(ids[i])
        lp = logprobs[i - 1, tid].item()
        if offsets is not None:
            start, end = int(offsets[i][0]), int(offsets[i][1])
        else:  # reconstruct spans by decoding incrementally
            piece = tok.decode([tid])
            start = text.find(piece, cursor)
            start = cursor if start < 0 else start
            end = start + len(piece)
            cursor = end
        out.append(
            {
                "token_id": tid,
                "token_str": tok.decode([tid]),
                "start": start,
                "end": end,
                "surprisal_bits": -lp / math.log(2),
            }
        )
    return out


def surrogate_score(text: str, config: Optional[DewatermarkConfig] = None) -> dict:
    """Reference-free proxy for statistical-watermark strength (no key needed).

    Green-list schemes lift mean per-token surprisal, so mean/high-surprisal
    fractions move down as a watermark is scrubbed. This is only a proxy — the
    eval harness computes the true keyed z-score — but it gives a before/after
    signal on arbitrary text.
    """
    try:
        si = self_information(text, config)
    except ScorerUnavailable as exc:
        return {"available": False, "reason": str(exc)}
    if not si:
        return {
            "available": True,
            "scored_tokens": 0,
            "mean_surprisal_bits": 0.0,
            "high_surprisal_fraction": 0.0,
        }
    bits = [t["surprisal_bits"] for t in si]
    mean = sum(bits) / len(bits)
    high = sum(1 for b in bits if b >= 8.0) / len(bits)
    return {
        "available": True,
        "scored_tokens": len(bits),
        "mean_surprisal_bits": round(mean, 3),
        "high_surprisal_fraction": round(high, 3),
    }


def clear_cache() -> None:
    """Release cached tokenizer/model references and accelerator memory."""
    with _lock:
        _state.clear()
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        if getattr(torch, "mps", None) and hasattr(torch.mps, "empty_cache"):
            torch.mps.empty_cache()
    except Exception:
        pass


def cache_info() -> dict:
    """Return non-sensitive model cache state for diagnostics."""
    with _lock:
        return {
            "models": [
                {key: entry[key] for key in ("name", "device", "dtype")}
                for entry in _state.values()
            ]
        }
