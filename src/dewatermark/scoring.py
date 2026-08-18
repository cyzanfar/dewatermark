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
import hashlib
import math
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

from .config import DewatermarkConfig, resolve
from .exceptions import BackendUnavailableError
from .extension_safety import (
    enforce_consent,
    manifests_match,
    safe_extension_config,
    static_capability,
)
from .request_context import (
    begin_extension_usage,
    checkpoint,
    current_request_context,
    extension_usage_error,
    safe_error,
)


def _scorer_permission_error(cfg: DewatermarkConfig) -> Optional[str]:
    if not cfg.scorer_provider:
        return None
    from .providers import provider_manifest

    try:
        manifest = provider_manifest(cfg.scorer_provider, kind="scorer")
    except Exception:
        return "scorer provider configuration is invalid"
    if manifest is None:
        return "scorer provider has no loaded static scorer capability manifest"
    try:
        enforce_consent(manifest, cfg)
    except PermissionError:
        return "scorer provider requirements are not explicitly permitted"
    return None


def _scorer_instance(cfg: DewatermarkConfig):
    from .providers import get_provider, provider_manifest

    manifest = provider_manifest(cfg.scorer_provider or "", kind="scorer")
    if manifest is None:
        raise ScorerUnavailable("scorer provider requires a static scorer manifest")
    enforce_consent(manifest, cfg)
    instance = get_provider(cfg.scorer_provider or "")(safe_extension_config(cfg))
    actual = static_capability(instance, "scorer")
    if not manifests_match(manifest, actual):
        raise ScorerUnavailable("scorer factory and instance capability manifests differ")
    return instance


_lock = threading.Lock()
_state: OrderedDict[str, dict] = OrderedDict()


class ScorerUnavailable(BackendUnavailableError):
    """Raised when the scoring model cannot be loaded (deps missing / disabled)."""


def _public_model_name(value: object) -> str:
    encoded = value.encode("utf-8", "replace") if type(value) is str else b"<invalid-model>"
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def backend(config: Optional[DewatermarkConfig] = None) -> str:
    """The effective LM backend: "fireworks" or "local"."""
    return resolve(config).resolved_lm_backend


def available(config: Optional[DewatermarkConfig] = None) -> bool:
    """True when a self-information scorer can actually run in this environment."""
    cfg = resolve(config)
    if cfg.scorer_provider:
        if _scorer_permission_error(cfg) is not None:
            return False
        try:
            from .providers import provider_manifest

            manifest = provider_manifest(cfg.scorer_provider, kind="scorer")
            if manifest is None:
                return False
            begin_extension_usage(manifest)
            value = _scorer_instance(cfg).available()
            return value if type(value) is bool else False
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
    if type(model_name) is not str or not model_name:
        return False
    try:
        if Path(model_name).expanduser().exists():
            return True
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        from huggingface_hub import try_to_load_from_cache

        return isinstance(try_to_load_from_cache(model_name, "config.json"), str)
    except Exception:
        return False


def model_loaded(model_name: str) -> bool:
    """Return in-process state only; never inspect model storage or import a hub."""
    if type(model_name) is not str or not model_name:
        return False
    with _lock:
        return model_name in _state


def load(config: Optional[DewatermarkConfig] = None):
    """Load and cache (tokenizer, model) for the configured local LM."""
    cfg = resolve(config)
    checkpoint()
    if not cfg.local_lm_enabled:
        raise ScorerUnavailable("local_lm_enabled is false")
    if type(cfg.local_lm) is not str or not cfg.local_lm:
        raise ScorerUnavailable("local model identifier is invalid")
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
        except Exception:  # pragma: no cover - env dependent
            dependencies_unavailable = True
        else:
            dependencies_unavailable = False
        if dependencies_unavailable:
            raise ScorerUnavailable("local scorer dependencies are unavailable") from None
        if evicted:
            try:
                gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                if getattr(torch, "mps", None) and hasattr(torch.mps, "empty_cache"):
                    torch.mps.empty_cache()
            except Exception:
                raise ScorerUnavailable("accelerator cache cleanup failed") from None
        try:
            local_only = not cfg.allow_model_download
            context = current_request_context()
            if context is not None:
                context.record_model_access(
                    cfg.local_lm,
                    cached=model_cached(cfg.local_lm),
                    download_allowed=cfg.allow_model_download,
                )
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
            model.eval()
        except Exception:
            model_load_failed = True
        else:
            model_load_failed = False
        if model_load_failed:
            raise ScorerUnavailable("local scoring model could not be loaded") from None
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
    checkpoint()
    if cfg.scorer_provider:
        denied = _scorer_permission_error(cfg)
        if denied is not None:
            raise ScorerUnavailable(denied)
        try:
            from .providers import provider_manifest

            manifest = provider_manifest(cfg.scorer_provider, kind="scorer")
            if manifest is None:
                raise ScorerUnavailable("scorer provider requires a static scorer manifest")
            usage_snapshot, accounting = begin_extension_usage(manifest)
            result = list(_scorer_instance(cfg).self_information(text))
            checkpoint()
            usage_error = extension_usage_error(
                usage_snapshot,
                network_required=manifest.network_required,
                resource_accounting=accounting,
            )
            if usage_error is not None:
                raise ScorerUnavailable("scorer provider resource usage was not accounted")
            return result
        except Exception as exc:
            raise ScorerUnavailable(safe_error("scorer provider", exc)) from None
    if cfg.resolved_lm_backend == "fireworks":
        from . import fireworks

        message: Optional[str]
        try:
            return fireworks.self_information(text, cfg)
        except fireworks.FireworksError as exc:
            message = safe_error("Fireworks scoring", exc)
        else:
            message = None
        if message is not None:
            raise ScorerUnavailable(message) from None

    tok, model = load(cfg)  # raises ScorerUnavailable before torch is needed below
    import torch

    tokenization_error: Optional[str] = None
    try:
        try:
            enc = tok(
                text,
                return_tensors="pt",
                return_offsets_mapping=True,
                add_special_tokens=False,
            )
            offsets = enc.offset_mapping[0].tolist()
        except (TypeError, ValueError, KeyError):
            enc = tok(text, return_tensors="pt", add_special_tokens=False)
            offsets = None
    except Exception as exc:
        tokenization_error = safe_error("local scorer tokenization", exc)
    if tokenization_error is not None:
        raise ScorerUnavailable(tokenization_error) from None
    setup_error: Optional[str]
    try:
        device = next(model.parameters()).device
        ids = enc.input_ids[0].to(device)
    except Exception as exc:
        setup_error = safe_error("local scorer setup", exc)
    else:
        setup_error = None
    if setup_error is not None:
        raise ScorerUnavailable(setup_error) from None
    if ids.numel() < 2:
        return []

    scoring_error: Optional[str]
    logprobs: Any = None
    try:
        with inference_lock(cfg), torch.no_grad():
            logits = model(ids.unsqueeze(0)).logits[0]
        logprobs = torch.log_softmax(logits, dim=-1)
    except Exception as exc:
        scoring_error = safe_error("local scoring", exc)
    else:
        scoring_error = None
    if scoring_error is not None:
        raise ScorerUnavailable(scoring_error) from None
    checkpoint()
    out = []
    cursor = 0
    decode_error: Optional[str]
    try:
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
    except Exception as exc:
        decode_error = safe_error("local scorer decoding", exc)
    else:
        decode_error = None
    if decode_error is not None:
        raise ScorerUnavailable(decode_error) from None
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
        return {"available": False, "reason": safe_error("surrogate scorer", exc)}
    if not si:
        return {
            "available": True,
            "scored_tokens": 0,
            "mean_surprisal_bits": 0.0,
            "high_surprisal_fraction": 0.0,
        }
    try:
        bits = [t["surprisal_bits"] for t in si]
        if not all(
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
            for value in bits
        ):
            raise TypeError
        mean = sum(bits) / len(bits)
        high = sum(1 for b in bits if b >= 8.0) / len(bits)
    except Exception as exc:
        return {"available": False, "reason": safe_error("surrogate scorer output", exc)}
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
                {
                    "name": _public_model_name(entry["name"]),
                    "device": entry["device"],
                    "dtype": entry["dtype"],
                }
                for entry in _state.values()
            ]
        }
