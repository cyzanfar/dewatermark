"""Fireworks AI backend — run the self-information scorer and BIRA over the
Fireworks completions API instead of a local model. No GPU, no model hosting.

Scoring: POST /v1/completions with echo=true + logprobs. Fireworks echoes the
prompt tokens with their log-probabilities AND integer token_ids, so we get both
the surprisal (for the proxy green-list) and the exact token IDs needed for
logit_bias — no local tokenizer required.

BIRA: reuse those high-surprisal token_ids as the proxy green-list and apply a
negative logit_bias on a /v1/chat/completions rewrite call.
"""

from __future__ import annotations

import math
from typing import Optional

from .config import DewatermarkConfig, assert_remote_allowed, resolve
from .exceptions import BackendUnavailableError
from .http import post_json
from .prompt_safety import INERT_DATA_INSTRUCTION, inert_block
from .quality import evaluate_candidate
from .request_context import public_quality_report, safe_error
from .runtime import emit

_LN2 = math.log(2)


def _emit_usage(cfg: DewatermarkConfig, payload: dict) -> None:
    usage = payload.get("usage") or {}
    safe_usage = {
        key: int(value)
        for key, value in usage.items()
        if key in ("prompt_tokens", "completion_tokens", "total_tokens")
        and isinstance(value, (int, float))
    }
    if safe_usage:
        emit(cfg, "provider.usage", backend="fireworks", **safe_usage)


class FireworksError(BackendUnavailableError):
    pass


def available(config: Optional[DewatermarkConfig] = None) -> bool:
    cfg = resolve(config)
    if not cfg.fireworks_api_key:
        return False
    try:
        assert_remote_allowed(cfg.fireworks_base_url, cfg)
    except PermissionError:
        return False
    return True


def _headers(cfg: DewatermarkConfig) -> dict:
    if not cfg.fireworks_api_key:
        raise FireworksError("fireworks_api_key is not configured")
    return {"Authorization": f"Bearer {cfg.fireworks_api_key}", "Content-Type": "application/json"}


def _allow(cfg: DewatermarkConfig) -> None:
    try:
        assert_remote_allowed(cfg.fireworks_base_url, cfg)
    except PermissionError:
        denied = True
    else:
        denied = False
    if denied:
        raise FireworksError(
            "Fireworks remote processing is not permitted by the active policy"
        ) from None


def self_information(text: str, config: Optional[DewatermarkConfig] = None) -> list[dict]:
    """Per-token surprisal of `text` via echo-logprobs. Same shape as
    scoring.self_information: [{token_id, token_str, start, end, surprisal_bits}]."""
    cfg = resolve(config)
    _allow(cfg)
    base = cfg.fireworks_base_url.rstrip("/")
    body = {
        "model": cfg.fireworks_model,
        "prompt": text,
        "echo": True,
        "logprobs": 1,
        "max_tokens": 1,
        "temperature": 0,
    }
    request_error: Optional[str]
    try:
        resp = post_json(
            f"{base}/completions",
            headers=_headers(cfg),
            body=body,
            timeout=min(60, cfg.request_timeout),
            retries=cfg.request_retries,
            config=cfg,
            backend="fireworks",
        )
    except Exception as exc:
        request_error = safe_error("Fireworks scoring request", exc)
    else:
        request_error = None
    if request_error is not None:
        raise FireworksError(request_error) from None
    status_code = resp.status_code if type(resp.status_code) is int else 0
    if status_code != 200:
        if not status_code:
            raise FireworksError(
                "malformed Fireworks scoring response; response content was redacted"
            ) from None
        raise FireworksError(
            f"Fireworks scoring returned HTTP {status_code}; response content was redacted"
        )

    malformed = False
    lp: dict = {}
    try:
        payload = resp.json()
        if not isinstance(payload, dict):
            raise TypeError
        _emit_usage(cfg, payload)
        lp = payload["choices"][0].get("logprobs") or {}
        if not isinstance(lp, dict):
            raise TypeError
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        malformed = True
    if malformed:
        raise FireworksError(
            "malformed Fireworks scoring response; response content was redacted"
        ) from None

    tokens = lp.get("tokens") or []
    token_logprobs = lp.get("token_logprobs") or []
    token_ids = lp.get("token_ids") or []
    offsets = lp.get("text_offset") or []

    out = []
    try:
        if not all(
            isinstance(value, list) for value in (tokens, token_logprobs, token_ids, offsets)
        ):
            raise TypeError
        for i, logprob in enumerate(token_logprobs):
            if logprob is None:  # first prompt token has no left context
                continue
            if isinstance(logprob, bool) or not isinstance(logprob, (int, float)):
                raise TypeError
            start = offsets[i] if i < len(offsets) else 0
            if isinstance(start, bool) or not isinstance(start, int):
                raise TypeError
            if start >= len(text):  # the appended generated token (max_tokens=1)
                continue
            end = offsets[i + 1] if i + 1 < len(offsets) else len(text)
            if isinstance(end, bool) or not isinstance(end, int):
                raise TypeError
            token_id = token_ids[i] if i < len(token_ids) else -1
            token_str = tokens[i] if i < len(tokens) else ""
            if isinstance(token_id, bool) or not isinstance(token_id, int):
                raise TypeError
            if not isinstance(token_str, str):
                raise TypeError
            out.append(
                {
                    "token_id": token_id,
                    "token_str": token_str,
                    "start": start,
                    "end": min(end, len(text)),
                    "surprisal_bits": -float(logprob) / _LN2,
                }
            )
    except (IndexError, TypeError, ValueError):
        malformed_tokens = True
    else:
        malformed_tokens = False
    if malformed_tokens:
        raise FireworksError(
            "malformed Fireworks scoring response; response content was redacted"
        ) from None
    return out


def surrogate_score(text: str, config: Optional[DewatermarkConfig] = None) -> dict:
    try:
        si = self_information(text, config)
    except FireworksError as exc:
        return {"available": False, "reason": safe_error("Fireworks scoring", exc)}
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


def chat(
    system_prompt: str,
    user_text: str,
    temperature: float = 1.0,
    timeout: int = 90,
    config: Optional[DewatermarkConfig] = None,
) -> str:
    """OpenAI-compatible chat completion via Fireworks. Used by the paraphraser
    (CLSA translation round-trip, paraphrase strategies, SIRA infill) so a
    Fireworks deployment needs no second LLM provider. `reasoning_effort: low`
    keeps gpt-oss-class models from spending the budget on chain-of-thought."""
    cfg = resolve(config)
    _allow(cfg)
    base = cfg.fireworks_base_url.rstrip("/")
    body = {
        "model": cfg.fireworks_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text},
        ],
        "temperature": temperature,
        "reasoning_effort": "low",
        "max_tokens": min(cfg.max_output_tokens, max(256, len(user_text.split()) * 3 + 128)),
    }
    request_error: Optional[str]
    try:
        resp = post_json(
            f"{base}/chat/completions",
            headers=_headers(cfg),
            body=body,
            timeout=min(timeout, cfg.request_timeout),
            retries=cfg.request_retries,
            config=cfg,
            backend="fireworks",
        )
    except Exception as exc:
        request_error = safe_error("Fireworks chat request", exc)
    else:
        request_error = None
    if request_error is not None:
        raise FireworksError(request_error) from None
    status_code = resp.status_code if type(resp.status_code) is int else 0
    if status_code != 200:
        if not status_code:
            raise FireworksError(
                "malformed Fireworks chat response; response content was redacted"
            ) from None
        raise FireworksError(
            f"Fireworks chat returned HTTP {status_code}; response content was redacted"
        )
    malformed = False
    content = ""
    try:
        payload = resp.json()
        if not isinstance(payload, dict):
            raise TypeError
        _emit_usage(cfg, payload)
        raw_content = payload["choices"][0]["message"].get("content")
        if not isinstance(raw_content, str):
            raise TypeError
        content = raw_content.strip()
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        malformed = True
    if malformed:
        raise FireworksError(
            "malformed Fireworks chat response; response content was redacted"
        ) from None
    if not content:
        raise FireworksError("empty chat content")
    return content


def _estimate_green(si: list[dict], quantile: float, cap: int = 250) -> list[int]:
    """Proxy green-list: token IDs whose surprisal is at/above `quantile` here.
    Capped because logit_bias payloads should stay bounded."""
    if not si:
        return []
    bits = sorted(t["surprisal_bits"] for t in si)
    thresh = bits[min(int(len(bits) * quantile), len(bits) - 1)]
    ranked = sorted(
        (t for t in si if t["surprisal_bits"] >= thresh and t["token_id"] >= 0),
        key=lambda t: t["surprisal_bits"],
        reverse=True,
    )
    ids, seen = [], set()
    for t in ranked:
        if t["token_id"] not in seen:
            seen.add(t["token_id"])
            ids.append(t["token_id"])
        if len(ids) >= cap:
            break
    return ids


_REWRITE_SYSTEM = (
    "Rewrite the user's text in your own words. Preserve every fact, name, number, "
    "and the overall meaning exactly. Do not add commentary or disclaimers. Output "
    f"only the rewritten text. {INERT_DATA_INSTRUCTION}"
)


def bira_rewrite(
    text: str,
    beta: float = 8.0,
    quantile: float = 0.7,
    config: Optional[DewatermarkConfig] = None,
    *,
    max_restarts: int = 3,
    bias_backoff: float = 0.65,
) -> tuple[str, dict]:
    """Negative-bias rewrite over Fireworks: estimate the proxy green-list from
    echo-logprobs, then rewrite with a negative logit_bias on those token IDs."""
    cfg = resolve(config)
    detail = {"stage": "bias_inversion", "backend": "fireworks", "beta": beta, "quantile": quantile}
    if cfg.max_remote_calls < 2:
        detail["error"] = "Fireworks BIRA requires a remote-call budget of at least 2"
        detail["warning"] = "kept original"
        return text, detail
    try:
        _allow(cfg)
    except FireworksError as exc:
        detail["error"] = safe_error("Fireworks policy check", exc)
        detail["warning"] = "kept original"
        return text, detail
    base = cfg.fireworks_base_url.rstrip("/")
    try:
        si = self_information(text, cfg)
    except FireworksError as exc:
        detail["error"] = safe_error("Fireworks scoring", exc)
        detail["warning"] = "kept original"
        return text, detail

    green = _estimate_green(si, quantile)
    detail["green_size"] = len(green)
    attempts = []
    current_beta = beta
    allowed_restarts = max(1, min(max_restarts, cfg.max_remote_calls - 1))
    for restart in range(allowed_restarts):
        bias_val = max(-100, min(-1, int(round(-abs(current_beta)))))
        body = {
            "model": cfg.fireworks_model,
            "messages": [
                {"role": "system", "content": _REWRITE_SYSTEM},
                {"role": "user", "content": inert_block(text)},
            ],
            "temperature": 1.0,
            "top_p": 0.95,
            "max_tokens": min(cfg.max_output_tokens, 1200, len(text.split()) * 2 + 160),
            "reasoning_effort": "low",
        }
        if green:
            body["logit_bias"] = {str(tid): bias_val for tid in green}
        try:
            resp = post_json(
                f"{base}/chat/completions",
                headers=_headers(cfg),
                body=body,
                timeout=min(90, cfg.request_timeout),
                retries=cfg.request_retries,
                config=cfg,
                backend="fireworks",
            )
        except Exception as exc:
            attempts.append(
                {"restart": restart, "beta": current_beta, "error": safe_error("rewrite", exc)}
            )
            current_beta *= bias_backoff
            continue
        status_code = resp.status_code if type(resp.status_code) is int else 0
        if status_code != 200:
            attempts.append(
                {
                    "restart": restart,
                    "beta": current_beta,
                    "error": (
                        f"HTTP {status_code}; response content was redacted"
                        if status_code
                        else "malformed rewrite response; response content was redacted"
                    ),
                }
            )
            current_beta *= bias_backoff
            continue
        try:
            payload = resp.json()
            if not isinstance(payload, dict):
                raise TypeError
            _emit_usage(cfg, payload)
            msg = payload["choices"][0]["message"]
            if not isinstance(msg, dict):
                raise TypeError
            raw_output = msg.get("content")
            if not isinstance(raw_output, str):
                raise TypeError
            out = raw_output.strip()
        except (AttributeError, KeyError, IndexError, TypeError, ValueError):
            attempts.append(
                {
                    "restart": restart,
                    "beta": current_beta,
                    "error": "malformed Fireworks rewrite response; response content was redacted",
                }
            )
            current_beta *= bias_backoff
            continue
        try:
            quality = evaluate_candidate(text, out, cfg)
        except Exception as exc:
            attempts.append(
                {
                    "restart": restart,
                    "beta": current_beta,
                    "error": safe_error("quality evaluation", exc),
                }
            )
            current_beta *= bias_backoff
            continue
        public_quality = public_quality_report(quality)
        attempts.append(
            {"restart": restart, "beta": round(current_beta, 3), "quality": public_quality}
        )
        if quality.passed:
            detail.update(
                attempts=attempts,
                effective_beta=current_beta,
                quality=public_quality,
                tokens_after=len(out.split()),
            )
            return out, detail
        current_beta *= bias_backoff

    detail["attempts"] = attempts
    detail["warning"] = "all rewrites failed or failed deterministic quality gates; kept original"
    return text, detail
