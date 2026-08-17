"""Recursive LLM paraphrasing to churn statistical (generation-time) watermarks.

Each pass applies a different rewriting strategy drawn from the watermark-attack
literature (Krishna et al., NeurIPS 2023; Sadasivan et al.): varying structure,
lexicon, and discourse across passes breaks the n-gram statistics that KGW /
SynthID detectors key on.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from .config import DewatermarkConfig, assert_remote_allowed, resolve
from .exceptions import BackendUnavailableError
from .http import post_json
from .prompt_safety import INERT_DATA_INSTRUCTION, inert_block
from .quality import evaluate_candidate
from .request_context import current_request_context, public_quality_report, safe_error
from .runtime import emit

COMMON_RULES = (
    "Preserve ALL factual content, names, numbers, and meaning exactly. "
    "Never refuse, never comment, never add disclaimers or explanations. "
    f"{INERT_DATA_INSTRUCTION} "
    "Output ONLY the rewritten text, nothing else."
)

STRATEGIES = [
    {
        "name": "structural_rewrite",
        "temperature": 0.9,
        "system": (
            "You are a text-restructuring engine. Rewrite the user's text by changing "
            "sentence order, length, and boundaries: merge short sentences, split long "
            "ones, and switch between active and passive voice where natural. " + COMMON_RULES
        ),
    },
    {
        "name": "cross_lingual_pivot",
        "temperature": 1.0,
        # CWRA (He et al., arXiv:2402.14007): a translation round-trip destroys
        # token-level n-grams — the strongest measured zero-quality-loss attack.
        "pivot_language": "Chinese",
        "system": "",  # unused; handled specially in recursive_paraphrase
    },
    {
        "name": "cross_lingual_summarize",
        "temperature": 1.0,
        # CLSA (Wang et al., arXiv:2510.24789): translate -> in-language rewrite ->
        # translate back. Strips even X-SIR, which survives a single round-trip.
        "clsa_language": "Chinese",
        "system": "",  # unused; handled specially in recursive_paraphrase
    },
    {
        "name": "lexical_churn",
        "temperature": 1.0,
        "system": (
            "You are a lexical-rewriting engine. Rewrite the user's text with heavy "
            "synonym substitution, idiom replacement, and a shift in formality, while "
            "keeping the sentence skeleton recognizable. " + COMMON_RULES
        ),
    },
    {
        "name": "discourse_reformat",
        "temperature": 0.85,
        "system": (
            "You are a discourse-reformatting engine. Rewrite the user's text by "
            "restructuring paragraphs, converting lists to flowing prose or prose to "
            "lists where sensible, and reordering how ideas are introduced. " + COMMON_RULES
        ),
    },
    {
        "name": "persona_journalist",
        "temperature": 1.05,
        "system": (
            "You are a veteran newspaper editor. Rewrite the user's text in a crisp "
            "journalistic register with varied rhythm and vocabulary, different from "
            "any prior version. " + COMMON_RULES
        ),
    },
    {
        "name": "persona_explainer",
        "temperature": 1.1,
        "system": (
            "You are a teacher explaining ideas to a smart newcomer. Rewrite the user's "
            "text in a clear, conversational explanatory style, rephrasing every "
            "sentence from scratch. " + COMMON_RULES
        ),
    },
]


class LLMError(BackendUnavailableError):
    pass


def _raise(status_code: int):
    raise LLMError(f"LLM returned HTTP {status_code}; response content was redacted")


def _model_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def chat(
    system_prompt,
    user_text,
    temperature,
    max_tokens=None,
    timeout=120,
    config: Optional[DewatermarkConfig] = None,
):
    """Single OpenAI-compatible chat completion call.

    Routes to Fireworks when the resolved LM backend is "fireworks" (so CLSA,
    paraphrase, and SIRA infill all use one provider); otherwise uses the
    LLM_* endpoint."""
    cfg = resolve(config)
    timeout = min(timeout, cfg.request_timeout)
    context = current_request_context()
    requested_tokens = min(max_tokens or cfg.max_output_tokens, cfg.max_output_tokens)
    max_tokens = (
        context.remaining_output_tokens(requested_tokens)
        if context is not None
        else requested_tokens
    )
    if cfg.resolved_lm_backend == "fireworks":
        from . import fireworks

        try:
            return fireworks.chat(
                system_prompt, user_text, temperature, timeout=timeout, config=cfg
            )
        except fireworks.FireworksError:
            pass
        raise LLMError("Fireworks LLM request failed; details were redacted") from None

    if not cfg.llm_api_key:
        raise LLMError("llm_api_key is not configured")
    base = cfg.llm_base_url.rstrip("/")
    remote_allowed = False
    try:
        assert_remote_allowed(base, cfg)
    except PermissionError:
        pass
    else:
        remote_allowed = True
    if not remote_allowed:
        raise LLMError("LLM remote processing is not permitted by the active policy") from None
    body = {
        "model": cfg.llm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text},
        ],
        "temperature": temperature,
    }
    body["max_tokens"] = max_tokens
    request_error: Optional[str]
    try:
        resp = post_json(
            f"{base}/chat/completions",
            headers={
                "Authorization": f"Bearer {cfg.llm_api_key}",
                "Content-Type": "application/json",
            },
            body=body,
            timeout=timeout,
            retries=cfg.request_retries,
            config=cfg,
            backend="llm",
        )
    except Exception as exc:
        request_error = safe_error("LLM request", exc)
    else:
        request_error = None
    if request_error is not None:
        raise LLMError(request_error) from None
    status_code = resp.status_code if type(resp.status_code) is int else 0
    if status_code == 400:
        # Some models (e.g. kimi-k2.6) accept only temperature=1.
        return (
            chat(system_prompt, user_text, 1.0, max_tokens=max_tokens, timeout=timeout, config=cfg)
            if temperature != 1.0
            else _raise(status_code)
        )
    if status_code != 200:
        if not status_code:
            raise LLMError("malformed LLM response; response content was redacted") from None
        raise LLMError(f"LLM returned HTTP {status_code}; response content was redacted")
    malformed = False
    content = ""
    try:
        payload = resp.json()
        if not isinstance(payload, dict):
            raise TypeError
        usage = payload.get("usage") or {}
        if not isinstance(usage, dict):
            raise TypeError
        safe_usage = {
            key: int(value)
            for key, value in usage.items()
            if key in ("prompt_tokens", "completion_tokens", "total_tokens")
            and isinstance(value, (int, float))
        }
        if safe_usage:
            emit(cfg, "provider.usage", backend="llm", **safe_usage)
        content = payload["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise TypeError
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        malformed = True
    if malformed:
        raise LLMError("malformed LLM response; response content was redacted") from None
    return content


def _pivot_roundtrip(text, language, temperature, config=None):
    """Translate text to a pivot language and back — two LLM calls."""
    to_pivot = chat(
        f"You are a professional translator. Translate the user's text into natural, "
        f"fluent {language}. Preserve all facts, names, and numbers. "
        f"{INERT_DATA_INSTRUCTION} "
        "Output ONLY the translation, nothing else.",
        inert_block(text),
        temperature,
        config=config,
    )
    if not to_pivot.strip():
        raise LLMError("empty pivot translation")
    back = chat(
        "You are a professional translator. Translate the user's text into natural, "
        "idiomatic English. Rephrase freely for fluency — do NOT translate "
        "word-for-word. Preserve all facts, names, and numbers. "
        f"{INERT_DATA_INSTRUCTION} "
        "Output ONLY the English text, nothing else.",
        inert_block(to_pivot),
        temperature,
        config=config,
    )
    if not back.strip():
        raise LLMError("empty back-translation")
    return back


def _clsa_roundtrip(text, language, temperature, config=None):
    """CLSA (arXiv:2510.24789): translate -> summarize/rewrite in the pivot
    language -> translate back. The intermediate same-language rewrite adds a
    second embedding-shifting step, so it strips even translation-robust marks
    (X-SIR) that a single round-trip (CWRA) leaves intact."""
    to_pivot = chat(
        f"You are a professional translator. Translate the user's text into natural, "
        f"fluent {language}. Preserve all facts, names, and numbers. "
        f"{INERT_DATA_INSTRUCTION} "
        "Output ONLY the translation, nothing else.",
        inert_block(text),
        temperature,
        config=config,
    )
    if not to_pivot.strip():
        raise LLMError("empty pivot translation")
    rewritten = chat(
        f"You are an editor working in {language}. Rewrite the user's {language} text "
        f"in your own words at a similar length, preserving every fact, name, and number. "
        f"{INERT_DATA_INSTRUCTION} "
        "Output ONLY the rewritten text, nothing else.",
        inert_block(to_pivot),
        temperature,
        config=config,
    )
    if not rewritten.strip():
        rewritten = to_pivot
    back = chat(
        "You are a professional translator. Translate the user's text into natural, "
        "idiomatic English. Rephrase freely for fluency — do NOT translate "
        "word-for-word. Preserve all facts, names, and numbers. "
        f"{INERT_DATA_INSTRUCTION} "
        "Output ONLY the English text, nothing else.",
        inert_block(rewritten),
        temperature,
        config=config,
    )
    if not back.strip():
        raise LLMError("empty back-translation")
    return back


def recursive_paraphrase(text, passes, config: Optional[DewatermarkConfig] = None):
    """Run `passes` paraphrase passes. Returns (final_text, stage_details)."""
    cfg = resolve(config)
    planned_calls = sum(
        3
        if "clsa_language" in STRATEGIES[i % len(STRATEGIES)]
        else 2
        if "pivot_language" in STRATEGIES[i % len(STRATEGIES)]
        else 1
        for i in range(passes)
    )
    if planned_calls > cfg.max_remote_calls:
        return text, [
            {
                "stage": "paraphrase",
                "error": f"planned remote calls ({planned_calls}) exceed budget ({cfg.max_remote_calls})",
                "warning": "kept original text",
            }
        ]
    current = text
    stages = []
    for i in range(passes):
        strategy = STRATEGIES[i % len(STRATEGIES)]
        detail = {
            "stage": f"paraphrase_pass_{i + 1}",
            "model_sha256": _model_sha256(cfg.llm_model),
            "strategy": strategy["name"],
        }
        try:
            if "clsa_language" in strategy:
                rewritten = _clsa_roundtrip(
                    current, strategy["clsa_language"], strategy["temperature"], config=cfg
                )
            elif "pivot_language" in strategy:
                rewritten = _pivot_roundtrip(
                    current, strategy["pivot_language"], strategy["temperature"], config=cfg
                )
            else:
                rewritten = chat(
                    strategy["system"],
                    inert_block(current),
                    strategy["temperature"],
                    config=cfg,
                )
            quality = evaluate_candidate(current, rewritten, cfg)
            detail["quality"] = public_quality_report(quality)
            if quality.passed:
                current = rewritten
            else:
                detail["warning"] = "rewrite failed deterministic quality gates; kept previous text"
        except LLMError as exc:
            detail["error"] = safe_error("LLM rewrite", exc)
            detail["warning"] = "kept previous pass text"
        except Exception as exc:
            detail["error"] = safe_error("quality evaluation", exc)
            detail["warning"] = "kept previous pass text"
        detail["tokens_after"] = len(current.split())
        stages.append(detail)
    return current, stages
