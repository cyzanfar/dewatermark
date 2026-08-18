"""Configuration for dewatermark.

A single frozen dataclass carries every knob the library needs. Each field falls
back to an environment variable via :meth:`DewatermarkConfig.from_env`, and a
module-level default (built lazily from the environment) backs every public
function that does not receive an explicit ``config=`` argument.

New integrations should use these namespaced environment variables. Unprefixed
v0.2 names remain temporary compatibility aliases:

  DEWATERMARK_LM_BACKEND            "auto" (default) | "fireworks" | "local"
  DEWATERMARK_FIREWORKS_AI_API_KEY  Fireworks API key
  DEWATERMARK_FIREWORKS_BASE_URL    default https://api.fireworks.ai/inference/v1
  DEWATERMARK_FIREWORKS_MODEL       default accounts/fireworks/models/gpt-oss-20b
  DEWATERMARK_LOCAL_LM              default Qwen/Qwen2.5-0.5B-Instruct
  DEWATERMARK_LOCAL_LM_ENABLED      "true"/"false" (default true)
  DEWATERMARK_DETECTOR_PROVIDER     Optional named detector provider
  DEWATERMARK_LLM_API_KEY           OpenAI-compatible chat endpoint key
  DEWATERMARK_LLM_BASE_URL          default https://api.moonshot.ai/v1
  DEWATERMARK_LLM_MODEL             default kimi-k2.6
"""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass, field, fields, replace
from typing import Any, Callable, Mapping, Optional, cast
from urllib.parse import urlparse

from .exceptions import ConfigurationError, RemoteProcessingDeniedError
from .models import SanitizeProfile


def _env(name: str, default: Optional[str] = None, legacy: Optional[str] = None) -> Optional[str]:
    """Read a namespaced variable, falling back to its v0.2 legacy alias."""
    return os.environ.get(f"DEWATERMARK_{name}", os.environ.get(legacy or name, default))


def _env_bool(name: str, default: bool, legacy: Optional[str] = None) -> bool:
    raw = _env(name, legacy=legacy)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ConfigurationError(f"DEWATERMARK_{name} must be true or false")


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)) or str(default))
    except ValueError:
        raise ConfigurationError(f"DEWATERMARK_{name} must be an integer") from None


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)) or str(default))
    except ValueError:
        raise ConfigurationError(f"DEWATERMARK_{name} must be numeric") from None


def _validate_base_url(value: str, name: str) -> None:
    if type(value) is not str:
        raise ConfigurationError(f"{name} must be an absolute http or https URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError(f"{name} must be an absolute http or https URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError(
            f"{name} cannot contain credentials, a query string, or a fragment"
        )


@dataclass(frozen=True)
class DewatermarkConfig:
    """Immutable configuration for all dewatermark backends."""

    lm_backend: str = "auto"  # "auto" | "fireworks" | "local"
    fireworks_api_key: Optional[str] = field(default=None, repr=False)
    fireworks_base_url: str = field(default="https://api.fireworks.ai/inference/v1", repr=False)
    fireworks_model: str = field(default="accounts/fireworks/models/gpt-oss-20b", repr=False)
    local_lm: str = field(default="Qwen/Qwen2.5-0.5B-Instruct", repr=False)
    local_lm_enabled: bool = True
    allow_model_download: bool = False
    scorer_provider: Optional[str] = field(default=None, repr=False)
    detector_provider: Optional[str] = field(default=None, repr=False)
    rewriter_provider: Optional[str] = field(default=None, repr=False)
    llm_api_key: Optional[str] = field(default=None, repr=False)
    llm_base_url: str = field(default="https://api.moonshot.ai/v1", repr=False)
    llm_model: str = field(default="kimi-k2.6", repr=False)
    sanitize_profile: SanitizeProfile = "safe"
    allow_remote_processing: bool = False
    request_retries: int = 2
    request_timeout: int = 120
    max_concurrency: int = 4
    max_input_chars: int = 1_000_000
    max_remote_calls: int = 16
    max_output_tokens: int = 2048
    max_batch_items: int = 1000
    model_cache_size: int = 2
    random_seed: int = 13
    require_verified: bool = False
    quality_min_length_ratio: float = 0.70
    quality_max_length_ratio: float = 1.35
    max_chunk_chars: int = 12000
    semantic_scorer: Optional[Callable[[str, str], float]] = field(
        default=None, repr=False, compare=False
    )
    quality_min_semantic_score: Optional[float] = None
    quality_gate: Optional[Any] = field(default=None, repr=False, compare=False)
    quality_gates: tuple[Any, ...] = field(default=(), repr=False, compare=False)
    chunker: Optional[Any] = field(default=None, repr=False, compare=False)
    event_handler: Optional[Callable[[Mapping[str, Any]], None]] = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if type(self.lm_backend) is not str or self.lm_backend not in (
            "auto",
            "fireworks",
            "local",
        ):
            raise ConfigurationError("lm_backend must be 'auto', 'fireworks', or 'local'")
        if self.sanitize_profile not in ("safe", "aggressive"):
            raise ConfigurationError("sanitize_profile must be 'safe' or 'aggressive'")
        for name in (
            "local_lm_enabled",
            "allow_model_download",
            "allow_remote_processing",
            "require_verified",
        ):
            if type(getattr(self, name)) is not bool:
                raise ConfigurationError(f"{name} must be boolean")
        _validate_base_url(self.fireworks_base_url, "fireworks_base_url")
        _validate_base_url(self.llm_base_url, "llm_base_url")
        for name in ("fireworks_model", "local_lm", "llm_model"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise ConfigurationError(f"{name} must be a non-empty string")
        for name in ("scorer_provider", "detector_provider", "rewriter_provider"):
            value = getattr(self, name)
            if value is not None and (type(value) is not str or not value.strip()):
                raise ConfigurationError(f"{name} must be a non-empty string when configured")
        if type(self.request_retries) is not int or not 0 <= self.request_retries <= 5:
            raise ConfigurationError("request_retries must be between 0 and 5")
        if type(self.request_timeout) is not int or not 1 <= self.request_timeout <= 3600:
            raise ConfigurationError("request_timeout must be between 1 and 3600 seconds")
        if type(self.max_concurrency) is not int or not 1 <= self.max_concurrency <= 64:
            raise ConfigurationError("max_concurrency must be between 1 and 64")
        if type(self.max_input_chars) is not int or self.max_input_chars < 1:
            raise ConfigurationError("max_input_chars must be positive")
        if type(self.max_remote_calls) is not int or not 0 <= self.max_remote_calls <= 100:
            raise ConfigurationError("max_remote_calls must be between 0 and 100")
        if type(self.max_output_tokens) is not int or not 32 <= self.max_output_tokens <= 32768:
            raise ConfigurationError("max_output_tokens must be between 32 and 32768")
        if type(self.max_batch_items) is not int or not 1 <= self.max_batch_items <= 100_000:
            raise ConfigurationError("max_batch_items must be between 1 and 100000")
        if type(self.model_cache_size) is not int or not 1 <= self.model_cache_size <= 8:
            raise ConfigurationError("model_cache_size must be between 1 and 8")
        if type(self.random_seed) is not int or self.random_seed < 0:
            raise ConfigurationError("random_seed must be a non-negative integer")
        if (
            type(self.quality_min_length_ratio) not in (int, float)
            or type(self.quality_max_length_ratio) not in (int, float)
            or not math.isfinite(float(self.quality_min_length_ratio))
            or not math.isfinite(float(self.quality_max_length_ratio))
            or not 0 < self.quality_min_length_ratio <= self.quality_max_length_ratio
        ):
            raise ConfigurationError("invalid quality length-ratio bounds")
        if type(self.max_chunk_chars) is not int or self.max_chunk_chars < 256:
            raise ConfigurationError("max_chunk_chars must be at least 256")
        if self.quality_min_semantic_score is not None and (
            type(self.quality_min_semantic_score) not in (int, float)
            or not math.isfinite(float(self.quality_min_semantic_score))
            or not 0 <= self.quality_min_semantic_score <= 1
        ):
            raise ConfigurationError("quality_min_semantic_score must be between 0 and 1")
        if type(self.quality_gates) is not tuple:
            raise ConfigurationError("quality_gates must be an immutable tuple")

    @property
    def resolved_lm_backend(self) -> str:
        """ "auto" resolves to "fireworks" when a Fireworks key is set, else "local"."""
        if self.lm_backend != "auto":
            return self.lm_backend
        return "fireworks" if self.fireworks_api_key else "local"

    @classmethod
    def from_env(cls) -> "DewatermarkConfig":
        """Build a config from the process environment."""
        return cls(
            lm_backend=_env("LM_BACKEND", "auto") or "auto",
            fireworks_api_key=_env("FIREWORKS_AI_API_KEY") or None,
            fireworks_base_url=_env("FIREWORKS_BASE_URL", "https://api.fireworks.ai/inference/v1")
            or "",
            fireworks_model=_env("FIREWORKS_MODEL", "accounts/fireworks/models/gpt-oss-20b") or "",
            local_lm=_env("LOCAL_LM", "Qwen/Qwen2.5-0.5B-Instruct") or "",
            local_lm_enabled=_env_bool("LOCAL_LM_ENABLED", True),
            allow_model_download=_env_bool("ALLOW_MODEL_DOWNLOAD", False),
            scorer_provider=_env("SCORER_PROVIDER") or None,
            detector_provider=_env("DETECTOR_PROVIDER") or None,
            rewriter_provider=_env("REWRITER_PROVIDER") or None,
            llm_api_key=_env("LLM_API_KEY") or None,
            llm_base_url=_env("LLM_BASE_URL", "https://api.moonshot.ai/v1") or "",
            llm_model=_env("LLM_MODEL", "kimi-k2.6") or "",
            sanitize_profile=cast(SanitizeProfile, _env("SANITIZE_PROFILE", "safe") or "safe"),
            allow_remote_processing=_env_bool("ALLOW_REMOTE_PROCESSING", False),
            request_retries=_env_int("REQUEST_RETRIES", 2),
            request_timeout=_env_int("REQUEST_TIMEOUT", 120),
            max_concurrency=_env_int("MAX_CONCURRENCY", 4),
            max_input_chars=_env_int("MAX_INPUT_CHARS", 1_000_000),
            max_remote_calls=_env_int("MAX_REMOTE_CALLS", 16),
            max_output_tokens=_env_int("MAX_OUTPUT_TOKENS", 2048),
            max_batch_items=_env_int("MAX_BATCH_ITEMS", 1000),
            model_cache_size=_env_int("MODEL_CACHE_SIZE", 2),
            random_seed=_env_int("RANDOM_SEED", 13),
            require_verified=_env_bool("REQUIRE_VERIFIED", False),
            quality_min_length_ratio=_env_float("QUALITY_MIN_LENGTH_RATIO", 0.70),
            quality_max_length_ratio=_env_float("QUALITY_MAX_LENGTH_RATIO", 1.35),
            max_chunk_chars=_env_int("MAX_CHUNK_CHARS", 12000),
        )

    def to_dict(self, *, redact_secrets: bool = True) -> dict[str, Any]:
        """Serialize configuration without credentials.

        ``redact_secrets`` remains for call compatibility, but credentials are
        never emitted even when an older caller passes ``False``.
        """
        value = {item.name: getattr(self, item.name) for item in fields(self)}
        value["semantic_scorer"] = bool(self.semantic_scorer)
        value["event_handler"] = bool(self.event_handler)
        # Extension class names are user-controlled metadata and have appeared
        # in real applications with embedded tenant or credential material.
        # Configuration serialization needs only presence, never Python names
        # or representations.
        value["quality_gate"] = "configured" if self.quality_gate is not None else None
        value["quality_gates"] = ["configured"] * len(self.quality_gates)
        value["chunker"] = "configured" if self.chunker is not None else None
        for key in (
            "fireworks_base_url",
            "fireworks_model",
            "local_lm",
            "llm_base_url",
            "llm_model",
            "scorer_provider",
            "detector_provider",
            "rewriter_provider",
        ):
            raw = value[key]
            value[key] = (
                "sha256:" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
                if raw is not None
                else None
            )
        for key in ("fireworks_api_key", "llm_api_key"):
            value[key] = "***" if value[key] else None
        return value


_default_config: Optional[DewatermarkConfig] = None


def get_config() -> DewatermarkConfig:
    """The module-level default config (from env, unless ``configure`` was called)."""
    global _default_config
    if _default_config is None:
        _default_config = DewatermarkConfig.from_env()
    return _default_config


def configure(**overrides) -> DewatermarkConfig:
    """Override fields of the module-level default config; returns the new config."""
    global _default_config
    _default_config = replace(get_config(), **overrides)
    return _default_config


def reset_config() -> None:
    """Drop the module-level default; the next ``get_config()`` re-reads the env.

    Intended for tests.
    """
    global _default_config
    _default_config = None


def resolve(config: Optional[DewatermarkConfig]) -> DewatermarkConfig:
    """Per-call override hook: explicit config wins, else the module default."""
    return config if config is not None else get_config()


def assert_remote_allowed(url: str, config: DewatermarkConfig) -> None:
    """Require explicit consent before transmitting text to any HTTP endpoint."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RemoteProcessingDeniedError("text-processing endpoint must use http or https")
    if not parsed.hostname:
        raise RemoteProcessingDeniedError("text-processing endpoint must include a hostname")
    if parsed.username or parsed.password:
        raise RemoteProcessingDeniedError("endpoint credentials must not be embedded in URLs")
    if not config.allow_remote_processing:
        raise RemoteProcessingDeniedError(
            "HTTP text processing is disabled; set allow_remote_processing=True "
            "or DEWATERMARK_ALLOW_REMOTE_PROCESSING=true after reviewing the privacy "
            "implications"
        )
