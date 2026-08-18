# Configuration

The core Unicode sanitizer needs no configuration. It runs locally without a
model or network connection.

Use `DewatermarkConfig` or `DEWATERMARK_*` environment variables for optional
model-backed rewriting, detector selection, quality checks, and request limits.
Remote text processing and model downloads require separate opt-ins.

## Python configuration

```python
from dewatermark import Dewatermark, DewatermarkConfig

config = DewatermarkConfig(
    sanitize_profile="safe",
    allow_model_download=False,
    allow_remote_processing=False,
    require_verified=False,
)

with Dewatermark(config) as dw:
    result = dw.remove("he\u200bllo", mode="sanitize")
```

`DewatermarkConfig` is immutable. Pass it to a `Dewatermark` instance or to a
configuration-aware operation such as `remove(..., config=config)`.

## Remote processing

This example sends source text to Fireworks. Keep credentials in the
environment and enable remote processing only after reviewing the privacy
impact:

```python
import os

from dewatermark import Dewatermark, DewatermarkConfig

text = "Text to process"
config = DewatermarkConfig(
    lm_backend="fireworks",
    fireworks_api_key=os.environ["DEWATERMARK_FIREWORKS_AI_API_KEY"],
    allow_remote_processing=True,
)

with Dewatermark(config) as dw:
    result = dw.remove(text, mode="bias_inversion", beta=6.0)
```

Setting an API key does not grant consent by itself. The request is denied
unless `allow_remote_processing=True` is also set. Model downloads use the
separate `allow_model_download` setting.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEWATERMARK_LM_BACKEND` | `auto` | `local`, `fireworks`, or automatic selection |
| `DEWATERMARK_LOCAL_LM` | `Qwen/Qwen2.5-0.5B-Instruct` | Local scorer and rewriter model |
| `DEWATERMARK_LOCAL_LM_ENABLED` | `true` | Allow configured local-model use |
| `DEWATERMARK_ALLOW_MODEL_DOWNLOAD` | `false` | Permit an explicit model download |
| `DEWATERMARK_FIREWORKS_AI_API_KEY` | — | Fireworks credential |
| `DEWATERMARK_FIREWORKS_BASE_URL` | Fireworks inference API | Fireworks-compatible endpoint |
| `DEWATERMARK_FIREWORKS_MODEL` | `accounts/fireworks/models/gpt-oss-20b` | Fireworks model identifier |
| `DEWATERMARK_LLM_API_KEY` | — | Credential sent to the configured OpenAI-compatible endpoint |
| `DEWATERMARK_LLM_BASE_URL` | `https://api.moonshot.ai/v1` | OpenAI-compatible endpoint; the key does not select it |
| `DEWATERMARK_LLM_MODEL` | `kimi-k2.6` | Model used by that endpoint |
| `DEWATERMARK_ALLOW_REMOTE_PROCESSING` | `false` | Permit source text to leave the process |
| `DEWATERMARK_SANITIZE_PROFILE` | `safe` | `safe` or explicitly lossy `aggressive` |
| `DEWATERMARK_SCORER_PROVIDER` | — | Registered scorer provider |
| `DEWATERMARK_REWRITER_PROVIDER` | — | Registered rewriter provider |
| `DEWATERMARK_DETECTOR_PROVIDER` | — | Named detector used for verification |
| `DEWATERMARK_REQUIRE_VERIFIED` | `false` | Reject statistical rewrites without compatible verification |
| `DEWATERMARK_REQUEST_RETRIES` | `2` | HTTP retry limit |
| `DEWATERMARK_REQUEST_TIMEOUT` | `120` | Request deadline in seconds |
| `DEWATERMARK_MAX_REMOTE_CALLS` | `16` | Physical HTTP-attempt limit; `0` disables remote calls |
| `DEWATERMARK_MAX_OUTPUT_TOKENS` | `2048` | Generated-token limit |
| `DEWATERMARK_MAX_INPUT_CHARS` | `1000000` | Input-character limit |
| `DEWATERMARK_MAX_CHUNK_CHARS` | `12000` | Rewrite chunk size |
| `DEWATERMARK_MAX_CONCURRENCY` | `4` | Batch worker limit |
| `DEWATERMARK_MAX_BATCH_ITEMS` | `1000` | Items accepted by one batch call |
| `DEWATERMARK_MODEL_CACHE_SIZE` | `2` | Local model instances kept in memory |
| `DEWATERMARK_RANDOM_SEED` | `13` | Recorded reproducibility seed |
| `DEWATERMARK_QUALITY_MIN_LENGTH_RATIO` | `0.70` | Minimum accepted candidate/source length ratio |
| `DEWATERMARK_QUALITY_MAX_LENGTH_RATIO` | `1.35` | Maximum accepted candidate/source length ratio |

New integrations should use the namespaced variables above. Unprefixed names
from version 0.2 remain temporary compatibility aliases.

## Privacy and credentials

- Configuration representations and result objects never include API keys.
- Endpoint URLs cannot contain embedded credentials.
- Planning does not load models, import unloaded plugins, open sockets, or send
  source text.
- A provider that can use a model or network must declare that requirement
  before receiving text.
- Request limits are shared across chunks, retries, providers, detectors, and
  quality checks.

See the [assurance model](ASSURANCE.md), [extension guide](EXTENSIONS.md), and
[quality-check guide](QUALITY_GATES.md) for the full execution rules.
