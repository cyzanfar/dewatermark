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
| `DEWATERMARK_MAX_DETECTOR_QUERIES` | `64` | Detector cache misses allowed in one localization or mitigation request |
| `DEWATERMARK_MAX_SEARCH_CANDIDATES` | `24` | Candidates examined in one mitigation request |
| `DEWATERMARK_MODEL_CACHE_SIZE` | `2` | Local model instances kept in memory |
| `DEWATERMARK_RANDOM_SEED` | `13` | Recorded reproducibility seed |
| `DEWATERMARK_QUALITY_MIN_LENGTH_RATIO` | `0.70` | Minimum accepted candidate/source length ratio |
| `DEWATERMARK_QUALITY_MAX_LENGTH_RATIO` | `1.35` | Maximum accepted candidate/source length ratio |

New integrations should use the namespaced variables above. Unprefixed names
from version 0.2 remain temporary compatibility aliases.

## Detector-guided search limits

`DewatermarkConfig` sets application-wide ceilings. A caller may set smaller
per-request values with `SearchLimits`, the CLI flags, the HTTP `limits` object,
or the MCP arguments. A request cannot raise an application ceiling.

| Limit | Normal default | Allowed range | Notes |
| --- | --- | --- | --- |
| `max_rounds` | `2` | 1–32 | Search passes over the current beam |
| `beam_width` | `4` | 1–32 | Detected candidates kept for another round |
| `max_candidates` | Configured `max_search_candidates` (`24`) | 1–512 per request; config range 1–1000 | Counts proposals before quality and detector checks |
| `max_transform_calls` | Chosen candidate limit on CLI/HTTP/MCP | 1–512 | Counts strategy invocations, including rejected ones |
| `max_detector_queries` | Configured value (`64`) | 1–100,000 | Counts detector cache misses across search and verification |
| `max_candidate_characters` | Configured `max_input_chars` | 1–10,000,000 | Python-only field; effective value cannot exceed `max_input_chars` |
| `max_verification_candidates` | `8` | 1–128 | Cleared candidates tried against held-out verifiers |

`SearchLimits()` by itself has `max_candidates=32` and
`max_transform_calls=32`. When `mitigate()` creates limits from configuration,
it uses `max_search_candidates` for the candidate ceiling. The CLI, HTTP, and
MCP transports default transform calls to the selected candidate limit.

`DetectorSession(max_queries=...)` uses the smaller of its requested value and
`DewatermarkConfig.max_detector_queries`. Cache hits are free. `score_many()`
rejects a batch before invoking any new detector when all cache misses would not
fit.

Localization also spends from this detector-query budget. It scores the full
document first, then all fallback windows as one preflighted batch. Choose a
window and stride that fit the budget; a smaller stride creates more windows.
The fallback also refuses to materialize more than four million aggregate
window characters, preventing highly overlapping scans from amplifying memory.

Network access and model download are not search limits. They are permissions
and remain off unless the caller opts in. Transformation consent is also
required by CLI, HTTP, and MCP mitigation calls.

### Command strategy bounds

`CommandStrategy` has separate process and response bounds. Its defaults are a
60-second timeout, 4 MiB stdout, 16 KiB stderr, 8 candidates, 1,000,000
characters per candidate, and 4,000,000 aggregate candidate characters. The
hard implementation ceilings are 3,600 seconds, 16 MiB per captured stream,
1,000 candidates, and 67,108,864 characters per candidate or in aggregate.

Effective candidate, character, token, timeout, network, and model permissions
are always reduced to the active request and application limits. A command
cannot use its response to increase them. See
[Extensions](EXTENSIONS.md#bounded-command-strategies) for the protocol.

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
[quality-check guide](QUALITY_GATES.md) for the full execution rules. The
[detector-guided mitigation guide](DETECTOR_GUIDED_MITIGATION.md) explains how
these limits are shared by localization, search, and held-out verification.
