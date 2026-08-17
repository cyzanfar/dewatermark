"""Small bounded-retry HTTP helper shared by remote backends."""

from __future__ import annotations

import time
from typing import Optional

import requests

from .config import DewatermarkConfig
from .runtime import emit


def post_json(
    url: str,
    *,
    headers: dict,
    body: dict,
    timeout: int,
    retries: int = 2,
    config: Optional[DewatermarkConfig] = None,
    backend: str = "remote",
):
    last_error: requests.RequestException | None = None
    for attempt in range(retries + 1):
        started = time.monotonic()
        if config:
            emit(config, "http.request.started", backend=backend, attempt=attempt + 1)
        try:
            response = requests.post(
                url, headers=headers, json=body, timeout=timeout, allow_redirects=False
            )
            if response.status_code not in (408, 429) and response.status_code < 500:
                if config:
                    emit(
                        config,
                        "http.request.finished",
                        backend=backend,
                        attempt=attempt + 1,
                        status_code=response.status_code,
                        latency_ms=round((time.monotonic() - started) * 1000, 3),
                    )
                return response
            last_error = requests.HTTPError(
                f"retryable HTTP {response.status_code}", response=response
            )
        except requests.RequestException as exc:
            last_error = exc
        if attempt < retries:
            if config:
                emit(config, "http.request.retry", backend=backend, attempt=attempt + 1)
            time.sleep(min(2.0, 0.25 * (2**attempt)))
    assert last_error is not None
    raise last_error
