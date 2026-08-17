"""Small bounded-retry HTTP helper shared by remote backends."""

from __future__ import annotations

import time
from typing import Optional

import requests

from .config import DewatermarkConfig, assert_remote_allowed
from .exceptions import BackendUnavailableError
from .request_context import current_request_context
from .runtime import emit


class HTTPTransportError(BackendUnavailableError):
    """A bounded remote request failed without retaining request/response data."""


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
    effective_config = config or DewatermarkConfig()
    assert_remote_allowed(url, effective_config)
    failed = False
    for attempt in range(retries + 1):
        started = time.monotonic()
        context = current_request_context()
        effective_timeout: float = timeout
        if context is not None:
            context.before_remote_call(url, backend, body)
            effective_timeout = context.remaining_seconds(float(timeout))
        if config:
            emit(config, "http.request.started", backend=backend, attempt=attempt + 1)
        try:
            response = requests.post(
                url,
                headers=headers,
                json=body,
                timeout=effective_timeout,
                allow_redirects=False,
            )
            if context is not None and response.status_code >= 400:
                context.release_latest_output_reservation()
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
            failed = True
        except requests.RequestException:
            failed = True
            if context is not None:
                context.release_latest_output_reservation()
        if attempt < retries:
            if config:
                emit(config, "http.request.retry", backend=backend, attempt=attempt + 1)
            delay = min(2.0, 0.25 * (2**attempt))
            if context is not None:
                delay = min(delay, context.remaining_seconds())
            time.sleep(delay)
    if not failed:  # defensive: the loop always returns or records a failure
        raise HTTPTransportError("remote request did not complete") from None
    raise HTTPTransportError(
        "remote request failed after bounded retries; details redacted"
    ) from None
