#!/usr/bin/env python3
"""Minimal offline command-detector protocol example.

This is a deterministic conformance example, not a real watermark detector.
Register it from Python with a static manifest; the runtime will execute this
file only when detection is explicitly requested::

    import sys
    from pathlib import Path

    from dewatermark.command_detector import (
        command_detector_manifest,
        detector_configuration_sha256,
        make_command_detector_factory,
    )
    from dewatermark.providers import register_detector

    public_config = {"algorithm": "marker-count-v1", "marker": "[demo-watermark]"}
    manifest = command_detector_manifest(
        identifier="demo-command-detector",
        schemes=("demo-marker",),
        configuration_sha256=detector_configuration_sha256(public_config),
        threshold=1.0,
        calibrated=False,
        independent=False,
    )
    command = (sys.executable, str(Path("examples/detector_adapter.py").resolve()))
    register_detector("demo-command", make_command_detector_factory(command, manifest))

The marker is intentionally visible so this example cannot be mistaken for
evidence about a production or vendor watermark.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from typing import Any, Mapping

PROTOCOL_VERSION = "1.0"
DETECTOR = "demo-command-detector"
SCHEME = "demo-marker"
MARKER = "[demo-watermark]"
THRESHOLD = 1.0
PUBLIC_CONFIGURATION = {"algorithm": "marker-count-v1", "marker": MARKER}


def _configuration_sha256(configuration: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        configuration, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


CONFIGURATION_SHA256 = _configuration_sha256(PUBLIC_CONFIGURATION)


def _safe_failure(reason_code: str) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "action": "detect.result",
        "detector": DETECTOR,
        "scheme": SCHEME,
        "status": "detector_error",
        "score": None,
        "threshold": THRESHOLD,
        "score_direction": "higher",
        "effective_tokens": 0,
        "configuration_sha256": CONFIGURATION_SHA256,
        "reason_code": reason_code,
    }


def handle(request: Mapping[str, Any]) -> dict[str, Any]:
    if request.get("protocol_version") != PROTOCOL_VERSION:
        return _safe_failure("incompatible_protocol")
    if request.get("action") != "detect":
        return _safe_failure("unsupported_action")
    if request.get("detector") != DETECTOR:
        return _safe_failure("detector_mismatch")
    if request.get("configuration_sha256") != CONFIGURATION_SHA256:
        return _safe_failure("configuration_mismatch")
    text = request.get("text")
    if not isinstance(text, str):
        return _safe_failure("invalid_text")
    score = float(text.count(MARKER))
    assert math.isfinite(score)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "action": "detect.result",
        "detector": DETECTOR,
        "scheme": SCHEME,
        "status": "detected" if score >= THRESHOLD else "not_detected",
        "score": score,
        "threshold": THRESHOLD,
        "score_direction": "higher",
        "effective_tokens": len(text.split()),
        "configuration_sha256": CONFIGURATION_SHA256,
    }


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, Mapping):
            response = _safe_failure("invalid_request")
        else:
            response = handle(request)
    except (json.JSONDecodeError, UnicodeError, ValueError, TypeError):
        response = _safe_failure("invalid_request")
    json.dump(response, sys.stdout, ensure_ascii=True, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
