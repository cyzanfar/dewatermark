"""Minimal executable implementing command-strategy protocol v1.

Run it through ``CommandStrategy((sys.executable, this_file), manifest)``. This
example is intentionally deterministic and offline; its outputs remain
untrusted candidates that ``mitigate`` must quality-check and verify.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    text = request["text"]
    limit = request["policy"]["max_candidates"]
    candidates = []
    if " very " in text:
        candidates.append(text.replace(" very ", " ", 1))
    if "; " in text:
        candidates.append(text.replace("; ", ". ", 1))
    response = {
        "protocol_version": request["protocol_version"],
        "action": "generate.result",
        "strategy": request["strategy"],
        "configuration_sha256": request["configuration_sha256"],
        "candidates": candidates[:limit],
    }
    json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
