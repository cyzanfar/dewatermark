#!/usr/bin/env python3
"""Export or verify the canonical OpenAPI document without starting a server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dewatermark.server import openapi_schema  # noqa: E402

TARGET = ROOT / "schemas" / "openapi-v1.json"


def rendered() -> str:
    return json.dumps(openapi_schema(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="verify the checked-in snapshot")
    action.add_argument("--write", action="store_true", help="update the checked-in snapshot")
    args = parser.parse_args()
    expected = rendered()
    if args.write:
        TARGET.write_text(expected, encoding="utf-8")
        return 0
    try:
        current = TARGET.read_text(encoding="utf-8")
    except FileNotFoundError:
        print("OpenAPI snapshot is missing; run with --write", file=sys.stderr)
        return 1
    if current != expected:
        print("OpenAPI snapshot is stale; run with --write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
