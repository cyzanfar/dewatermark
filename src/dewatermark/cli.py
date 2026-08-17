"""Non-interactive CLI designed for humans, scripts, and AI agents."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional, Sequence

from . import __version__, analyze, capabilities, plan, remove, sanitize
from .config import DewatermarkConfig
from .exceptions import DewatermarkError
from .models import SCHEMA_VERSION
from .schemas import removal_result_schema
from .scoring import load

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BACKEND = 3
EXIT_PROCESSING = 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dewatermark")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("sanitize", "analyze", "remove"):
        cmd = sub.add_parser(name)
        cmd.add_argument("text", nargs="?", help="text; omit to read stdin")
        cmd.add_argument("--input", type=Path, help="read UTF-8 text from a file")
        cmd.add_argument("--format", choices=("text", "json", "jsonl"), default="text")
        if name == "sanitize":
            cmd.add_argument("--profile", choices=("safe", "aggressive"), default="safe")
        if name == "remove":
            cmd.add_argument(
                "--mode",
                choices=(
                    "auto",
                    "sanitize",
                    "paraphrase",
                    "full",
                    "sira",
                    "bias_inversion",
                    "adversarial",
                ),
                default="auto",
            )
            cmd.add_argument("--passes", type=int, default=2)
            cmd.add_argument("--epsilon", type=float, default=0.3)
            cmd.add_argument("--beta", type=float, default=6.0)
            cmd.add_argument("--best-of", type=int, default=3)
            cmd.add_argument("--offline", action="store_true")
            cmd.add_argument("--allow-model-download", action="store_true")
            cmd.add_argument("--dry-run", action="store_true")
    sub.add_parser("capabilities")
    sub.add_parser("schema")
    download = sub.add_parser("download-model")
    download.add_argument("--model")
    return parser


def _read(args: argparse.Namespace) -> str:
    if args.text is not None and args.input is not None:
        raise ValueError("provide only one of positional text or --input")
    if args.input:
        return args.input.read_text(encoding="utf-8")
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise ValueError("text is required on stdin, as an argument, or with --input")


def _schema() -> dict[str, Any]:
    return removal_result_schema()


def _emit(value: Any, fmt: str = "json") -> None:
    if fmt == "text" and isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _remove_one(text: str, args: argparse.Namespace, cfg: DewatermarkConfig) -> dict:
    return remove(
        text,
        mode=args.mode,
        passes=args.passes,
        epsilon=args.epsilon,
        beta=args.beta,
        best_of=args.best_of,
        config=cfg,
    ).to_dict()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "capabilities":
            _emit(capabilities())
            return EXIT_OK
        if args.command == "schema":
            _emit(_schema())
            return EXIT_OK
        if args.command == "download-model":
            cfg = DewatermarkConfig(
                local_lm=args.model or DewatermarkConfig().local_lm, allow_model_download=True
            )
            load(cfg)
            _emit({"status": "ready", "model": cfg.local_lm})
            return EXIT_OK

        if args.command == "remove":
            cfg = DewatermarkConfig.from_env()
            cfg = replace(
                cfg,
                allow_model_download=args.allow_model_download,
                allow_remote_processing=False if args.offline else cfg.allow_remote_processing,
            )
            if args.dry_run:
                _emit(plan(args.mode, cfg, passes=args.passes, best_of=args.best_of).to_dict())
                return EXIT_OK

        text = _read(args)
        if args.command == "sanitize":
            cleaned = sanitize(text, profile=args.profile)
            _emit(
                cleaned
                if args.format == "text"
                else {
                    "schema_version": SCHEMA_VERSION,
                    "cleaned_text": cleaned,
                    "changed": cleaned != text,
                },
                args.format,
            )
            return EXIT_OK
        if args.command == "analyze":
            _emit(analyze(text), "json")
            return EXIT_OK

        if args.format == "jsonl":
            had_errors = False
            for line_number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                    source = payload["text"] if isinstance(payload, dict) else str(payload)
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    had_errors = True
                    _emit(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "line": line_number,
                            "status": "failed",
                            "error": str(exc),
                        }
                    )
                    continue
                result = _remove_one(source, args, cfg)
                result["line"] = line_number
                _emit(result)
            return EXIT_PROCESSING if had_errors else EXIT_OK
        result = _remove_one(text, args, cfg)
        _emit(result["cleaned_text"] if args.format == "text" else result, args.format)
        return EXIT_OK
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return EXIT_USAGE
    except DewatermarkError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return EXIT_BACKEND
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return EXIT_PROCESSING


if __name__ == "__main__":
    raise SystemExit(main())
