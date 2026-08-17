"""Non-interactive CLI designed for humans, scripts, and AI agents."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn, Optional, Sequence

from . import __version__, analyze, capabilities, plan, remove, sanitize
from .assurance_api import (
    ConsentRequiredError,
    PlanMismatchError,
    apply_plan,
    create_plan,
    inspect_text,
    verify_text,
)
from .config import DewatermarkConfig
from .exceptions import DewatermarkError
from .models import SCHEMA_VERSION
from .scanner import (
    baseline_fingerprints,
    changed_lines_from_unified_diff,
    scan_paths,
    scan_text,
    to_sarif,
)
from .schemas import public_schema
from .scoring import load

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_BACKEND = 3
EXIT_PROCESSING = 4

_MODES = (
    "auto",
    "sanitize",
    "paraphrase",
    "full",
    "sira",
    "bias_inversion",
    "adversarial",
)


class _SafeArgumentParser(argparse.ArgumentParser):
    """Reject malformed argv without reflecting supplied values to stderr."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: invalid command-line arguments\n")


class _CliUsageError(ValueError):
    """A locally generated, safe-to-display usage error."""


def _add_assurance_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("text", nargs="?", help="text; omit to read stdin")
    command.add_argument("--input", type=Path, help="read UTF-8 text from a file")
    command.add_argument("--mode", choices=_MODES, default="auto", help="transformation mode")
    command.add_argument("--passes", type=int, default=2, help="rewrite pass count")
    command.add_argument("--epsilon", type=float, default=0.3, help="SIRA mask fraction")
    command.add_argument("--beta", type=float, default=6.0, help="bias-inversion strength")
    command.add_argument("--best-of", type=int, default=3, help="candidate count")
    command.add_argument("--detector", default="unicode", help="registered detector name")
    command.add_argument(
        "--require-verified",
        action="store_true",
        help="reject a statistical rewrite unless the named independent detector clears it",
    )
    command.add_argument(
        "--allow-network", action="store_true", help="consent to remote text processing"
    )
    command.add_argument(
        "--allow-model-download",
        action="store_true",
        help="consent to model acquisition; requires --allow-network",
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="dewatermark",
        description="Inspect and remove suspicious Unicode artifacts; evaluate detector-scoped statistical mitigations.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    command_help = {
        "sanitize": "remove Unicode artifacts with a versioned local policy",
        "analyze": "inspect Unicode artifacts without changing text",
        "remove": "run the quality-gated transformation pipeline",
    }
    for name in ("sanitize", "analyze", "remove"):
        cmd = sub.add_parser(name, help=command_help[name])
        cmd.add_argument("text", nargs="?", help="text; omit to read stdin")
        cmd.add_argument("--input", type=Path, help="read UTF-8 text from a file")
        formats = {
            "sanitize": (("text", "json"), "text"),
            "analyze": (("json",), "json"),
            "remove": (("text", "json", "jsonl"), "text"),
        }
        choices, default = formats[name]
        cmd.add_argument("--format", choices=choices, default=default, help="output format")
        if name == "sanitize":
            cmd.add_argument(
                "--profile",
                choices=("safe", "aggressive"),
                default="safe",
                help="safe contextual cleanup or explicitly lossy aggressive normalization",
            )
        if name == "remove":
            cmd.add_argument(
                "--mode",
                choices=_MODES,
                default="auto",
                help="transformation mode",
            )
            cmd.add_argument("--passes", type=int, default=2, help="rewrite pass count")
            cmd.add_argument("--epsilon", type=float, default=0.3, help="SIRA mask fraction")
            cmd.add_argument("--beta", type=float, default=6.0, help="bias-inversion strength")
            cmd.add_argument("--best-of", type=int, default=3, help="candidate count")
            cmd.add_argument("--detector", help="registered detector name")
            cmd.add_argument(
                "--require-verified",
                action="store_true",
                help="reject an unverified statistical rewrite",
            )
            cmd.add_argument("--offline", action="store_true", help="disable all remote processing")
            cmd.add_argument(
                "--allow-network",
                action="store_true",
                help="explicitly allow configured remote text processing",
            )
            cmd.add_argument(
                "--allow-model-download",
                action="store_true",
                help="consent to model acquisition",
            )
            cmd.add_argument(
                "--dry-run", action="store_true", help="print a plan without processing"
            )
    inspect = sub.add_parser("inspect", help="content-bound, non-mutating assurance inspection")
    inspect.add_argument("text", nargs="?", help="text; omit to read stdin")
    inspect.add_argument("--input", type=Path, help="read UTF-8 text from a file")
    inspect.add_argument("--detector", default="unicode", help="registered detector name")
    assurance_plan = sub.add_parser("plan", help="create a content-bound transformation plan")
    _add_assurance_options(assurance_plan)
    apply = sub.add_parser("apply", help="apply an exact reviewed plan")
    _add_assurance_options(apply)
    apply.add_argument("--plan-digest", required=True, help="digest from the reviewed plan")
    apply.add_argument("--consent", action="store_true", help="consent to the reviewed transform")
    verify = sub.add_parser("verify", help="verify source and candidate with a named detector")
    verify.add_argument("source", nargs="?", help="source text")
    verify.add_argument("candidate", nargs="?", help="candidate text")
    verify.add_argument("--source-input", type=Path, help="read source from a UTF-8 file")
    verify.add_argument("--candidate-input", type=Path, help="read candidate from a UTF-8 file")
    verify.add_argument(
        "--detector", default="unicode-artifacts-v1", help="registered detector name"
    )
    sub.add_parser("capabilities", help="show installed features without network or model loading")
    schema = sub.add_parser("schema", help="print a packaged JSON Schema")
    schema.add_argument(
        "--kind",
        choices=(
            "removal-result",
            "evidence-receipt",
            "detector-capability",
            "command-detector",
        ),
        default="removal-result",
    )
    download = sub.add_parser("download-model", help="explicitly acquire a local model")
    download.add_argument("--model", help="Hugging Face model identifier or local path")
    check = sub.add_parser("check", help="scan files for suspicious Unicode")
    check.add_argument("paths", nargs="*", type=Path)
    check.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    check.add_argument("--output", type=Path)
    check.add_argument("--fix", action="store_true")
    check.add_argument("--profile", choices=("safe", "aggressive"), default="safe")
    check.add_argument("--max-file-bytes", type=int, default=2_000_000)
    check.add_argument("--baseline", type=Path, help="JSON finding baseline for comparison")
    check.add_argument("--write-baseline", type=Path, help="write finding fingerprints as JSON")
    check.add_argument("--suppress", action="append", default=[], help="finding suppression token")
    check.add_argument(
        "--new-only", action="store_true", help="report findings absent from baseline"
    )
    check.add_argument("--diff", type=Path, help="restrict findings to lines in a unified diff")
    check.add_argument(
        "--all-findings",
        action="store_true",
        help="include legitimate-context informational observations",
    )
    server = sub.add_parser("serve", help="run the local HTTP/OpenAPI API")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.add_argument("--api-key-env", default="DEWATERMARK_SERVER_API_KEY")
    return parser


def _read(args: argparse.Namespace) -> str:
    if args.text is not None and args.input is not None:
        raise _CliUsageError("provide only one of positional text or --input")
    if args.input:
        return args.input.read_text(encoding="utf-8")
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise _CliUsageError("text is required on stdin, as an argument, or with --input")


def _read_verify(args: argparse.Namespace) -> tuple[str, str]:
    if args.source is not None and args.source_input is not None:
        raise _CliUsageError("provide only one of source or --source-input")
    if args.candidate is not None and args.candidate_input is not None:
        raise _CliUsageError("provide only one of candidate or --candidate-input")
    source = (
        args.source_input.read_text(encoding="utf-8")
        if args.source_input is not None
        else args.source
    )
    candidate = (
        args.candidate_input.read_text(encoding="utf-8")
        if args.candidate_input is not None
        else args.candidate
    )
    if source is None or candidate is None:
        raise _CliUsageError("verify requires source and candidate text or file inputs")
    return source, candidate


def _assurance_options(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "passes": args.passes,
        "epsilon": args.epsilon,
        "beta": args.beta,
        "best_of": args.best_of,
    }


def _read_baseline(path: Optional[Path]) -> frozenset[str]:
    if path is None:
        return frozenset()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("fingerprints", [])
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise _CliUsageError("baseline must be a JSON string array or an object with fingerprints")
    return frozenset(payload)


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
        detector=args.detector,
        config=cfg,
    ).to_dict()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inspect":
            _emit(inspect_text(_read(args), args.detector))
            return EXIT_OK
        if args.command == "plan":
            _emit(
                create_plan(
                    _read(args),
                    args.mode,
                    detector=args.detector,
                    allow_network=args.allow_network,
                    allow_model_download=args.allow_model_download,
                    require_verified=args.require_verified,
                    options=_assurance_options(args),
                    config=DewatermarkConfig.from_env(),
                )
            )
            return EXIT_OK
        if args.command == "apply":
            _emit(
                apply_plan(
                    _read(args),
                    args.plan_digest,
                    args.mode,
                    detector=args.detector,
                    consent=args.consent,
                    allow_network=args.allow_network,
                    allow_model_download=args.allow_model_download,
                    require_verified=args.require_verified,
                    options=_assurance_options(args),
                    config=DewatermarkConfig.from_env(),
                )
            )
            return EXIT_OK
        if args.command == "verify":
            source, candidate = _read_verify(args)
            _emit(verify_text(source, candidate, args.detector))
            return EXIT_OK
        if args.command == "capabilities":
            _emit(capabilities())
            return EXIT_OK
        if args.command == "schema":
            _emit(public_schema(args.kind))
            return EXIT_OK
        if args.command == "download-model":
            cfg = DewatermarkConfig(
                local_lm=args.model or DewatermarkConfig().local_lm, allow_model_download=True
            )
            load(cfg)
            _emit({"status": "ready", "model": cfg.local_lm})
            return EXIT_OK
        if args.command == "serve":
            from .server import serve

            serve(args.host, args.port, args.api_key_env)
            return EXIT_OK
        if args.command == "check":
            baseline = _read_baseline(args.baseline)
            changed_lines = (
                changed_lines_from_unified_diff(args.diff.read_text(encoding="utf-8"))
                if args.diff
                else None
            )
            dispositions = (
                ("actionable", "contextual", "informational")
                if args.all_findings
                else ("actionable",)
            )
            if args.paths:
                report = scan_paths(
                    args.paths,
                    max_file_bytes=args.max_file_bytes,
                    fix=args.fix,
                    profile=args.profile,
                    baseline=baseline,
                    suppressions=args.suppress,
                    changed_lines=changed_lines,
                    dispositions=dispositions,
                    new_only=args.new_only,
                )
            elif not sys.stdin.isatty():
                from .scanner import ScanReport

                report = ScanReport(
                    1,
                    scan_text(
                        sys.stdin.read(),
                        baseline=baseline,
                        suppressions=args.suppress,
                        dispositions=dispositions,
                        new_only=args.new_only,
                    ),
                )
            else:
                report = scan_paths(
                    [Path(".")],
                    max_file_bytes=args.max_file_bytes,
                    fix=args.fix,
                    profile=args.profile,
                    baseline=baseline,
                    suppressions=args.suppress,
                    changed_lines=changed_lines,
                    dispositions=dispositions,
                    new_only=args.new_only,
                )
            if args.write_baseline:
                args.write_baseline.write_text(
                    json.dumps(
                        {
                            "schema_version": "1.0",
                            "fingerprints": sorted(baseline | baseline_fingerprints(report)),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            value: Any
            if args.format == "sarif":
                value = to_sarif(report)
            elif args.format == "json":
                value = report.to_dict()
            else:
                value = "\n".join(
                    f"{f.path}:{f.line}:{f.column}: {f.disposition} "
                    f"{f.category} {f.codepoint} - {f.message}"
                    for f in report.findings
                )
                if not value:
                    value = f"No suspicious Unicode found in {report.files_scanned} file(s)."
            output = (
                value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
            )
            if args.output:
                args.output.write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
            return (
                EXIT_PROCESSING
                if report.errors
                else (EXIT_FINDINGS if report.findings else EXIT_OK)
            )

        if args.command == "remove":
            cfg = DewatermarkConfig.from_env()
            cfg = replace(
                cfg,
                allow_model_download=args.allow_model_download,
                allow_remote_processing=(
                    False
                    if args.offline
                    else (True if args.allow_network else cfg.allow_remote_processing)
                ),
                require_verified=args.require_verified,
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
                except (json.JSONDecodeError, KeyError, TypeError):
                    had_errors = True
                    _emit(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "line": line_number,
                            "status": "failed",
                            "error": "line is not valid JSON with a text field",
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
    except _CliUsageError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return EXIT_USAGE
    except ConsentRequiredError:
        print(
            json.dumps({"status": "failed", "error": "apply requires explicit consent=true"}),
            file=sys.stderr,
        )
        return EXIT_USAGE
    except PlanMismatchError:
        print(
            json.dumps(
                {"status": "failed", "error": "plan digest does not match the reviewed request"}
            ),
            file=sys.stderr,
        )
        return EXIT_USAGE
    except (ValueError, OSError):
        print(json.dumps({"status": "failed", "error": "invalid input"}), file=sys.stderr)
        return EXIT_USAGE
    except PermissionError:
        print(
            json.dumps({"status": "failed", "error": "operation is not permitted"}), file=sys.stderr
        )
        return EXIT_BACKEND
    except DewatermarkError:
        print(
            json.dumps({"status": "failed", "error": "backend operation failed; details redacted"}),
            file=sys.stderr,
        )
        return EXIT_BACKEND
    except Exception:
        print(
            json.dumps({"status": "failed", "error": "processing failed; details redacted"}),
            file=sys.stderr,
        )
        return EXIT_PROCESSING


if __name__ == "__main__":
    raise SystemExit(main())
