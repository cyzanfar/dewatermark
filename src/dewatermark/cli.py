"""Non-interactive CLI designed for humans, scripts, and AI agents."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn, Optional, Sequence

from . import __version__, analyze, capabilities, plan, remove, sanitize
from .adapter_packs import list_adapter_packs, materialize_adapter_pack
from .agent_skill import agent_skill_path, materialize_agent_skill
from .assurance_api import (
    ConsentRequiredError,
    PlanMismatchError,
    apply_plan,
    create_plan,
    inspect_text,
    verify_text,
)
from .config import DewatermarkConfig
from .detector_session import DetectorSession
from .detector_tools import (
    conform_reference_detectors,
    discover_detector_capabilities,
    doctor_detectors,
)
from .exceptions import DewatermarkError
from .localization import localize
from .models import SCHEMA_VERSION
from .optimizer import SearchLimits, mitigate
from .reference_detectors import ReferenceScheme
from .scanner import (
    baseline_fingerprints,
    changed_lines_from_unified_diff,
    path_is_selected,
    scan_paths,
    scan_text,
    to_sarif,
)
from .scanner_config import resolve_scanner_config
from .schemas import public_schema
from .scoring import load
from .strategies import registered_strategy

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_BACKEND = 3
EXIT_PROCESSING = 4
_MAX_CLI_TEXT_BYTES = 16 * 1024 * 1024
_MAX_CLI_AUXILIARY_BYTES = 16 * 1024 * 1024

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
    command.add_argument("--passes", type=int, default=2, help="rewrite pass count (1-5)")
    command.add_argument("--epsilon", type=float, default=0.3, help="SIRA mask fraction (0.05-0.9)")
    command.add_argument("--beta", type=float, default=6.0, help="bias-inversion strength (0-20)")
    command.add_argument("--best-of", type=int, default=3, help="candidate count (1-6)")
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
            cmd.add_argument("--passes", type=int, default=2, help="rewrite pass count (1-5)")
            cmd.add_argument(
                "--epsilon", type=float, default=0.3, help="SIRA mask fraction (0.05-0.9)"
            )
            cmd.add_argument(
                "--beta", type=float, default=6.0, help="bias-inversion strength (0-20)"
            )
            cmd.add_argument("--best-of", type=int, default=3, help="candidate count (1-6)")
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
    localization = sub.add_parser(
        "localize",
        help="locate spans implicated by a named detector without changing text",
    )
    localization.add_argument("text", nargs="?", help="text; omit to read stdin")
    localization.add_argument("--input", type=Path, help="read UTF-8 text from a file")
    localization.add_argument("--detector", required=True, help="registered detector name")
    localization.add_argument(
        "--window-characters", type=int, default=1200, help="fallback window size"
    )
    localization.add_argument(
        "--stride-characters", type=int, default=600, help="fallback window stride"
    )
    localization.add_argument(
        "--familywise-alpha", type=float, default=0.01, help="window-search error rate"
    )
    localization.add_argument(
        "--max-detector-queries", type=int, help="cap detector calls for this request"
    )
    localization.add_argument(
        "--allow-network", action="store_true", help="allow this detector to transmit text"
    )
    localization.add_argument(
        "--allow-model-download",
        action="store_true",
        help="allow this detector to acquire a model",
    )
    mitigation = sub.add_parser(
        "mitigate",
        help="search for the smallest quality-safe candidate verified by held-out detectors",
    )
    mitigation.add_argument("text", nargs="?", help="text; omit to read stdin")
    mitigation.add_argument("--input", type=Path, help="read UTF-8 text from a file")
    mitigation.add_argument("--detector", required=True, help="primary search detector")
    mitigation.add_argument(
        "--verifier",
        action="append",
        required=True,
        help="distinct calibrated verifier; repeat for more than one",
    )
    mitigation.add_argument(
        "--strategy",
        action="append",
        required=True,
        help="registered transformer provider; repeat to search a portfolio",
    )
    mitigation.add_argument(
        "--consent",
        action="store_true",
        help="consent to candidate generation under the declared permissions",
    )
    mitigation.add_argument(
        "--allow-network", action="store_true", help="allow declared remote candidate work"
    )
    mitigation.add_argument(
        "--allow-model-download",
        action="store_true",
        help="allow declared model acquisition",
    )
    mitigation.add_argument("--format", choices=("json", "text"), default="json")
    mitigation.add_argument("--max-rounds", type=int, default=2)
    mitigation.add_argument("--beam-width", type=int, default=4)
    mitigation.add_argument("--max-candidates", type=int)
    mitigation.add_argument("--max-transform-calls", type=int)
    mitigation.add_argument("--max-detector-queries", type=int)
    mitigation.add_argument("--max-verification-candidates", type=int, default=8)
    sub.add_parser("capabilities", help="show installed features without network or model loading")
    skill = sub.add_parser(
        "skill",
        help="locate or install the bundled AI-agent workflow",
        description="Locate or safely copy the bundled remove-text-watermarks agent skill.",
    )
    skill_sub = skill.add_subparsers(dest="skill_command", required=True)
    skill_sub.add_parser("path", help="print the filesystem path to the bundled skill")
    skill_install = skill_sub.add_parser(
        "install", help="copy the skill into a new directory without overwriting files"
    )
    skill_install.add_argument("--output", type=Path, required=True)
    detectors = sub.add_parser(
        "detectors",
        help="inventory and validate detector integrations without sending text",
        description=(
            "Inspect static detector manifests or run the packaged synthetic-reference "
            "vectors. Listing and doctor never import entry-point plugins, start commands, "
            "load models, or open sockets."
        ),
    )
    detector_sub = detectors.add_subparsers(dest="detector_command", required=True)
    detector_sub.add_parser(
        "list",
        help="list canonical static capabilities and aliases without loading plugins",
    )
    detector_sub.add_parser(
        "doctor",
        help="audit static pins, abstentions, and claim boundaries",
    )
    detector_conformance = detector_sub.add_parser(
        "conformance",
        help="run dependency-free public vectors for the built-in research fixtures",
    )
    detector_conformance.add_argument(
        "--scheme",
        choices=("all", "kgw", "unigram", "tournament"),
        default="all",
        help="synthetic reference family to validate (never a vendor detector)",
    )
    detector_sub.add_parser(
        "packs",
        help="list pinned external adapter packs and their fail-closed status",
    )
    detector_scaffold = detector_sub.add_parser(
        "scaffold",
        help="copy one adapter pack into a new directory without overwriting files",
    )
    detector_scaffold.add_argument("--pack", choices=("kgw", "synthid", "unigram"), required=True)
    detector_scaffold.add_argument("--output", type=Path, required=True)
    schema = sub.add_parser("schema", help="print a packaged JSON Schema")
    schema.add_argument(
        "--kind",
        choices=(
            "removal-result",
            "evidence-receipt",
            "detector-capability",
            "command-detector",
            "command-strategy",
            "localization-result",
            "mitigation-result",
            "benchmark-evidence-bundle",
            "benchmark-comparator-registry",
            "benchmark-protocol-manifest",
            "benchmark-run-config",
            "benchmark-input-corpus",
            "benchmark-observation-set",
            "benchmark-replication-record",
            "benchmark-sample-registry",
            "openapi",
        ),
        default="removal-result",
    )
    download = sub.add_parser("download-model", help="explicitly acquire a local model")
    download.add_argument("--model", help="Hugging Face model identifier or local path")
    check = sub.add_parser("check", help="scan files for suspicious Unicode")
    check.add_argument("paths", nargs="*", type=Path)
    check.add_argument(
        "--stdin-path",
        type=Path,
        help="label stdin as this file and apply its repository scanner policy",
    )
    check.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    check.add_argument("--output", type=Path)
    check.add_argument("--fix", action="store_true")
    check.add_argument("--profile", choices=("safe", "aggressive"), default="safe")
    check.add_argument(
        "--max-file-bytes",
        type=int,
        help="maximum bytes per file; overrides discovered scanner configuration",
    )
    config_group = check.add_mutually_exclusive_group()
    config_group.add_argument(
        "--config", type=Path, help="explicit .dewatermark.toml or pyproject.toml"
    )
    config_group.add_argument(
        "--no-config", action="store_true", help="disable scanner configuration discovery"
    )
    check.add_argument(
        "--exclude", action="append", default=[], help="additional cross-platform exclude glob"
    )
    check.add_argument(
        "--extension",
        action="append",
        help="file extension to scan; repeat to replace configured extensions",
    )
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


def _read_bounded_file(path: Path, *, maximum: int, label: str) -> str:
    if not path.is_file():
        raise _CliUsageError(f"{label} must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise _CliUsageError(f"{label} exceeds the supported size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise _CliUsageError(f"{label} must be valid UTF-8") from None


def _read(args: argparse.Namespace) -> str:
    if args.text is not None and args.input is not None:
        raise _CliUsageError("provide only one of positional text or --input")
    if args.input:
        return _read_bounded_file(args.input, maximum=_MAX_CLI_TEXT_BYTES, label="input")
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        value = sys.stdin.read(_MAX_CLI_TEXT_BYTES + 1)
        if len(value.encode("utf-8")) > _MAX_CLI_TEXT_BYTES:
            raise _CliUsageError("standard input exceeds the supported size limit")
        return value
    raise _CliUsageError("text is required on stdin, as an argument, or with --input")


def _read_verify(args: argparse.Namespace) -> tuple[str, str]:
    if args.source is not None and args.source_input is not None:
        raise _CliUsageError("provide only one of source or --source-input")
    if args.candidate is not None and args.candidate_input is not None:
        raise _CliUsageError("provide only one of candidate or --candidate-input")
    source = (
        _read_bounded_file(
            args.source_input,
            maximum=_MAX_CLI_TEXT_BYTES,
            label="source input",
        )
        if args.source_input is not None
        else args.source
    )
    candidate = (
        _read_bounded_file(
            args.candidate_input,
            maximum=_MAX_CLI_TEXT_BYTES,
            label="candidate input",
        )
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
    payload = json.loads(
        _read_bounded_file(path, maximum=_MAX_CLI_AUXILIARY_BYTES, label="baseline")
    )
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


def _removal_failed(result: Any) -> bool:
    if not isinstance(result, dict):
        return True
    report = result.get("report")
    return not isinstance(report, dict) or report.get("status") == "failed"


def _emit_jsonl_failure(line_number: int, error: str) -> None:
    _emit(
        {
            "schema_version": SCHEMA_VERSION,
            "line": line_number,
            "status": "failed",
            "error": error,
        }
    )


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
            applied = apply_plan(
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
            _emit(applied)
            return EXIT_PROCESSING if _removal_failed(applied.get("result")) else EXIT_OK
        if args.command == "verify":
            source, candidate = _read_verify(args)
            _emit(verify_text(source, candidate, args.detector))
            return EXIT_OK
        if args.command == "localize":
            config = replace(
                DewatermarkConfig.from_env(),
                allow_remote_processing=bool(args.allow_network),
                allow_model_download=bool(args.allow_model_download),
            )
            session = DetectorSession(
                args.detector,
                config=config,
                max_queries=args.max_detector_queries,
            )
            localization_report = localize(
                _read(args),
                session,
                window_characters=args.window_characters,
                stride_characters=args.stride_characters,
                familywise_alpha=args.familywise_alpha,
            )
            _emit(localization_report.to_dict())
            return EXIT_PROCESSING if localization_report.status == "failed" else EXIT_OK
        if args.command == "mitigate":
            if not args.consent:
                raise ConsentRequiredError
            config = replace(
                DewatermarkConfig.from_env(),
                allow_remote_processing=bool(args.allow_network),
                allow_model_download=bool(args.allow_model_download),
            )
            max_candidates = (
                args.max_candidates
                if args.max_candidates is not None
                else config.max_search_candidates
            )
            max_transform_calls = (
                args.max_transform_calls if args.max_transform_calls is not None else max_candidates
            )
            limits = SearchLimits(
                max_rounds=args.max_rounds,
                beam_width=args.beam_width,
                max_candidates=max_candidates,
                max_transform_calls=max_transform_calls,
                max_detector_queries=(
                    args.max_detector_queries
                    if args.max_detector_queries is not None
                    else config.max_detector_queries
                ),
                max_candidate_characters=config.max_input_chars,
                max_verification_candidates=args.max_verification_candidates,
            )
            source_text = _read(args)
            strategies = [registered_strategy(name, config) for name in args.strategy]
            mitigation_result = mitigate(
                source_text,
                args.detector,
                strategies,
                verifier_detectors=args.verifier,
                config=config,
                limits=limits,
            )
            _emit(
                (
                    mitigation_result.cleaned_text
                    if args.format == "text"
                    else mitigation_result.to_dict()
                ),
                args.format,
            )
            return (
                EXIT_OK
                if mitigation_result.status == "verified"
                or mitigation_result.reason_code == "source_not_detected"
                else EXIT_PROCESSING
            )
        if args.command == "capabilities":
            _emit(capabilities())
            return EXIT_OK
        if args.command == "skill":
            if args.skill_command == "path":
                _emit({"name": "remove-text-watermarks", "path": str(agent_skill_path())})
                return EXIT_OK
            created = materialize_agent_skill(args.output)
            _emit(
                {
                    "status": "created",
                    "name": "remove-text-watermarks",
                    "output": str(args.output),
                    "files": [path.relative_to(args.output).as_posix() for path in created],
                }
            )
            return EXIT_OK
        if args.command == "detectors":
            if args.detector_command == "list":
                _emit(
                    {
                        "side_effect_free": True,
                        "detectors": [
                            entry.to_dict() for entry in discover_detector_capabilities()
                        ],
                    }
                )
                return EXIT_OK
            if args.detector_command == "doctor":
                doctor_report = doctor_detectors()
                _emit(doctor_report.to_dict())
                return EXIT_OK if doctor_report.passed else EXIT_PROCESSING
            if args.detector_command == "packs":
                _emit({"side_effect_free": True, "packs": list(list_adapter_packs())})
                return EXIT_OK
            if args.detector_command == "scaffold":
                created = materialize_adapter_pack(args.pack, args.output)
                _emit(
                    {
                        "status": "created",
                        "pack": args.pack,
                        "output": str(args.output),
                        "files": [path.name for path in created],
                    }
                )
                return EXIT_OK
            scheme_choices: dict[str, tuple[ReferenceScheme, ...]] = {
                "kgw": ("kgw-word-v1",),
                "unigram": ("unigram-word-v1",),
                "tournament": ("tournament-word-v1",),
            }
            selected = scheme_choices.get(args.scheme)
            conformance_report = conform_reference_detectors(selected)
            _emit(conformance_report.to_dict())
            return EXIT_OK if conformance_report.passed else EXIT_PROCESSING
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
            if args.paths and args.stdin_path is not None:
                raise _CliUsageError("--stdin-path cannot be combined with path arguments")
            config_start = (
                args.paths[0]
                if len(args.paths) == 1
                else (args.stdin_path.parent if args.stdin_path is not None else Path.cwd())
            )
            scanner_config = resolve_scanner_config(
                args.config,
                start=config_start,
                discover=not args.no_config,
            )
            policy_root = (
                Path(scanner_config.source).parent
                if scanner_config.source is not None
                else config_start
            )
            baseline = _read_baseline(args.baseline)
            changed_lines = (
                changed_lines_from_unified_diff(
                    _read_bounded_file(
                        args.diff,
                        maximum=_MAX_CLI_AUXILIARY_BYTES,
                        label="diff",
                    )
                )
                if args.diff
                else None
            )
            dispositions = (
                ("actionable", "contextual", "informational")
                if args.all_findings
                else scanner_config.dispositions
            )
            suppressions = (*scanner_config.suppressions, *args.suppress)
            exclude_patterns = (*scanner_config.exclude, *args.exclude)
            extensions = tuple(args.extension) if args.extension else scanner_config.extensions
            max_file_bytes = (
                args.max_file_bytes
                if args.max_file_bytes is not None
                else scanner_config.max_file_bytes
            )
            if not 1 <= max_file_bytes <= 1_000_000_000:
                raise _CliUsageError("max file bytes is outside the supported range")
            if args.paths:
                report = scan_paths(
                    args.paths,
                    max_file_bytes=max_file_bytes,
                    fix=args.fix,
                    profile=args.profile,
                    baseline=baseline,
                    suppressions=suppressions,
                    changed_lines=changed_lines,
                    dispositions=dispositions,
                    new_only=args.new_only,
                    exclude_patterns=exclude_patterns,
                    extensions=extensions,
                    policy_root=policy_root,
                )
            elif not sys.stdin.isatty():
                from .scanner import ScanReport

                if args.fix:
                    raise _CliUsageError("--fix requires filesystem path arguments")
                if args.diff is not None:
                    raise _CliUsageError("--diff requires filesystem path arguments")
                source_text = sys.stdin.read(max_file_bytes + 1)
                if len(source_text.encode("utf-8")) > max_file_bytes:
                    raise _CliUsageError("standard input exceeds max file bytes")
                stdin_selected = args.stdin_path is None or path_is_selected(
                    args.stdin_path,
                    root=policy_root,
                    exclude_patterns=exclude_patterns,
                    extensions=extensions,
                )
                stdin_findings = (
                    scan_text(
                        source_text,
                        path=str(args.stdin_path) if args.stdin_path is not None else "<stdin>",
                        baseline=baseline,
                        suppressions=suppressions,
                        dispositions=dispositions,
                        new_only=args.new_only,
                    )
                    if stdin_selected
                    else ()
                )
                report = ScanReport(
                    int(stdin_selected),
                    stdin_findings,
                    configuration={
                        "max_file_bytes": max_file_bytes,
                        "fix": False,
                        "profile": args.profile,
                        "new_only": args.new_only,
                        "extensions": sorted(extensions),
                        "exclude_patterns": sorted(exclude_patterns),
                        "dispositions": sorted(dispositions),
                        "suppression_count": len(suppressions),
                        "baseline_count": len(baseline),
                        "diff_filter": False,
                    },
                )
            else:
                if args.stdin_path is not None:
                    raise _CliUsageError("--stdin-path requires piped stdin")
                report = scan_paths(
                    [Path(".")],
                    max_file_bytes=max_file_bytes,
                    fix=args.fix,
                    profile=args.profile,
                    baseline=baseline,
                    suppressions=suppressions,
                    changed_lines=changed_lines,
                    dispositions=dispositions,
                    new_only=args.new_only,
                    exclude_patterns=exclude_patterns,
                    extensions=extensions,
                    policy_root=policy_root,
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
                    if not isinstance(payload, dict) or type(payload.get("text")) is not str:
                        raise TypeError
                    source = payload["text"]
                except (json.JSONDecodeError, TypeError):
                    had_errors = True
                    _emit_jsonl_failure(
                        line_number,
                        "line is not valid JSON with a text field",
                    )
                    continue
                try:
                    result = _remove_one(source, args, cfg)
                except PermissionError:
                    had_errors = True
                    _emit_jsonl_failure(line_number, "line operation is not permitted")
                    continue
                except DewatermarkError:
                    had_errors = True
                    _emit_jsonl_failure(
                        line_number,
                        "line backend operation failed; details redacted",
                    )
                    continue
                except (ValueError, OSError):
                    had_errors = True
                    _emit_jsonl_failure(line_number, "line contains invalid input")
                    continue
                except Exception:
                    had_errors = True
                    _emit_jsonl_failure(
                        line_number,
                        "line processing failed; details redacted",
                    )
                    continue
                result["line"] = line_number
                _emit(result)
                had_errors = had_errors or _removal_failed(result)
            return EXIT_PROCESSING if had_errors else EXIT_OK
        result = _remove_one(text, args, cfg)
        _emit(result["cleaned_text"] if args.format == "text" else result, args.format)
        return EXIT_PROCESSING if _removal_failed(result) else EXIT_OK
    except _CliUsageError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return EXIT_USAGE
    except ConsentRequiredError:
        operation = "mitigate" if args.command == "mitigate" else "apply"
        print(
            json.dumps(
                {"status": "failed", "error": f"{operation} requires explicit consent=true"}
            ),
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
    except PermissionError:
        print(
            json.dumps({"status": "failed", "error": "operation is not permitted"}), file=sys.stderr
        )
        return EXIT_BACKEND
    except (ValueError, OSError):
        print(json.dumps({"status": "failed", "error": "invalid input"}), file=sys.stderr)
        return EXIT_USAGE
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
