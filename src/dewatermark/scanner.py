"""Repository scanning, safe fixes, baselines, diff filtering, and SARIF output."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Collection, Iterable, Iterator, Mapping, Optional, Sequence

from .unicode import UNICODE_POLICY_VERSION, analyze, sanitize_with_edits

DEFAULT_EXTENSIONS = frozenset(
    ".c .cc .cfg .conf .cpp .css .csv .go .h .hpp .html .ini .java .js .json .jsx "
    ".kt .md .mdx .php .properties .py .rb .rs .rst .sh .sql .svg .toml .ts .tsx "
    ".txt .xml .yaml .yml".split()
)
SKIP_DIRS = frozenset(
    {
        ".git",
        ".gradle",
        ".hg",
        ".hypothesis",
        ".idea",
        ".intellijPlatform",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "vendor",
    }
)
# Context-dependent typography and bidi controls are useful forensic signals,
# but they are too ambiguous to fail a repository check by default. Callers can
# opt into them explicitly; the default is limited to actionable evidence.
DEFAULT_DISPOSITIONS = frozenset({"actionable"})
_VALID_DISPOSITIONS = frozenset({"actionable", "contextual", "informational"})
_PRIVATE_CONFIGURATION_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    }
)


def _public_configuration(value: object, *, key: str = "") -> object:
    """Project scanner policy without reflecting credentials or objects."""
    normalized = key.lower().replace("-", "_")
    if normalized in _PRIVATE_CONFIGURATION_KEYS or normalized.endswith(
        ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
    ):
        return "<redacted>"
    value_type = type(value)
    if value_type is dict and isinstance(value, dict):
        return {
            item_key: _public_configuration(item, key=item_key)
            for item_key, item in value.items()
            if type(item_key) is str
        }
    if value_type in (list, tuple) and isinstance(value, (list, tuple)):
        return [_public_configuration(item) for item in value]
    if value is None or value_type in (str, bool, int, float):
        return value
    return "<redacted>"


@dataclass(frozen=True, repr=False)
class ScanFinding:
    path: str
    line: int
    column: int
    category: str
    codepoint: str
    risk: str
    message: str
    disposition: str = "actionable"
    context: str = ""
    codepoint_offset: int = -1
    byte_offset: int = -1
    grapheme_index: int = -1
    fingerprint: str = ""
    baseline_state: str = "new"

    def __repr__(self) -> str:
        return "<dewatermark scan finding; path and context redacted>"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, repr=False)
class ScanEdit:
    """An accepted file edit, sufficient to audit or reconstruct changed codepoints."""

    path: str
    line: int
    column: int
    codepoint_offset: int
    byte_offset: int
    output_offset: int
    category: str
    action: str
    original: str
    replacement: str
    original_codepoints: tuple[str, ...]
    replacement_codepoints: tuple[str, ...]
    reason: str
    stage: str
    profile: str
    accepted: bool = True
    reversible: bool = True

    def __repr__(self) -> str:
        return "<dewatermark scan edit; path and content redacted>"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, repr=False)
class ScanReport:
    files_scanned: int
    findings: tuple[ScanFinding, ...]
    errors: tuple[str, ...] = ()
    edits: tuple[ScanEdit, ...] = ()
    fixed_files: tuple[str, ...] = ()
    configuration: Optional[Mapping[str, object]] = None

    def __repr__(self) -> str:
        return "<dewatermark scan report; paths and policy redacted>"

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
            "errors": list(self.errors),
            "edit_count": len(self.edits),
            "edits": [item.to_dict() for item in self.edits],
            "fixed_files": list(self.fixed_files),
            "unicode_policy_version": UNICODE_POLICY_VERSION,
            "configuration": _public_configuration(
                self.configuration if type(self.configuration) is dict else {}
            ),
        }


def _normalized_path_candidates(path: Path, root: Path) -> tuple[str, ...]:
    """Return stable path spellings used by scanner exclusion patterns."""
    values = {path.name, path.as_posix()}
    for base in (root, Path.cwd()):
        try:
            values.add(path.resolve().relative_to(base.resolve()).as_posix())
        except ValueError:
            pass
    return tuple(sorted(values))


def _normalize_exclude_pattern(raw_pattern: str) -> str:
    pattern = raw_pattern.strip().replace("\\", "/")
    return pattern[2:] if pattern.startswith("./") else pattern


def _is_excluded(path: Path, root: Path, patterns: Collection[str]) -> bool:
    candidates = _normalized_path_candidates(path, root)
    for raw_pattern in patterns:
        pattern = _normalize_exclude_pattern(raw_pattern)
        if not pattern:
            continue
        if any(
            fnmatch.fnmatchcase(candidate, pattern)
            or fnmatch.fnmatchcase(candidate, f"**/{pattern}")
            for candidate in candidates
        ):
            return True
    return False


def path_is_selected(
    path: str | Path,
    *,
    root: str | Path,
    exclude_patterns: Collection[str] = (),
    extensions: Collection[str] = DEFAULT_EXTENSIONS,
) -> bool:
    """Apply repository extension/exclusion policy to an in-memory file path."""
    candidate = Path(path)
    normalized_extensions = frozenset(
        value.lower() if value.startswith(".") else f".{value.lower()}" for value in extensions
    )
    return candidate.suffix.lower() in normalized_extensions and not _is_excluded(
        candidate, Path(root), exclude_patterns
    )


def _iter_files(
    paths: Sequence[Path],
    *,
    exclude_patterns: Collection[str] = (),
    extensions: Collection[str] = DEFAULT_EXTENSIONS,
    policy_root: Optional[Path] = None,
) -> Iterator[Path]:
    seen: set[Path] = set()
    for source in paths:
        root = policy_root or (source if source.is_dir() else source.parent)
        if source.is_file() and not source.is_symlink():
            candidates: Iterable[Path] = (
                () if _is_excluded(source, root, exclude_patterns) else (source,)
            )
        elif source.is_dir():
            candidates = (
                item
                for item in source.rglob("*")
                if item.is_file()
                and not item.is_symlink()
                and not any(part in SKIP_DIRS for part in item.parts)
                and item.suffix.lower() in extensions
                and not _is_excluded(item, root, exclude_patterns)
            )
        else:
            continue
        for item in candidates:
            resolved = item.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield item


def _location(text: str, position: int) -> tuple[int, int]:
    return text.count("\n", 0, position) + 1, position - text.rfind("\n", 0, position)


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _fingerprint(
    *, path: str, line: int, column: int, category: str, codepoint: str, text: str
) -> str:
    # Include a hash of line content rather than the content itself: baselines
    # remain useful without persisting secrets from scanned files.
    line_digest = hashlib.sha256(_line_text(text, line).encode("utf-8")).hexdigest()[:16]
    value = "\0".join((path.replace("\\", "/"), category, codepoint, str(column), line_digest))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _matches_suppression(finding: ScanFinding, suppressions: Collection[str]) -> bool:
    candidates = {
        finding.fingerprint,
        finding.codepoint,
        finding.category,
        finding.disposition,
        f"{finding.path}:{finding.line}",
        f"{finding.path}:{finding.line}:{finding.codepoint}",
        f"{finding.path}:{finding.line}:{finding.column}:{finding.codepoint}",
    }
    return any(
        token in candidates
        or any(fnmatch.fnmatchcase(candidate, token) for candidate in candidates)
        for token in suppressions
    )


def scan_text(
    text: str,
    path: str = "<stdin>",
    *,
    baseline: Optional[Collection[str]] = None,
    suppressions: Collection[str] = (),
    changed_lines: Optional[Collection[int]] = None,
    dispositions: Collection[str] = DEFAULT_DISPOSITIONS,
    new_only: bool = False,
) -> tuple[ScanFinding, ...]:
    """Return location-aware findings with optional baseline/diff filtering.

    Suppressions accept an exact fingerprint, codepoint, category, disposition,
    ``path:line[:column]:codepoint``, or a shell-style pattern matching one of
    those values.  Informational observations are available by passing all
    three dispositions explicitly.
    """
    if type(text) is not str:
        raise TypeError("scanner text must be a string")
    if isinstance(dispositions, str) or isinstance(suppressions, str) or isinstance(baseline, str):
        raise TypeError("scanner policies must be collections, not strings")
    if not dispositions or not set(dispositions) <= _VALID_DISPOSITIONS:
        raise ValueError("scanner dispositions must contain supported values")
    baseline_values = baseline or frozenset()
    findings: list[ScanFinding] = []
    for group in analyze(text)["unicode"]["findings"]:
        occurrence_by_position = {item["position"]: item for item in group.get("occurrences", ())}
        for position in group["positions"]:
            occurrence = occurrence_by_position.get(
                position,
                {
                    "disposition": group.get("disposition", "actionable"),
                    "context": "",
                    "byte_offset": len(text[:position].encode("utf-8")),
                    "grapheme_index": position,
                },
            )
            disposition = str(occurrence["disposition"])
            if disposition not in dispositions:
                continue
            line, column = _location(text, position)
            if changed_lines is not None and line not in changed_lines:
                continue
            fingerprint = _fingerprint(
                path=path,
                line=line,
                column=column,
                category=group["category"],
                codepoint=group["codepoint"],
                text=text,
            )
            item = ScanFinding(
                path=path,
                line=line,
                column=column,
                category=group["category"],
                codepoint=group["codepoint"],
                risk=group["risk"],
                message=group["explanation"],
                disposition=disposition,
                context=str(occurrence["context"]),
                codepoint_offset=position,
                byte_offset=int(occurrence["byte_offset"]),
                grapheme_index=int(occurrence["grapheme_index"]),
                fingerprint=fingerprint,
                baseline_state="existing" if fingerprint in baseline_values else "new",
            )
            if _matches_suppression(item, suppressions):
                continue
            if new_only and item.baseline_state != "new":
                continue
            findings.append(item)
    return tuple(findings)


def baseline_fingerprints(report: ScanReport) -> frozenset[str]:
    """Return a privacy-preserving baseline consumable by :func:`scan_paths`."""
    return frozenset(item.fingerprint for item in report.findings if item.fingerprint)


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines_from_unified_diff(diff: str) -> dict[str, frozenset[int]]:
    """Extract added/modified target lines from a git-style unified diff."""
    changed: dict[str, set[int]] = {}
    path: Optional[str] = None
    new_line = 0
    in_hunk = False
    for raw_line in diff.splitlines():
        if raw_line.startswith("+++ "):
            value = raw_line[4:].split("\t", 1)[0]
            path = value[2:] if value.startswith("b/") else value
            if path == "/dev/null":
                path = None
            in_hunk = False
            continue
        match = _HUNK.match(raw_line)
        if match:
            new_line = int(match.group(1))
            in_hunk = path is not None
            continue
        if not in_hunk or path is None or not raw_line:
            continue
        marker = raw_line[0]
        if marker == "+":
            changed.setdefault(path, set()).add(new_line)
            new_line += 1
        elif marker == "-":
            continue
        elif marker in {" ", "\\"}:
            if marker == " ":
                new_line += 1
        else:
            in_hunk = False
    return {key: frozenset(value) for key, value in changed.items()}


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    """Atomically replace one explicit file while preserving its permission bits."""
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, stat.S_IMODE(mode))
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _manifest_to_scan_edits(
    path: Path, text: str, profile: str, manifest: Sequence[dict]
) -> list[ScanEdit]:
    edits: list[ScanEdit] = []
    for item in manifest:
        position = int(item["position"])
        line, column = _location(text, min(position, len(text)))
        edits.append(
            ScanEdit(
                path=str(path),
                line=line,
                column=column,
                codepoint_offset=position,
                byte_offset=int(item["byte_offset"]),
                output_offset=int(item.get("output_position", position)),
                category=str(item["category"]),
                action=str(item["action"]),
                original=str(item["original"]),
                replacement=str(item["replacement"]),
                original_codepoints=tuple(item["original_codepoints"]),
                replacement_codepoints=tuple(item["replacement_codepoints"]),
                reason=str(item["reason"]),
                stage=str(item["stage"]),
                profile=profile,
                reversible=bool(item.get("reversible", True)),
            )
        )
    return edits


def _safe_scan_error(path: Path, exc: BaseException) -> str:
    """Identify a failed file without exposing its path or exception message."""
    digest = hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:16]
    if isinstance(exc, UnicodeError):
        reason = "invalid_utf8"
    elif isinstance(exc, OSError):
        reason = "io_error"
    elif isinstance(exc, ValueError):
        reason = "validation_error"
    else:
        reason = "processing_error"
    return f"file_sha256:{digest}: {reason}"


def scan_paths(
    paths: Sequence[str | Path],
    *,
    max_file_bytes: int = 2_000_000,
    fix: bool = False,
    profile: str = "safe",
    baseline: Optional[Collection[str]] = None,
    suppressions: Collection[str] = (),
    changed_lines: Optional[Mapping[str, Collection[int]]] = None,
    dispositions: Collection[str] = DEFAULT_DISPOSITIONS,
    new_only: bool = False,
    exclude_patterns: Collection[str] = (),
    extensions: Collection[str] = DEFAULT_EXTENSIONS,
    policy_root: Optional[str | Path] = None,
) -> ScanReport:
    """Scan text files recursively and optionally apply atomic, audited fixes.

    Files are decoded and encoded directly as UTF-8 bytes, preserving a UTF-8
    BOM and all original CR/LF sequences.  Conservative fixes disable implicit
    NFC normalization so every byte change corresponds to a reported edit.
    """
    if isinstance(paths, (str, Path)):
        raise TypeError("scanner paths must be a sequence")
    if any(
        isinstance(value, str)
        for value in (extensions, dispositions, exclude_patterns, suppressions, baseline)
    ):
        raise TypeError("scanner policies must be collections, not strings")
    if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 1_000_000_000:
        raise ValueError("max_file_bytes must be between 1 and 1000000000")
    if type(fix) is not bool or type(new_only) is not bool:
        raise TypeError("scanner fix and new_only policies must be boolean")
    if profile not in {"safe", "aggressive"}:
        raise ValueError("scanner profile must be safe or aggressive")
    if not dispositions or not set(dispositions) <= _VALID_DISPOSITIONS:
        raise ValueError("scanner dispositions must contain supported values")
    if not extensions or any(type(value) is not str or not value.strip() for value in extensions):
        raise ValueError("scanner extensions must contain non-empty strings")
    if any(type(value) is not str for value in (*exclude_patterns, *suppressions)):
        raise TypeError("scanner exclude and suppression values must be strings")
    findings: list[ScanFinding] = []
    errors: list[str] = []
    edits: list[ScanEdit] = []
    fixed_files: list[str] = []
    count = 0
    normalized_extensions = frozenset(
        value.lower() if value.startswith(".") else f".{value.lower()}" for value in extensions
    )
    for path in _iter_files(
        [Path(value) for value in paths],
        exclude_patterns=exclude_patterns,
        extensions=normalized_extensions,
        policy_root=Path(policy_root) if policy_root is not None else None,
    ):
        try:
            if path.is_symlink():
                continue
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if metadata.st_size > max_file_bytes:
                continue
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                continue
            text = raw.decode("utf-8")
            count += 1
            path_changed_lines: Optional[Collection[int]] = None
            if changed_lines is not None:
                normalized = str(path).replace("\\", "/")
                path_changed_lines = changed_lines.get(normalized)
                if path_changed_lines is None:
                    try:
                        relative = str(path.resolve().relative_to(Path.cwd().resolve())).replace(
                            "\\", "/"
                        )
                    except ValueError:
                        relative = normalized
                    path_changed_lines = changed_lines.get(relative, frozenset())
            findings.extend(
                scan_text(
                    text,
                    str(path),
                    baseline=baseline,
                    suppressions=suppressions,
                    changed_lines=path_changed_lines,
                    dispositions=dispositions,
                    new_only=new_only,
                )
            )
            if fix:
                cleaned, _, manifest = sanitize_with_edits(
                    text,
                    profile=profile,  # type: ignore[arg-type]
                    normalize=profile != "safe",
                )
                if cleaned != text:
                    accepted = _manifest_to_scan_edits(path, text, profile, manifest)
                    if not accepted:
                        raise RuntimeError(
                            "sanitizer changed text without an accepted edit manifest"
                        )
                    _atomic_write(path, cleaned.encode("utf-8"), metadata.st_mode)
                    edits.extend(accepted)
                    fixed_files.append(str(path))
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            errors.append(_safe_scan_error(path, exc))
    return ScanReport(
        count,
        tuple(findings),
        tuple(errors),
        edits=tuple(edits),
        fixed_files=tuple(fixed_files),
        configuration={
            "max_file_bytes": max_file_bytes,
            "fix": fix,
            "profile": profile,
            "new_only": new_only,
            "extensions": sorted(normalized_extensions),
            "exclude_patterns": sorted(
                _normalize_exclude_pattern(item) for item in exclude_patterns
            ),
            "dispositions": sorted(dispositions),
            "suppression_count": len(suppressions),
            "baseline_count": len(baseline or ()),
            "diff_filter": changed_lines is not None,
        },
    )


def to_sarif(report: ScanReport) -> dict:
    """Convert a scan report into SARIF 2.1.0 for GitHub code scanning."""
    rules: dict[str, dict] = {}
    results = []
    for finding in report.findings:
        rule_id = f"dewatermark/{finding.category}"
        rules[rule_id] = {
            "id": rule_id,
            "shortDescription": {"text": f"Suspicious Unicode: {finding.category}"},
            "helpUri": "https://github.com/cyzanfar/text-watermark-remover#repository-scanning",
            "defaultConfiguration": {"level": "warning"},
            "properties": {"unicodePolicyVersion": UNICODE_POLICY_VERSION},
        }
        level = "note"
        if finding.disposition == "actionable":
            level = "error" if finding.risk == "high" else "warning"
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "baselineState": "unchanged" if finding.baseline_state == "existing" else "new",
                "message": {"text": f"{finding.message} ({finding.codepoint}; {finding.context})"},
                "partialFingerprints": {"unicodeFinding/v2": finding.fingerprint},
                "properties": {
                    "disposition": finding.disposition,
                    "byteOffset": finding.byte_offset,
                    "graphemeIndex": finding.grapheme_index,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                            },
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dewatermark",
                        "informationUri": "https://github.com/cyzanfar/text-watermark-remover",
                        "semanticVersion": UNICODE_POLICY_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
