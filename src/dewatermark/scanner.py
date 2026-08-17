"""Repository scanning and SARIF output for Unicode text watermarks."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .unicode import analyze, sanitize

DEFAULT_EXTENSIONS = frozenset(
    ".c .cc .cfg .conf .cpp .css .csv .go .h .hpp .html .ini .java .js .json .jsx "
    ".kt .md .mdx .php .properties .py .rb .rs .rst .sh .sql .svg .toml .ts .tsx "
    ".txt .xml .yaml .yml".split()
)
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
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


@dataclass(frozen=True)
class ScanFinding:
    path: str
    line: int
    column: int
    category: str
    codepoint: str
    risk: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    files_scanned: int
    findings: tuple[ScanFinding, ...]
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
            "errors": list(self.errors),
        }


def _iter_files(paths: Sequence[Path]) -> Iterator[Path]:
    seen: set[Path] = set()
    for source in paths:
        if source.is_file():
            candidates: Iterable[Path] = (source,)
        elif source.is_dir():
            candidates = (
                item
                for item in source.rglob("*")
                if item.is_file()
                and not item.is_symlink()
                and not any(part in SKIP_DIRS for part in item.parts)
                and item.suffix.lower() in DEFAULT_EXTENSIONS
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


def scan_text(text: str, path: str = "<stdin>") -> tuple[ScanFinding, ...]:
    """Return one location-aware finding for every suspicious code point."""
    findings: list[ScanFinding] = []
    for group in analyze(text)["unicode"]["findings"]:
        for position in group["positions"]:
            line, column = _location(text, position)
            findings.append(
                ScanFinding(
                    path=path,
                    line=line,
                    column=column,
                    category=group["category"],
                    codepoint=group["codepoint"],
                    risk=group["risk"],
                    message=group["explanation"],
                )
            )
    return tuple(findings)


def scan_paths(
    paths: Sequence[str | Path],
    *,
    max_file_bytes: int = 2_000_000,
    fix: bool = False,
    profile: str = "safe",
) -> ScanReport:
    """Scan text-like files recursively; optionally rewrite files explicitly."""
    findings: list[ScanFinding] = []
    errors: list[str] = []
    count = 0
    for path in _iter_files([Path(value) for value in paths]):
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8")
            count += 1
            findings.extend(scan_text(text, str(path)))
            if fix:
                cleaned, _ = sanitize(text, profile=profile)  # type: ignore[arg-type]
                if cleaned != text:
                    path.write_text(cleaned, encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path}: {exc}")
    return ScanReport(count, tuple(findings), tuple(errors))


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
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning" if finding.risk != "high" else "error",
                "message": {"text": f"{finding.message} ({finding.codepoint})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line, "startColumn": finding.column},
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
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
