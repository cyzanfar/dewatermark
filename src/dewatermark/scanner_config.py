"""Validated, side-effect-free repository scanner configuration."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

try:  # pragma: no cover - branch depends on the Python runtime
    import tomllib
except ImportError:  # pragma: no cover - Python 3.9/3.10
    import tomli as tomllib

from .scanner import DEFAULT_DISPOSITIONS, DEFAULT_EXTENSIONS

CONFIG_FILENAME = ".dewatermark.toml"
MAX_CONFIG_BYTES = 1_000_000
_ALLOWED_KEYS = {
    "exclude",
    "extensions",
    "max_file_bytes",
    "dispositions",
    "suppressions",
}
_DISPOSITIONS = frozenset({"actionable", "contextual", "informational"})


@dataclass(frozen=True, repr=False)
class ScannerConfig:
    """Resolved scanner policy before command-line overrides are applied."""

    exclude: tuple[str, ...] = ()
    extensions: tuple[str, ...] = tuple(sorted(DEFAULT_EXTENSIONS))
    max_file_bytes: int = 2_000_000
    dispositions: tuple[str, ...] = tuple(sorted(DEFAULT_DISPOSITIONS))
    suppressions: tuple[str, ...] = ()
    source: Optional[str] = None

    def __repr__(self) -> str:
        return "<dewatermark scanner configuration; policy source redacted>"

    def to_dict(self) -> dict[str, Any]:
        def public_strings(items: object) -> list[str]:
            if type(items) is not tuple:
                return []
            return [item if type(item) is str else "<redacted>" for item in items]

        value: dict[str, Any] = {
            "exclude": public_strings(self.exclude),
            "extensions": public_strings(self.extensions),
            "max_file_bytes": self.max_file_bytes if type(self.max_file_bytes) is int else 0,
            "dispositions": public_strings(self.dispositions),
            "suppressions": public_strings(self.suppressions),
            "source": None,
        }
        if type(self.source) is str:
            value["source"] = (
                "sha256:" + hashlib.sha256(self.source.encode("utf-8", "replace")).hexdigest()
            )
        elif self.source is not None:
            value["source"] = "<redacted>"
        return value


def _string_tuple(value: Any, name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(type(item) is str for item in value):
        raise ValueError(f"scanner {name} must be an array of strings")
    normalized = tuple(item.strip() for item in value)
    if any(not item for item in normalized) or (not allow_empty and not normalized):
        raise ValueError(f"scanner {name} contains an invalid value")
    return normalized


def _scan_table(payload: Mapping[str, Any], *, pyproject: bool) -> Mapping[str, Any]:
    value: Any = payload
    if pyproject:
        value = payload.get("tool", {})
        value = value.get("dewatermark", {}) if isinstance(value, Mapping) else {}
    if isinstance(value, Mapping) and "scan" in value:
        value = value["scan"]
    if not isinstance(value, Mapping):
        raise ValueError("scanner configuration must be a TOML table")
    return value


def load_scanner_config(path: str | Path) -> ScannerConfig:
    """Load one explicit TOML file without importing plugins or touching the network."""
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("scanner configuration must be a regular file")
    if source.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("scanner configuration exceeds the size limit")
    with source.open("rb") as handle:
        raw = handle.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("scanner configuration exceeds the size limit")
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise ValueError("scanner configuration is not valid UTF-8 TOML") from None
    table = _scan_table(payload, pyproject=source.name == "pyproject.toml")
    unknown = set(table) - _ALLOWED_KEYS
    if unknown:
        raise ValueError("scanner configuration contains unsupported keys")

    exclude = _string_tuple(table.get("exclude", []), "exclude")
    suppressions = _string_tuple(table.get("suppressions", []), "suppressions")
    extensions = _string_tuple(
        table.get("extensions", sorted(DEFAULT_EXTENSIONS)), "extensions", allow_empty=False
    )
    extensions = tuple(
        item.lower() if item.startswith(".") else f".{item.lower()}" for item in extensions
    )
    dispositions = _string_tuple(
        table.get("dispositions", sorted(DEFAULT_DISPOSITIONS)),
        "dispositions",
        allow_empty=False,
    )
    if not set(dispositions) <= _DISPOSITIONS:
        raise ValueError("scanner dispositions contain an unsupported value")
    max_file_bytes = table.get("max_file_bytes", 2_000_000)
    if (
        isinstance(max_file_bytes, bool)
        or not isinstance(max_file_bytes, int)
        or not 1 <= max_file_bytes <= 1_000_000_000
    ):
        raise ValueError("scanner max_file_bytes must be between 1 and 1000000000")
    return ScannerConfig(
        exclude=exclude,
        extensions=extensions,
        max_file_bytes=max_file_bytes,
        dispositions=dispositions,
        suppressions=suppressions,
        source=str(source),
    )


def find_scanner_config(start: str | Path = ".") -> Optional[Path]:
    """Find the nearest scanner config or pyproject section up to a VCS root."""
    current = Path(start).resolve()
    if current.is_file():
        current = current.parent
    while True:
        explicit = current / CONFIG_FILENAME
        if explicit.is_file() and not explicit.is_symlink():
            return explicit
        pyproject = current / "pyproject.toml"
        if pyproject.is_file() and not pyproject.is_symlink():
            try:
                with pyproject.open("rb") as handle:
                    raw = handle.read(MAX_CONFIG_BYTES + 1)
                if len(raw) > MAX_CONFIG_BYTES:
                    raise ValueError("pyproject exceeds scanner discovery bound")
                payload = tomllib.loads(raw.decode("utf-8"))
                tool = payload.get("tool", {})
                dewatermark = tool.get("dewatermark", {}) if isinstance(tool, Mapping) else {}
                if isinstance(dewatermark, Mapping) and "scan" in dewatermark:
                    return pyproject
            except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
                # Explicit loading will report malformed files. Discovery merely
                # decides whether a valid scanner table is present.
                pass
        parent = current.parent
        if (current / ".git").exists() or parent == current:
            return None
        current = parent


def resolve_scanner_config(
    path: str | Path | None = None,
    *,
    start: str | Path = ".",
    discover: bool = True,
) -> ScannerConfig:
    """Resolve an explicit or nearest scanner policy, otherwise return defaults."""
    selected = (
        Path(path) if path is not None else (find_scanner_config(start) if discover else None)
    )
    return load_scanner_config(selected) if selected is not None else ScannerConfig()


__all__ = [
    "CONFIG_FILENAME",
    "ScannerConfig",
    "find_scanner_config",
    "load_scanner_config",
    "resolve_scanner_config",
]
