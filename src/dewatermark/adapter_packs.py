"""Packaged, pinned external-detector integration templates."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

AdapterPackName = Literal["kgw", "synthid", "unigram"]
_PACK_FILES: dict[AdapterPackName, tuple[str, ...]] = {
    "kgw": (
        "README.md",
        "adapter.py",
        "adapter-config.json",
        "capability.json",
        "conformance.py",
        "fixture-cases.json",
        "build_natural_profile.py",
        "green-transitions-v1.json",
        "natural-adapter-config.json",
        "natural-capability.json",
        "natural-conformance-record.json",
        "natural-fixture-cases.json",
        "natural-profile-material.json",
        "natural-threshold-evidence.json",
        "natural-tokenizer.json",
        "natural_adapter.py",
        "natural_conformance.py",
        "operator_adapter.py",
        "seal_operator.py",
    ),
    "synthid": (
        "README.md",
        "adapter-manifest.template.json",
        "conformance.py",
        "fixture-cases.json",
        "operator_adapter.py",
        "seal_operator.py",
        "threshold-evidence.template.json",
        "upstream-conformance-record.json",
        "upstream_conformance.py",
    ),
    "unigram": (
        "README.md",
        "build_natural_profile.py",
        "green-mask-v1.json",
        "natural-adapter-config.json",
        "natural-capability.json",
        "natural-conformance-record.json",
        "natural-fixture-cases.json",
        "natural-profile-material.json",
        "natural-threshold-evidence.json",
        "natural-tokenizer.json",
        "natural_adapter.py",
        "natural_conformance.py",
        "operator_adapter.py",
        "seal_operator.py",
    ),
}
_MANIFEST_FILES: dict[AdapterPackName, str] = {
    "kgw": "natural-capability.json",
    "synthid": "adapter-manifest.template.json",
    "unigram": "natural-capability.json",
}


def _validate_name(name: str) -> AdapterPackName:
    if name not in _PACK_FILES:
        raise ValueError("unknown adapter pack; choose 'kgw', 'synthid', or 'unigram'")
    return name


def _read_bytes(name: AdapterPackName, filename: str) -> bytes:
    packaged = files("dewatermark").joinpath("data").joinpath("adapters").joinpath(name)
    try:
        return packaged.joinpath(filename).read_bytes()
    except FileNotFoundError:
        source = Path(__file__).resolve().parents[2] / "adapters" / name / filename
        return source.read_bytes()


def list_adapter_packs() -> tuple[dict[str, Any], ...]:
    """Return static pack status without executing or importing adapter code."""
    result = []
    for name in sorted(_PACK_FILES):
        manifest = adapter_pack_manifest(name)
        result.append(
            {
                "name": name,
                "files": list(_PACK_FILES[name]),
                "status": (
                    manifest.get("status") or manifest.get("metadata", {}).get("status", "unknown")
                ),
                "calibrated": bool(manifest.get("calibrated", False)),
                "production_detection": bool(
                    manifest.get("production_detection")
                    or manifest.get("metadata", {}).get("production_detection", False)
                ),
            }
        )
    return tuple(result)


def adapter_pack_manifest(name: str) -> dict[str, Any]:
    """Read one bounded checked-in manifest as a JSON object."""
    selected = _validate_name(name)
    payload = _read_bytes(selected, _MANIFEST_FILES[selected])
    if len(payload) > 256 * 1024:
        raise RuntimeError("adapter pack manifest exceeds its source bound")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise RuntimeError("adapter pack manifest is invalid") from None
    if not isinstance(value, dict):
        raise RuntimeError("adapter pack manifest is not a JSON object")
    return value


def materialize_adapter_pack(name: str, destination: Path | str) -> tuple[Path, ...]:
    """Copy a pack into a new directory, refusing every overwrite."""
    selected = _validate_name(name)
    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise FileExistsError("adapter pack destination already exists")
    target.mkdir(parents=True, exist_ok=False)
    created: list[Path] = []
    try:
        for filename in _PACK_FILES[selected]:
            path = target / filename
            path.write_bytes(_read_bytes(selected, filename))
            created.append(path)
    except BaseException:
        # Keep a partial directory visible for recovery/debugging. Silent
        # recursive deletion would be surprising and potentially destructive.
        raise
    return tuple(created)


__all__ = [
    "AdapterPackName",
    "adapter_pack_manifest",
    "list_adapter_packs",
    "materialize_adapter_pack",
]
