"""Reproducibility metadata and append-only checkpoints."""

from __future__ import annotations

import json
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any


def _version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def environment_manifest(args: Any) -> dict[str, Any]:
    """Capture configuration needed to interpret or reproduce a run."""
    packages = {
        name: _version(name)
        for name in (
            "dewatermark",
            "torch",
            "transformers",
            "sentence-transformers",
            "bert-score",
            "mauve-text",
        )
    }
    hardware: dict[str, Any] = {"platform": platform.platform(), "machine": platform.machine()}
    try:
        import torch

        hardware.update(
            cuda=torch.cuda.is_available(),
            mps=bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_available()),
        )
    except ImportError:
        hardware.update(cuda=False, mps=False)
    return {
        "schema_version": "1.0",
        "python": sys.version,
        "packages": packages,
        "hardware": hardware,
        "arguments": {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
        },
    }


def append_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def completed_lengths(path: Path) -> dict[int, dict[str, Any]]:
    completed: dict[int, dict[str, Any]] = {}
    if not path.exists():
        return completed
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
            if item.get("event") == "length.completed":
                completed[int(item["length"])] = item["results"]
        except (ValueError, TypeError, KeyError):
            continue
    return completed
