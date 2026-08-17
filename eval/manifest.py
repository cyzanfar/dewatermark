"""Content-addressed run manifests and append-only checkpoints.

The checkpoint format is intentionally JSONL so an interrupted experiment can
be inspected and recovered without special tooling.  Resume is permitted only
when the scientific inputs have the same content digest; output locations,
timestamps, and the ``--resume`` switch itself are not scientific inputs.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping

MANIFEST_SCHEMA_VERSION = "1.0"
CHECKPOINT_SCHEMA_VERSION = "2.0"
SCORE_TABLE_SCHEMA_VERSION = "1.0"

# These change where/how a run is recorded, not what is measured.
_NON_SCIENTIFIC_ARGUMENTS = {
    "checkpoint",
    "date",
    "include_text_artifacts",
    "json_output",
    "output",
    "resume",
}


class IncompatibleResumeError(RuntimeError):
    """A checkpoint belongs to a different scientific run."""


def _version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _json_value(value: Any) -> Any:
    """Return a deterministic, JSON-safe representation."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def canonical_json(value: Any) -> str:
    """Canonical serialization used for all content digests."""
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def json_safe(value: Any) -> Any:
    """Convert to standards-compliant JSON data (non-finite metrics become null)."""
    return _json_value(value)


def _tree_sha256(root: Path, *, suffixes: tuple[str, ...] | None = None) -> str:
    """Digest paths and bytes for a complete, deterministic source snapshot."""
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.name in {".DS_Store"}:
            continue
        if suffixes is not None and path.suffix not in suffixes:
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    except OSError:
        return None


def _git_source_state(root: Path) -> dict[str, Any]:
    """Read bounded local VCS identity without hooks, network, or error content."""
    environment = {
        "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }

    def call(*arguments: str) -> bytes | None:
        try:
            result = subprocess.run(
                ("git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *arguments),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode or len(result.stdout) > 1024 * 1024:
            return None
        return result.stdout

    commit_raw = call("rev-parse", "--verify", "HEAD")
    status_raw = call("status", "--porcelain=v1", "--untracked-files=no")
    commit = commit_raw.decode("ascii", "ignore").strip() if commit_raw else None
    if not commit or len(commit) != 40:
        commit = None
    return {
        "commit": commit,
        "tracked_dirty": bool(status_raw) if status_raw is not None else None,
        "tracked_status_sha256": hashlib.sha256(status_raw).hexdigest()
        if status_raw is not None
        else None,
    }


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
    arguments = {key: _json_value(value) for key, value in sorted(vars(args).items())}
    # Adapter commands can contain paths or accidentally supplied credentials.
    # Never publish them or a brute-forceable digest of them; the static public
    # sidecar plus executable/script digests carry scientific identity instead.
    for key in ("adapter", "cross_detector"):
        if key in arguments:
            values = arguments[key] if isinstance(arguments[key], list) else [arguments[key]]
            arguments[key] = [{"name": str(value).split("|", 1)[0]} for value in values]
    repository_root = Path(__file__).resolve().parent.parent
    source_root = repository_root / "src" / "dewatermark"
    unicode_policy = source_root / "unicode_policy.json"
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "python": sys.version,
        "python_version": platform.python_version(),
        "packages": packages,
        "harness_sha256": _tree_sha256(Path(__file__).resolve().parent, suffixes=(".py",)),
        "source_tree_sha256": _tree_sha256(source_root),
        "unicode_policy_sha256": _file_sha256(unicode_policy),
        "source_control": _git_source_state(repository_root),
        "hardware": hardware,
        "arguments": arguments,
    }


def scientific_identity(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Extract inputs that can change experimental conclusions."""
    arguments = {
        key: value
        for key, value in dict(manifest.get("arguments", {})).items()
        if key not in _NON_SCIENTIFIC_ARGUMENTS
    }
    return {
        "manifest_schema": manifest.get("schema_version"),
        "arguments": arguments,
        "packages": manifest.get("packages", {}),
        "python_version": manifest.get("python_version"),
        "harness_sha256": manifest.get("harness_sha256"),
        "source_tree_sha256": manifest.get("source_tree_sha256"),
        "unicode_policy_sha256": manifest.get("unicode_policy_sha256"),
        "source_control": manifest.get("source_control", {}),
        "prompt_sha256": manifest.get("prompt_sha256"),
        "scheme_manifests": manifest.get("scheme_manifests", {}),
        "detector_manifests": manifest.get("detector_manifests", {}),
        "dewatermark_config": manifest.get("dewatermark_config", {}),
        "runtime_backends": manifest.get("runtime_backends", {}),
        "resumability": manifest.get("resumability", {}),
    }


def run_identity(manifest: Mapping[str, Any]) -> str:
    """SHA-256 identity for all scientific inputs and implementation versions."""
    payload = canonical_json(scientific_identity(manifest)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _adapter_blockers(manifests: Any) -> list[str]:
    blockers: list[str] = []
    if not isinstance(manifests, Mapping):
        return blockers
    for name, value in sorted(manifests.items()):
        if not isinstance(value, Mapping):
            blockers.append(f"{name}: adapter manifest is unresolved")
            continue
        for message in value.get("reproducibility_blockers", []):
            blockers.append(f"{name}: {message}")
        if value.get("implementation", "").startswith("external-command") and not value.get(
            "reproducible", False
        ):
            blockers.append(f"{name}: external adapter identity is unresolved")
    return blockers


def resumability_assessment(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Explain whether interrupted scientific work can be safely combined."""
    blockers: list[str] = []
    arguments = manifest.get("arguments", {})
    if not isinstance(arguments, Mapping):
        blockers.append("scientific arguments are unresolved")
        arguments = {}
    statistical = not bool(arguments.get("skip_statistical", True))
    if statistical and not arguments.get("model_revision"):
        blockers.append("generator model revision is not pinned")
    if not manifest.get("source_tree_sha256"):
        blockers.append("dewatermark source tree digest is unresolved")
    if not manifest.get("harness_sha256"):
        blockers.append("evaluation harness digest is unresolved")
    if not manifest.get("unicode_policy_sha256"):
        blockers.append("Unicode policy digest is unresolved")
    blockers.extend(_adapter_blockers(manifest.get("scheme_manifests", {})))
    blockers.extend(_adapter_blockers(manifest.get("detector_manifests", {})))
    return {"resolved": not blockers, "blockers": sorted(set(blockers))}


def finalize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a copy carrying its content-addressed ``run_id``."""
    result = dict(manifest)
    result["resumability"] = resumability_assessment(result)
    result["run_id"] = run_identity(result)
    return result


def content_addressed_score_table(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a content-free per-sample score table with a stable digest."""
    forbidden = {"text", "prompt", "source_text", "candidate_text", "content"}

    def contains_text(value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(
                str(key).lower() in forbidden or contains_text(item) for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(contains_text(item) for item in value)
        return False

    safe_records = json_safe(records)
    for record in safe_records:
        if not isinstance(record, dict):
            raise ValueError("score-table records must be objects")
        if contains_text(record):
            raise ValueError("score-table records cannot contain source text")
    digest = hashlib.sha256(canonical_json(safe_records).encode("utf-8")).hexdigest()
    return {
        "schema_version": SCORE_TABLE_SCHEMA_VERSION,
        "sha256": digest,
        "records": safe_records,
    }


def append_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = json_safe({"checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION, **payload})
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def checkpoint_run_ids(path: Path) -> set[str]:
    """Return explicit or derivable run identities found in a checkpoint."""
    identities: set[str] = set()
    for item in _records(path):
        identity = item.get("run_id")
        if isinstance(identity, str):
            identities.add(identity)
        manifest = item.get("manifest")
        if isinstance(manifest, dict):
            identities.add(str(manifest.get("run_id") or run_identity(manifest)))
    return identities


def ensure_resume_compatible(path: Path, manifest: Mapping[str, Any]) -> str:
    """Refuse to combine a checkpoint with a scientifically different run."""
    resumability = manifest.get("resumability", {})
    if isinstance(resumability, Mapping) and resumability.get("resolved") is False:
        reasons = resumability.get("blockers", [])
        detail = "; ".join(str(value) for value in reasons[:3])
        raise IncompatibleResumeError(f"run is not safely resumable: {detail}")
    expected = str(manifest.get("run_id") or run_identity(manifest))
    existing = checkpoint_run_ids(path)
    if not existing:
        raise IncompatibleResumeError("checkpoint contains no run manifest; start a new checkpoint")
    if existing != {expected}:
        found = ", ".join(sorted(value[:12] for value in existing))
        raise IncompatibleResumeError(
            f"checkpoint run identity mismatch: expected {expected[:12]}, found {found}"
        )
    return expected


def completed_lengths(path: Path, run_id: str | None = None) -> dict[int, dict[str, Any]]:
    """Return completed length results, optionally restricted to one run."""
    completed: dict[int, dict[str, Any]] = {}
    for item in _records(path):
        if item.get("event") != "length.completed":
            continue
        # Version-1 checkpoints did not carry a run id. Preserve read
        # compatibility, but never use such records for a verified v2 resume.
        if run_id is not None and item.get("run_id") != run_id:
            continue
        try:
            completed[int(item["length"])] = item["results"]
        except (ValueError, TypeError, KeyError):
            continue
    return completed
