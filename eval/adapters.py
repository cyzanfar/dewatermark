"""Fail-closed adapters for independent/official watermark implementations.

The executable protocol is deliberately small: one JSON object on stdin and
one JSON object on stdout, with no shell involved.  Scientific identity comes
from a bounded *static sidecar*; capability discovery never executes adapter
code.  Runtime capability responses are treated as an additional consistency
check, never as authority to upgrade an adapter to independent.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from dewatermark.bounded_process import BoundedProcessFailure, run_bounded_process
from dewatermark.command_safety import (
    secret_file_argument_indexes,
    validate_public_command,
    validate_public_json,
)

try:
    from .manifest import StrictJSONError, strict_json_loads
    from .public_codes import REPRODUCIBILITY_BLOCKER_CODES
except ImportError:  # direct-script compatibility
    from manifest import StrictJSONError, strict_json_loads  # type: ignore
    from public_codes import REPRODUCIBILITY_BLOCKER_CODES  # type: ignore

PROTOCOL_VERSION = "1.0"
SIDECAR_SCHEMA_VERSION = "1.0"
MAX_SIDECAR_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
_MAX_CAPTURE_BYTES = 16 * 1024 * 1024
_ADAPTER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNRESOLVED = {"", "unknown", "unresolved", "unspecified", "latest", "none", "null"}
_SCRIPT_SUFFIXES_BY_INTERPRETER = {
    "bash": frozenset({".bash", ".sh"}),
    "bun": frozenset({".cjs", ".js", ".mjs", ".ts"}),
    "dash": frozenset({".sh"}),
    "deno": frozenset({".js", ".mjs", ".ts"}),
    "ksh": frozenset({".ksh", ".sh"}),
    "lua": frozenset({".lua"}),
    "node": frozenset({".cjs", ".js", ".mjs"}),
    "nodejs": frozenset({".cjs", ".js", ".mjs"}),
    "perl": frozenset({".pl"}),
    "php": frozenset({".php"}),
    "ruby": frozenset({".rb"}),
    "sh": frozenset({".sh"}),
    "zsh": frozenset({".sh", ".zsh"}),
}
_PUBLIC_OPTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PYTHON_INTERPRETER = re.compile(r"^(?:pythonw?|pypy)(?:\d+(?:\.\d+)*)?(?:t)?$")
_PYTHON_NO_VALUE_OPTIONS = re.compile(r"^-[bBdEiIOPqRsSuvx]+$")


def _argument_name(value: str, *, windows: bool | None = None) -> str | None:
    """Return a syntactic option name, never a positional path."""
    if windows is None:
        windows = os.name == "nt"
    if value.startswith("--") and value != "--":
        raw = value[2:].split("=", 1)[0]
    elif value.startswith("-") and value != "-":
        raw = value[1:].split("=", 1)[0]
    elif windows and value.startswith("/") and value != "/":
        raw = re.split(r"[=:]", value[1:], maxsplit=1)[0]
    else:
        return None
    if not _PUBLIC_OPTION_NAME.fullmatch(raw):
        return None
    return raw.lower().replace("-", "_")


def _command_basename(value: str) -> str:
    """Extract an executable basename for either native path convention."""
    name = re.split(r"[/\\]", value)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _interpreter_script_suffixes(executable: str) -> frozenset[str] | None:
    name = _command_basename(executable)
    if _PYTHON_INTERPRETER.fullmatch(name):
        return frozenset({".py", ".pyw", ".pyz"})
    return _SCRIPT_SUFFIXES_BY_INTERPRETER.get(name)


def _python_script_argument_index(command: tuple[str, ...]) -> int | None:
    index = 1
    while index < len(command):
        argument = command[index]
        if argument == "--":
            index += 1
            break
        if _PYTHON_NO_VALUE_OPTIONS.fullmatch(argument):
            index += 1
            continue
        if argument.startswith("-"):
            return None
        break
    if index >= len(command):
        return None
    return index


def _classify_code_argument_indexes(
    command: tuple[str, ...],
) -> tuple[frozenset[int], bool]:
    """Classify argv positions whose bytes form the launched implementation.

    Position zero is always the executable. Known interpreters require one
    unambiguous suffix-matched script. Python's no-value isolation/runtime
    flags are parsed from a closed allowlist; code strings, modules, flags with
    values, and unknown options deliberately remain unresolved. Other
    file-valued arguments are configuration or data and stay private.
    """
    indexes = {0}
    interpreter = _command_basename(command[0])
    suffixes = _interpreter_script_suffixes(command[0])
    if suffixes is None:
        return frozenset(indexes), True
    if _PYTHON_INTERPRETER.fullmatch(interpreter):
        script_index = _python_script_argument_index(command)
    else:
        script_index = 1 if len(command) > 1 and not command[1].startswith("-") else None
    if script_index is None or Path(command[script_index]).suffix.lower() not in suffixes:
        return frozenset(indexes), False
    indexes.add(script_index)
    return frozenset(indexes), True


def _split_command(command: str, *, windows: Optional[bool] = None) -> tuple[str, ...]:
    """Split an adapter command without corrupting Windows path separators."""
    if windows is None:
        windows = os.name == "nt"
    argv = shlex.split(command, posix=not windows)
    if windows:
        argv = [
            value[1:-1]
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}
            else value
            for value in argv
        ]
    return validate_public_command(tuple(argv))


class AdapterContractError(RuntimeError):
    """External adapter violated the JSON protocol."""


def _run_bounded_command(
    command: tuple[str, ...],
    payload: bytes,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    adapter_name: str,
    checkpoint: Callable[[], None] | None = None,
) -> bytes:
    """Run argv through the shared process-tree and output boundary."""
    try:
        result = run_bounded_process(
            command,
            payload,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            environment=_scrubbed_environment(),
            checkpoint=checkpoint,
        )
    except BoundedProcessFailure as exc:
        if exc.kind == "launch_failed":
            message = f"adapter {adapter_name} could not be launched"
        elif exc.kind == "timed_out":
            message = f"adapter {adapter_name} timed out; process output was redacted"
        elif exc.kind == "output_limit":
            raise AdapterContractError(
                f"adapter {adapter_name} exceeded its output limit; process output was redacted"
            ) from None
        elif exc.kind == "nonzero_exit":
            message = (
                f"adapter {adapter_name} exited with status {exc.returncode}; "
                "process output was redacted"
            )
        else:
            message = f"adapter {adapter_name} process cleanup failed"
        raise RuntimeError(message) from None
    return result.stdout


def _public_mapping(value: Any) -> Any:
    """Remove credential-like fields before persisting adapter metadata."""
    if type(value) is dict:

        def safe_key(key: object) -> bool:
            normalized = str(key).lower().replace("-", "_")
            forbidden = {
                "api_key",
                "authorization",
                "body",
                "candidate_text",
                "content",
                "cookie",
                "key_slot",
                "password",
                "private_key",
                "prompt",
                "response",
                "secret",
                "source_text",
                "text",
                "access_token",
                "auth_token",
                "refresh_token",
            }
            return normalized not in forbidden and not normalized.endswith(
                ("_api_key", "_password", "_private_key", "_secret", "_token")
            )

        return {
            key: _public_mapping(value[key])
            for key in sorted(item_key for item_key in value if type(item_key) is str)
            if safe_key(key)
        }
    if type(value) in (list, tuple):
        return [_public_mapping(item) for item in value]
    if type(value) in (str, int, float, bool) or value is None:
        return value
    return "<redacted>"


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _public_mapping(value), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _scrubbed_environment() -> dict[str, str]:
    """Return a minimal child environment without ambient credentials."""
    allowed = {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.setdefault("PATH", os.defpath)
    environment.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _is_revision(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _UNRESOLVED


def _discover_sidecar(command: tuple[str, ...]) -> Path | None:
    """Find a conventional adjacent manifest without importing or executing code."""
    candidates: list[Path] = []
    code_indexes, _resolved = _classify_code_argument_indexes(command)
    for index in sorted(code_indexes):
        argument = command[index]
        path = Path(argument).expanduser()
        if not path.is_file():
            continue
        candidates.extend(
            (
                Path(f"{path}.manifest.json"),
                path.with_suffix(".manifest.json"),
                path.parent / "adapter-manifest.json",
            )
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _load_sidecar(path: Path) -> tuple[dict[str, Any], str]:
    try:
        if path.stat().st_size > MAX_SIDECAR_BYTES:
            raise AdapterContractError("adapter sidecar exceeds the size limit")
        with path.open("rb") as handle:
            raw = handle.read(MAX_SIDECAR_BYTES + 1)
        if len(raw) > MAX_SIDECAR_BYTES:
            raise AdapterContractError("adapter sidecar exceeds the size limit")
        value = strict_json_loads(raw)
    except AdapterContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, StrictJSONError):
        raise AdapterContractError("adapter sidecar could not be read as bounded JSON") from None
    if not isinstance(value, dict):
        raise AdapterContractError("adapter sidecar must contain one JSON object")
    try:
        public_value = validate_public_json(value, source="adapter sidecar")
    except (TypeError, ValueError):
        raise AdapterContractError("adapter sidecar contains non-public metadata") from None
    if type(public_value) is not dict:
        raise AdapterContractError("adapter sidecar must contain one JSON object")
    return public_value, hashlib.sha256(raw).hexdigest()


@dataclass(repr=False)
class CommandScheme:
    name: str
    command: tuple[str, ...]
    family: str
    source: str
    timeout: int = 600
    allow_network: bool = False
    allow_model_download: bool = False
    sidecar_path: Path | None = None
    max_request_bytes: int = MAX_REQUEST_BYTES
    max_response_bytes: int = MAX_RESPONSE_BYTES
    max_stderr_bytes: int = MAX_STDERR_BYTES
    _capabilities: Optional[dict[str, Any]] = None
    _static_manifest: Optional[dict[str, Any]] = None
    _sidecar_sha256: str | None = None
    _last_generation: dict[str, Any] = field(default_factory=dict)
    _last_detection: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            type(self.command) is not tuple
            or not self.command
            or len(self.command) > 128
            or any(
                type(argument) is not str
                or not argument
                or len(argument) > 32_768
                or "\0" in argument
                for argument in self.command
            )
        ):
            raise ValueError("adapter argv must be a bounded non-empty string array")
        validate_public_command(self.command)
        if type(self.name) is not str or not _ADAPTER_NAME.fullmatch(self.name):
            raise ValueError("adapter name must be a registered identifier")
        try:
            validate_public_json({"name": self.name}, source="adapter name")
        except (TypeError, ValueError):
            raise ValueError("adapter name must be a public registered identifier") from None
        if (
            type(self.family) is not str
            or type(self.source) is not str
            or not self.family
            or not self.source
            or len(self.family) > 256
            or len(self.source) > 4096
        ):
            raise ValueError("adapter family and source must be bounded public metadata")
        try:
            validate_public_json(
                {"family": self.family, "source": self.source}, source="adapter identity"
            )
        except (TypeError, ValueError):
            raise ValueError("adapter family and source must be public metadata") from None
        if self.sidecar_path is None:
            self.sidecar_path = _discover_sidecar(self.command)

    def __repr__(self) -> str:
        return "<evaluation command adapter; representation redacted>"

    @classmethod
    def from_spec(cls, spec: str) -> "CommandScheme":
        """Parse an adapter spec without invoking a shell.

        Preferred form is ``NAME|FAMILY|SOURCE|SIDECAR|COMMAND``.  The legacy
        four-field form remains executable, but is never classified as an
        independent implementation unless an adjacent sidecar is discovered.
        """
        parts = spec.split("|", 4)
        if len(parts) == 4:
            name, family, source, command = parts
            sidecar = None
        elif len(parts) == 5:
            name, family, source, sidecar_value, command = parts
            sidecar = Path(sidecar_value).expanduser() if sidecar_value else None
        else:
            raise ValueError(
                "adapter must be NAME|FAMILY|SOURCE|COMMAND or NAME|FAMILY|SOURCE|SIDECAR|COMMAND"
            ) from None
        if not _ADAPTER_NAME.fullmatch(name):
            raise ValueError("adapter name must be a registered identifier")
        if not family or not source or any(character in family + source for character in "\r\n"):
            raise ValueError("adapter family and source must be non-empty single-line values")
        argv = _split_command(command)
        if not argv:
            raise ValueError("adapter command cannot be empty")
        return cls(name=name, family=family, source=source, command=argv, sidecar_path=sidecar)

    def _call(
        self,
        payload: dict[str, Any],
        *,
        checkpoint: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "protocol_version": PROTOCOL_VERSION,
            "policy": {
                "allow_network": self.allow_network,
                "allow_model_download": self.allow_model_download,
            },
            **payload,
        }
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if (
            isinstance(self.max_request_bytes, bool)
            or not isinstance(self.max_request_bytes, int)
            or not 1 <= self.max_request_bytes <= _MAX_CAPTURE_BYTES
        ):
            raise AdapterContractError(f"adapter {self.name} request limit is invalid")
        for limit_name, limit in (
            ("response", self.max_response_bytes),
            ("stderr", self.max_stderr_bytes),
        ):
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 1 <= limit <= _MAX_CAPTURE_BYTES
            ):
                raise AdapterContractError(
                    f"adapter {self.name} {limit_name} limit is invalid"
                ) from None
        if len(encoded) > self.max_request_bytes:
            raise AdapterContractError(f"adapter {self.name} request exceeds the size limit")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(float(self.timeout))
            or not 0 < self.timeout <= 3600
        ):
            raise AdapterContractError(f"adapter {self.name} timeout must be between 0 and 3600s")
        stdout = _run_bounded_command(
            self.command,
            encoded,
            timeout_seconds=float(self.timeout),
            max_stdout_bytes=self.max_response_bytes,
            max_stderr_bytes=self.max_stderr_bytes,
            adapter_name=self.name,
            checkpoint=checkpoint,
        )
        try:
            result = strict_json_loads(stdout)
        except (UnicodeError, json.JSONDecodeError, StrictJSONError):
            raise AdapterContractError(f"adapter {self.name} returned invalid JSON") from None
        if not isinstance(result, dict):
            raise AdapterContractError(f"adapter {self.name} must return a JSON object")
        response_version = result.get("protocol_version", PROTOCOL_VERSION)
        if str(response_version).split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise AdapterContractError(
                f"adapter {self.name} uses an incompatible protocol major"
            ) from None
        return result

    def _legacy_manifest(self) -> dict[str, Any]:
        return {
            "schema_version": SIDECAR_SCHEMA_VERSION,
            "id": self.name,
            "family": self.family,
            "source": self.source,
            "implementation": "external-command-unresolved",
            "implementation_version": "unresolved",
            "independent_requested": False,
            "independent": False,
            "vendor_validated": False,
            "score_direction": "higher",
            "minimum_effective_tokens": 0,
            "minimum_tokens": 0,
            "configuration_sha256": None,
            "model_revision": None,
            "tokenizer_revision": None,
            "golden_conformance": {"passed": False},
            "network_required": None,
            "model_download_required": None,
            "reproducibility_blockers": ["no_static_adapter_sidecar"],
        }

    def static_manifest(self) -> dict[str, Any]:
        """Return static public metadata; this method never executes the adapter."""
        if self._static_manifest is not None:
            return dict(self._static_manifest)
        if self.sidecar_path is None:
            self._static_manifest = self._legacy_manifest()
            return dict(self._static_manifest)
        supplied, self._sidecar_sha256 = _load_sidecar(self.sidecar_path)
        schema = str(supplied.get("schema_version", ""))
        if schema.split(".", 1)[0] != SIDECAR_SCHEMA_VERSION.split(".", 1)[0]:
            raise AdapterContractError("adapter sidecar uses an incompatible schema major")
        direction = supplied.get("score_direction")
        if direction not in {"higher", "lower"}:
            raise AdapterContractError("adapter sidecar score_direction must be higher or lower")
        try:
            minimum = int(
                supplied.get("minimum_effective_tokens", supplied.get("minimum_tokens", 0))
            )
        except (TypeError, ValueError):
            raise AdapterContractError(
                "adapter sidecar minimum_effective_tokens must be an integer"
            ) from None
        golden = supplied.get("golden_conformance")
        blockers: list[str] = []
        if supplied.get("independent") is not True:
            blockers.append("independent_classification_not_requested")
        if supplied.get("family") != self.family:
            blockers.append("family_mismatch")
        if supplied.get("source") != self.source:
            blockers.append("source_mismatch")
        required_text = ("id", "implementation", "implementation_version")
        for key in required_text:
            if not _is_revision(supplied.get(key)):
                blockers.append(f"{key}_unresolved")
        if minimum < 1:
            blockers.append("minimum_effective_tokens_not_positive")
        configuration_sha256 = supplied.get("configuration_sha256")
        if not isinstance(configuration_sha256, str) or not _SHA256.fullmatch(configuration_sha256):
            blockers.append("configuration_sha256_invalid")
        for key in ("model_revision", "tokenizer_revision"):
            if not _is_revision(supplied.get(key)):
                blockers.append(f"{key}_unresolved")
        if not isinstance(golden, dict) or golden.get("passed") is not True:
            blockers.append("golden_conformance_not_passed")
        else:
            for key in ("vectors_sha256", "report_sha256"):
                value = golden.get(key)
                if not isinstance(value, str) or not _SHA256.fullmatch(value):
                    blockers.append(f"golden_{key}_invalid")
        if not isinstance(supplied.get("network_required"), bool):
            blockers.append("network_required_unresolved")
        if not isinstance(supplied.get("model_download_required"), bool):
            blockers.append("model_download_required_unresolved")
        _code_indexes, invocation_resolved = _classify_code_argument_indexes(self.command)
        if not invocation_resolved:
            blockers.append("adapter_executable_digest_unresolved")
        assert set(blockers) <= REPRODUCIBILITY_BLOCKER_CODES
        manifest = {
            **supplied,
            "minimum_effective_tokens": minimum,
            "minimum_tokens": minimum,
            "independent_requested": supplied.get("independent") is True,
            "independent": not blockers,
            "sidecar_sha256": self._sidecar_sha256,
            "reproducibility_blockers": blockers,
        }
        self._static_manifest = _public_mapping(manifest)
        return dict(self._static_manifest)

    def executable_digests(self) -> list[dict[str, Any]]:
        """Digest classified executable/script positions without recording paths."""
        values: list[dict[str, Any]] = []
        seen: set[Path] = set()
        code_indexes, _resolved = _classify_code_argument_indexes(self.command)
        for index in sorted(code_indexes):
            argument = self.command[index]
            candidate = Path(argument).expanduser()
            if index == 0 and not candidate.is_file():
                located = shutil.which(argument, path=_scrubbed_environment().get("PATH"))
                candidate = Path(located) if located else candidate
            if not candidate.is_file():
                continue
            try:
                resolved = candidate.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                values.append(
                    {
                        "argument_index": index,
                        "basename": resolved.name,
                        "sha256": _file_sha256(resolved),
                    }
                )
            except OSError:
                continue
        return values

    def reproducibility_manifest(self) -> dict[str, Any]:
        manifest = self.static_manifest()
        executable = self.executable_digests()
        private_file_indexes = secret_file_argument_indexes(self.command)
        blockers = list(manifest.get("reproducibility_blockers", []))
        code_indexes, invocation_resolved = _classify_code_argument_indexes(self.command)
        digested_indexes = {item["argument_index"] for item in executable}
        if not invocation_resolved or not code_indexes <= digested_indexes:
            blockers.append("adapter_executable_digest_unresolved")
        if not manifest.get("sidecar_sha256"):
            blockers.append("adapter_sidecar_digest_unresolved")
        command_identity = {
            "argument_count": len(self.command),
            "option_names": sorted(
                name
                for index, value in enumerate(self.command)
                if index not in private_file_indexes
                if (name := _argument_name(value)) is not None
            ),
            "configuration_sha256": manifest.get("configuration_sha256"),
            "executable_digests": executable,
        }
        return {
            **manifest,
            "command_sha256": _digest(command_identity),
            "command_identity": "public-shape-v1",
            "executable_digests": executable,
            "reproducibility_blockers": sorted(set(blockers)),
            "independent": manifest.get("independent") is True and not blockers,
            "reproducible": not blockers,
        }

    def _enforce_static_policy(self, manifest: dict[str, Any]) -> None:
        if manifest.get("network_required") is True and not self.allow_network:
            raise AdapterContractError(
                f"adapter {self.name} requires network access; pass --allow-network explicitly"
            ) from None
        if manifest.get("model_download_required") is True and not self.allow_model_download:
            raise AdapterContractError(
                f"adapter {self.name} requires a model download; "
                "pass --allow-model-download explicitly"
            ) from None

    def capabilities(self, *, checkpoint: Callable[[], None] | None = None) -> dict[str, Any]:
        """Execute the runtime capability check after static privacy preflight."""
        if self._capabilities is None:
            manifest = self.static_manifest()
            self._enforce_static_policy(manifest)
            raw_result = self._call({"action": "capabilities"}, checkpoint=checkpoint)
            try:
                result = validate_public_json(raw_result, source="adapter capability response")
            except (TypeError, ValueError):
                raise AdapterContractError(
                    f"adapter {self.name} returned non-public capability metadata"
                ) from None
            if type(result) is not dict:
                raise AdapterContractError(f"adapter {self.name} must return public metadata")
            if result.get("network_required") and not self.allow_network:
                raise AdapterContractError(
                    f"adapter {self.name} requires network access; pass --allow-network explicitly"
                ) from None
            if result.get("model_download_required") and not self.allow_model_download:
                raise AdapterContractError(
                    f"adapter {self.name} requires a model download; "
                    "pass --allow-model-download explicitly"
                ) from None
            runtime_manifest = (
                result.get("manifest") if isinstance(result.get("manifest"), dict) else {}
            )
            if manifest.get("independent"):
                for key in (
                    "id",
                    "implementation_version",
                    "configuration_sha256",
                    "model_revision",
                    "tokenizer_revision",
                ):
                    runtime_value = runtime_manifest.get(key, result.get(key))
                    if runtime_value != manifest.get(key):
                        raise AdapterContractError(
                            f"adapter {self.name} runtime {key} does not match its sidecar"
                        ) from None
            self._capabilities = result
        return dict(self._capabilities)

    def manifest(self) -> dict[str, Any]:
        """Compatibility alias for side-effect-free static discovery."""
        return self.reproducibility_manifest()

    def _validate_response_metadata(self, result: dict[str, Any]) -> dict[str, Any]:
        manifest = self.static_manifest()
        metadata: dict[str, Any] = {}
        for key in (
            "requested_tokens",
            "effective_tokens",
            "configuration_sha256",
            "model_revision",
            "tokenizer_revision",
        ):
            if key in result:
                metadata[key] = _public_mapping(result[key])
        if not manifest.get("independent"):
            return metadata
        for key in ("configuration_sha256", "model_revision", "tokenizer_revision"):
            if result.get(key) != manifest.get(key):
                raise AdapterContractError(
                    f"adapter {self.name} response {key} does not match its sidecar"
                ) from None
        try:
            effective = int(result["effective_tokens"])
        except (KeyError, TypeError, ValueError):
            raise AdapterContractError(
                f"adapter {self.name} response omitted effective_tokens"
            ) from None
        if effective < int(manifest["minimum_effective_tokens"]):
            raise AdapterContractError(
                f"adapter {self.name} result is below its minimum effective length"
            ) from None
        metadata["effective_tokens"] = effective
        return metadata

    def generate(self, prompt, _tok, _model, n, seed, watermarked=True):
        self.capabilities()
        result = self._call(
            {
                "action": "generate",
                "prompt": prompt,
                "max_new_tokens": n,
                "seed": seed,
                "watermarked": watermarked,
            }
        )
        if not isinstance(result.get("text"), str):
            raise AdapterContractError(f"adapter {self.name} generation omitted string text")
        metadata = self._validate_response_metadata(result)
        if "requested_tokens" in result:
            try:
                requested = int(result["requested_tokens"])
            except (TypeError, ValueError):
                raise AdapterContractError(
                    f"adapter {self.name} requested_tokens must be an integer"
                ) from None
            if requested != n:
                raise AdapterContractError(
                    f"adapter {self.name} reported a mismatched requested length"
                ) from None
            metadata["requested_tokens"] = requested
        self._last_generation = metadata
        return result["text"]

    def detect(self, text, _tok):
        manifest = self.static_manifest()
        self.capabilities()
        result = self._call({"action": "detect", "text": text})
        try:
            value = float(result["score"])
        except (KeyError, TypeError, ValueError):
            raise AdapterContractError(
                f"adapter {self.name} detection omitted numeric score"
            ) from None
        if not math.isfinite(value):
            raise AdapterContractError(f"adapter {self.name} returned a non-finite score")
        self._last_detection = self._validate_response_metadata(result)
        return -value if manifest["score_direction"] == "lower" else value

    def generation_metadata(self) -> dict[str, Any]:
        return dict(self._last_generation)

    def detection_metadata(self) -> dict[str, Any]:
        return dict(self._last_detection)

    def as_scheme(self) -> dict[str, Any]:
        """Build a scheme descriptor without executing adapter code."""
        manifest = self.manifest()
        return {
            "generate": self.generate,
            "detect": self.detect,
            "generation_metadata": self.generation_metadata,
            "detection_metadata": self.detection_metadata,
            "family": self.family,
            "source": self.source,
            "independent": bool(manifest.get("independent", False)),
            "manifest": manifest,
        }
