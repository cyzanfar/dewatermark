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
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Thread
from typing import Any, Optional

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
_SENSITIVE_ARGUMENTS = {
    "api_key",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


def _argument_name(value: str) -> str:
    return value.split("=", 1)[0].lstrip("-/").lower().replace("-", "_")


def _is_sensitive_argument(value: str) -> bool:
    name = _argument_name(value)
    if any(public in name for public in ("digest", "fingerprint", "identifier", "sha256")):
        return False
    return name in _SENSITIVE_ARGUMENTS or name.endswith(
        ("_api_key", "_credential", "_password", "_private_key", "_secret", "_token")
    )


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
    if any(_is_sensitive_argument(value) for value in argv) or any(
        re.search(r"://[^/@\s]+:[^/@\s]+@", value) for value in argv
    ):
        raise ValueError(
            "adapter command arguments cannot carry credentials; use an isolated "
            "operator-managed adapter boundary"
        )
    return tuple(argv)


class AdapterContractError(RuntimeError):
    """External adapter violated the JSON protocol."""


@dataclass
class _StreamCapture:
    limit: int
    retain: bool
    data: bytearray = field(default_factory=bytearray)
    count: int = 0
    overflow: bool = False


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate the adapter and its process group without surfacing details."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _read_bounded(
    stream: Any,
    capture: _StreamCapture,
    overflow_event: Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            capture.count += len(chunk)
            remaining = max(0, capture.limit - len(capture.data))
            if capture.retain and remaining:
                capture.data.extend(chunk[:remaining])
            if capture.count > capture.limit:
                capture.overflow = True
                overflow_event.set()
                _terminate_process(process)
                return
    except (OSError, ValueError):
        return


def _write_request(stream: Any, payload: bytes) -> None:
    try:
        stream.write(payload)
        stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _run_bounded_command(
    command: tuple[str, ...],
    payload: bytes,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    adapter_name: str,
) -> bytes:
    """Run argv with streaming output caps and one wall-clock deadline."""
    popen_options: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "env": _scrubbed_environment(),
        "close_fds": True,
    }
    if os.name == "nt":
        popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_options["start_new_session"] = True
    try:
        process: subprocess.Popen[bytes] = subprocess.Popen(command, **popen_options)
    except OSError:
        raise RuntimeError(f"adapter {adapter_name} could not be launched") from None
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    overflow_event = Event()
    stdout = _StreamCapture(max_stdout_bytes, retain=True)
    stderr = _StreamCapture(max_stderr_bytes, retain=False)
    readers = (
        Thread(
            target=_read_bounded,
            args=(process.stdout, stdout, overflow_event, process),
            daemon=True,
        ),
        Thread(
            target=_read_bounded,
            args=(process.stderr, stderr, overflow_event, process),
            daemon=True,
        ),
    )
    writer = Thread(target=_write_request, args=(process.stdin, payload), daemon=True)
    for thread in readers:
        thread.start()
    writer.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    try:
        while process.poll() is None:
            if overflow_event.is_set():
                _terminate_process(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process(process)
                break
            time.sleep(min(0.01, remaining))
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _terminate_process(process)
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"adapter {adapter_name} could not be terminated") from None
    finally:
        writer.join(timeout=1.0)
        for thread in readers:
            thread.join(timeout=1.0)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        for thread in readers:
            thread.join(timeout=0.1)
    if timed_out:
        raise RuntimeError(
            f"adapter {adapter_name} timed out; process output was redacted"
        ) from None
    if stdout.overflow or stderr.overflow:
        raise AdapterContractError(
            f"adapter {adapter_name} exceeded its output limit; process output was redacted"
        ) from None
    if process.returncode:
        raise RuntimeError(
            f"adapter {adapter_name} exited with status {process.returncode}; "
            "process output was redacted"
        ) from None
    return bytes(stdout.data)


def _public_mapping(value: Any) -> Any:
    """Remove credential-like fields before persisting adapter metadata."""
    if isinstance(value, dict):

        def safe_key(key: object) -> bool:
            normalized = str(key).lower().replace("-", "_")
            forbidden = {
                "api_key",
                "authorization",
                "body",
                "candidate_text",
                "content",
                "cookie",
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
            str(key): _public_mapping(item) for key, item in sorted(value.items()) if safe_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [_public_mapping(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


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
    for argument in command:
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
        raw = path.read_bytes()
        value = json.loads(raw)
    except AdapterContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise AdapterContractError("adapter sidecar could not be read as bounded JSON") from None
    if not isinstance(value, dict):
        raise AdapterContractError("adapter sidecar must contain one JSON object")
    return _public_mapping(value), hashlib.sha256(raw).hexdigest()


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
        if self.sidecar_path is None:
            self.sidecar_path = _discover_sidecar(self.command)

    def __repr__(self) -> str:
        return (
            f"CommandScheme(name={self.name!r}, family={self.family!r}, timeout={self.timeout!r})"
        )

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

    def _call(self, payload: dict[str, Any]) -> dict[str, Any]:
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
        )
        try:
            result = json.loads(stdout)
        except (UnicodeError, json.JSONDecodeError):
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
            "reproducibility_blockers": ["no static adapter sidecar was found"],
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
            blockers.append("sidecar does not request independent classification")
        if supplied.get("family") != self.family:
            blockers.append("sidecar family does not match the adapter registration")
        if supplied.get("source") != self.source:
            blockers.append("sidecar source does not match the adapter registration")
        required_text = ("id", "implementation", "implementation_version")
        for key in required_text:
            if not _is_revision(supplied.get(key)):
                blockers.append(f"{key} is unresolved")
        if minimum < 1:
            blockers.append("minimum_effective_tokens is not positive")
        configuration_sha256 = supplied.get("configuration_sha256")
        if not isinstance(configuration_sha256, str) or not _SHA256.fullmatch(configuration_sha256):
            blockers.append("configuration_sha256 is missing or invalid")
        for key in ("model_revision", "tokenizer_revision"):
            if not _is_revision(supplied.get(key)):
                blockers.append(f"{key} is unresolved")
        if not isinstance(golden, dict) or golden.get("passed") is not True:
            blockers.append("golden conformance has not passed")
        else:
            for key in ("vectors_sha256", "report_sha256"):
                value = golden.get(key)
                if not isinstance(value, str) or not _SHA256.fullmatch(value):
                    blockers.append(f"golden_conformance.{key} is missing or invalid")
        if not isinstance(supplied.get("network_required"), bool):
            blockers.append("network_required is unresolved")
        if not isinstance(supplied.get("model_download_required"), bool):
            blockers.append("model_download_required is unresolved")
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
        """Digest each local executable/script argument without recording its path."""
        values: list[dict[str, Any]] = []
        seen: set[Path] = set()
        for index, argument in enumerate(self.command):
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
        blockers = list(manifest.get("reproducibility_blockers", []))
        if not executable:
            blockers.append("adapter executable/script digest is unresolved")
        if not manifest.get("sidecar_sha256"):
            blockers.append("adapter sidecar digest is unresolved")
        command_identity = {
            "argument_count": len(self.command),
            "option_names": sorted(
                _argument_name(value) for value in self.command if value.startswith(("-", "/"))
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

    def capabilities(self) -> dict[str, Any]:
        """Execute the runtime capability check after static privacy preflight."""
        if self._capabilities is None:
            manifest = self.static_manifest()
            self._enforce_static_policy(manifest)
            result = _public_mapping(self._call({"action": "capabilities"}))
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
