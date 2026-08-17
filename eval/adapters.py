"""Adapters for independent/official watermark implementations.

An adapter executable receives one JSON object on stdin and returns one JSON
object on stdout.  Generation requests contain ``action=generate`` and detection
requests contain ``action=detect``.  This keeps heavyweight MarkLLM, SynthID,
and vendor-authorized detectors in isolated environments instead of vendoring
or silently approximating them in this harness.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional

PROTOCOL_VERSION = "1.0"


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
    return tuple(argv)


class AdapterContractError(RuntimeError):
    """External adapter violated the JSON protocol."""


@dataclass(frozen=True)
class CommandScheme:
    name: str
    command: tuple[str, ...]
    family: str
    source: str
    timeout: int = 600

    @classmethod
    def from_spec(cls, spec: str) -> "CommandScheme":
        """Parse ``NAME|FAMILY|SOURCE|COMMAND`` without invoking a shell."""
        try:
            name, family, source, command = spec.split("|", 3)
        except ValueError as exc:
            raise ValueError("adapter must be NAME|FAMILY|SOURCE|COMMAND") from exc
        argv = _split_command(command)
        if not argv:
            raise ValueError("adapter command cannot be empty")
        return cls(name=name, family=family, source=source, command=argv)

    def _call(self, payload: dict) -> dict:
        payload = {"protocol_version": PROTOCOL_VERSION, **payload}
        proc = subprocess.run(
            self.command,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        if proc.returncode:
            raise RuntimeError(f"adapter {self.name} exited {proc.returncode}: {proc.stderr[:300]}")
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterContractError(f"adapter {self.name} returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise AdapterContractError(f"adapter {self.name} must return a JSON object")
        response_version = result.get("protocol_version", PROTOCOL_VERSION)
        if str(response_version).split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise AdapterContractError(
                f"adapter {self.name} uses incompatible protocol {response_version}"
            )
        return result

    def capabilities(self) -> dict:
        return self._call({"action": "capabilities"})

    def generate(self, prompt, _tok, _model, n, seed, watermarked=True):
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
        return result["text"]

    def detect(self, text, _tok):
        result = self._call({"action": "detect", "text": text})
        try:
            return float(result["score"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterContractError(
                f"adapter {self.name} detection omitted numeric score"
            ) from exc

    def as_scheme(self) -> dict:
        return {
            "generate": self.generate,
            "detect": self.detect,
            "family": self.family,
            "source": self.source,
            "independent": True,
        }
