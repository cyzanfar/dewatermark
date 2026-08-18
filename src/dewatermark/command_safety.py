"""Credential-safe validation shared by bounded command adapters.

Command arguments are visible to other local processes on many platforms, and
configuration fingerprints are deliberately public.  Neither channel may be
used to smuggle a credential, a credential-derived value, or a private path.
"""

from __future__ import annotations

import ast
import hashlib
import io
import math
import os
import re
import shutil
import stat
import tokenize
from pathlib import Path
from typing import Any

from .models import _unsafe_public_text

_SENSITIVE_KEY_TOKENS = frozenset(
    {
        "auth",
        "authorization",
        "credential",
        "key",
        "password",
        "private",
        "secret",
        "token",
    }
)
_PATH_KEY_TOKENS = frozenset(
    {
        "dir",
        "directory",
        "directories",
        "file",
        "filename",
        "filenames",
        "path",
        "paths",
    }
)
_SAFE_KEY_IDENTIFIERS = frozenset(
    {
        "key_id",
        "key_identifier",
        "key_ids",
        "public_key_id",
        "public_key_identifier",
    }
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:sk|rk)[-_](?:live|test|proj|ant)?[-_A-Za-z0-9]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)(?:^|[^A-Za-z0-9])(?:x[-_]?api[-_]?key|api[-_]?key|"
        r"aws[-_]?secret[-_]?access[-_]?key|authorization|credential|password|secret|token)"
        r"\s*[:=]\s*[^\s,;]{8,}"
    ),
)
_URL_USERINFO = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")
_SENSITIVE_VALUE_MARKER = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:api[-_]?key|bearer|credential|password|private|secret|token)"
    r"(?![A-Za-z0-9])"
)
_FILE_OPTION = re.compile(r"(?i)(?:^|_)(?:credential|key|password|secret|token)_(?:file|path)$")
_PUBLIC_ID_OPTION = re.compile(r"(?i)(?:^|_)(?:key)_id(?:entifier)?s?$")
_FORBIDDEN_CONTAINER_OPTIONS = frozenset({"env", "environment", "header", "headers"})
_FILE_REFERENCE = re.compile(r"(?:[/\\]|^\.{1,2}$|\.[A-Za-z0-9]{1,16}$)")
_MAX_PUBLIC_DEPTH = 16
_MAX_PUBLIC_NODES = 4096
_MAX_PUBLIC_STRING_CHARACTERS = 4096
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_SCRIPT_BYTES = 16 * 1024 * 1024
_PYTHON_INTERPRETER = re.compile(r"(?i)^python(?:\d+(?:\.\d+)*)?(?:\.exe)?$")
_PYTHON_NO_VALUE_OPTIONS = frozenset(
    {
        "-B",
        "-E",
        "-I",
        "-O",
        "-OO",
        "-P",
        "-q",
        "-s",
        "-S",
        "-u",
        "-v",
        "-V",
        "-x",
        "--isolated",
        "--no-site",
        "--safe-path",
        "--unbuffered",
    }
)


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _sensitive_key(key: str) -> bool:
    normalized = _normalized_name(key)
    if normalized in _SAFE_KEY_IDENTIFIERS:
        return False
    tokens = tuple(part for part in normalized.split("_") if part)
    return any(token in _SENSITIVE_KEY_TOKENS for token in tokens)


def _path_key(key: str) -> bool:
    return any(token in _PATH_KEY_TOKENS for token in _normalized_name(key).split("_"))


def _unsafe_argument_value(value: str) -> bool:
    # Absolute executable/script paths are legitimate argv. Avoid treating
    # unrelated directory names (for example macOS ``/private`` plus a file
    # named ``tokenizer.py``) as two markers in one credential value.
    marker_subject = re.split(r"[/\\]", value)[-1] if re.search(r"[/\\]", value) else value
    return bool(
        _URL_USERINFO.search(value)
        or any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS)
        or len(_SENSITIVE_VALUE_MARKER.findall(marker_subject)) >= 2
    )


def _option(argument: str) -> tuple[str, str | None] | None:
    if not argument.startswith("-") or argument == "-":
        return None
    raw = argument.lstrip("-")
    name, separator, value = raw.partition("=")
    return _normalized_name(name), value if separator else None


def _file_reference(value: str) -> bool:
    return bool(value and _FILE_REFERENCE.search(value) and not _unsafe_argument_value(value))


def validate_public_command(command: Any) -> tuple[str, ...]:
    """Accept immutable argv only when no argument carries credential material.

    Secret values must be supplied through a separately reviewed operator
    channel.  A secret *file reference* is allowed because only its path reaches
    argv; the referenced content remains outside this public configuration.
    """
    if type(command) is not tuple:
        raise TypeError("command must be an immutable tuple of argv strings")
    if not command:
        raise ValueError("command argv cannot be empty")
    expect_file_reference = False
    for argument in command:
        if type(argument) is not str or not argument or "\x00" in argument:
            raise ValueError("command argv must contain exact non-empty strings without NUL bytes")
        if expect_file_reference:
            if not _file_reference(argument):
                raise ValueError(
                    "command argv cannot carry credentials; use an operator-managed secret channel"
                )
            expect_file_reference = False
            continue

        parsed = _option(argument)
        if parsed is not None:
            name, inline_value = parsed
            if name in _FORBIDDEN_CONTAINER_OPTIONS:
                raise ValueError(
                    "command argv cannot carry credentials; use an operator-managed secret channel"
                )
            if _FILE_OPTION.search(name):
                if inline_value is None:
                    expect_file_reference = True
                elif not _file_reference(inline_value):
                    raise ValueError(
                        "command argv cannot carry credentials; use an operator-managed secret channel"
                    )
                continue
            if _sensitive_key(name) and not _PUBLIC_ID_OPTION.search(name):
                raise ValueError(
                    "command argv cannot carry credentials; use an operator-managed secret channel"
                )
            if inline_value is not None and _unsafe_argument_value(inline_value):
                raise ValueError(
                    "command argv cannot carry credentials; use an operator-managed secret channel"
                )
            continue

        if _unsafe_argument_value(argument):
            raise ValueError(
                "command argv cannot carry credentials; use an operator-managed secret channel"
            )
    if expect_file_reference:
        raise ValueError("command secret-file option requires a file reference")
    return command


def secret_file_argument_indexes(command: Any) -> frozenset[int]:
    """Return argv positions that reference operator-managed secret files.

    The command is validated first. The returned positions must never be
    content-hashed or copied into a public identity; the option name itself may
    still be recorded as public command shape.
    """
    validated = validate_public_command(command)
    indexes: set[int] = set()
    expect_file_reference = False
    for index, argument in enumerate(validated):
        if expect_file_reference:
            indexes.add(index)
            expect_file_reference = False
            continue
        parsed = _option(argument)
        if parsed is None:
            continue
        name, inline_value = parsed
        if not _FILE_OPTION.search(name):
            continue
        if inline_value is None:
            expect_file_reference = True
        else:
            indexes.add(index)
    return frozenset(indexes)


def _resolved_command_file(value: str) -> Path | None:
    selected = value if os.path.dirname(value) else shutil.which(value)
    if not selected:
        return None
    try:
        return Path(selected).resolve(strict=True)
    except OSError:
        return None


def _bounded_regular_file_bytes(path: Path, *, limit: int) -> bytes | None:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        blocks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            blocks.append(block)
            remaining -= len(block)
        if remaining == 0 and os.read(descriptor, 1):
            return None
        return b"".join(blocks)
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _bounded_regular_file_sha256(path: Path, *, limit: int) -> str | None:
    content = _bounded_regular_file_bytes(path, limit=limit)
    return hashlib.sha256(content).hexdigest() if content is not None else None


def _python_source_identity_sha256(path: Path) -> str | None:
    """Hash executable Python syntax, ignoring comments and formatting only."""
    content = _bounded_regular_file_bytes(path, limit=_MAX_SCRIPT_BYTES)
    if content is None:
        return None
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
        tree = ast.parse(content.decode(encoding), filename="<detector-command>")
    except (LookupError, SyntaxError, UnicodeError):
        return None
    loaded_names = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    if isinstance(tree, ast.Module):
        filtered: list[ast.stmt] = []
        for statement in tree.body:
            targets: list[ast.expr] = []
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    list(statement.targets)
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
            assigned_names = {
                node.id
                for target in targets
                for node in ast.walk(target)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            }
            if assigned_names and assigned_names.isdisjoint(loaded_names):
                continue
            if isinstance(statement, ast.Pass) or (
                isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
            ):
                continue
            filtered.append(statement)
        tree.body = filtered
    normalized = ast.dump(tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(f"python-ast-v1\0{normalized}".encode("utf-8")).hexdigest()


def command_code_identity_sha256(command: Any) -> str | None:
    """Bind the executable and unambiguous script bytes used by a command.

    Arguments after the code entrypoint are deliberately excluded because they
    can reference operator-private configuration or secret files. Ambiguous
    interpreter forms (for example ``python -m`` or ``python -c``) return
    ``None`` and therefore cannot establish held-out implementation identity.
    """
    argv = validate_public_command(command)
    executable = _resolved_command_file(argv[0])
    if executable is None:
        return None
    executable_content = _bounded_regular_file_bytes(executable, limit=_MAX_EXECUTABLE_BYTES)
    if executable_content is None:
        return None
    if executable_content.startswith(b"#!"):
        shebang = executable_content.splitlines()[0].lower()
        if b"python" not in shebang:
            # Direct shell/other scripts need a language-specific semantic
            # identity. Ordinary execution is still allowed, but they cannot
            # establish held-out implementation independence.
            return None
        executable_digest = _python_source_identity_sha256(executable)
    else:
        executable_digest = hashlib.sha256(executable_content).hexdigest()
    if executable_digest is None:
        return None
    basename = re.split(r"[/\\]", argv[0])[-1]
    parts = ["command-code-v1", executable_digest]
    if _PYTHON_INTERPRETER.fullmatch(basename):
        index = 1
        flags: list[str] = []
        while index < len(argv):
            argument = argv[index]
            if argument == "--":
                flags.append(argument)
                index += 1
                break
            if argument in _PYTHON_NO_VALUE_OPTIONS:
                flags.append(argument)
                index += 1
                continue
            if argument.startswith("-"):
                return None
            break
        if index >= len(argv) or Path(argv[index]).suffix.lower() not in {".py", ".pyw", ".pyz"}:
            return None
        try:
            script = Path(argv[index]).resolve(strict=True)
        except OSError:
            return None
        script_digest = _python_source_identity_sha256(script)
        if script_digest is None:
            return None
        parts.extend(flags)
        parts.append(script_digest)
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def validate_public_json(value: Any, *, source: str = "configuration") -> Any:
    """Return strict literal JSON that is safe to hash or publish.

    Public configuration contains identifiers and commitments only.  It must
    not contain credential fields, credential-shaped values, local paths, or
    hook-bearing container subclasses.
    """
    nodes = 0

    def visit(item: Any, *, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_PUBLIC_NODES or depth > _MAX_PUBLIC_DEPTH:
            raise ValueError(f"{source} exceeds the public JSON complexity limit")
        item_type = type(item)
        if item is None or item_type in (bool, int):
            return item
        if item_type is float:
            if not math.isfinite(item):
                raise ValueError(f"{source} contains a non-finite number")
            return item
        if item_type is str:
            if len(item) > _MAX_PUBLIC_STRING_CHARACTERS or _unsafe_public_text(item):
                raise ValueError(f"{source} contains private or credential-like text")
            return item
        if item_type is dict:
            projected: dict[str, Any] = {}
            for key, nested in item.items():
                if type(key) is not str:
                    raise TypeError(f"{source} keys must be exact strings")
                if (
                    len(key) > 256
                    or _unsafe_public_text(key)
                    or _sensitive_key(key)
                    or _path_key(key)
                ):
                    raise ValueError(
                        f"{source} must contain public identifiers or commitments, not secrets or paths"
                    )
                projected[key] = visit(nested, depth=depth + 1)
            return projected
        if item_type in (list, tuple):
            return [visit(nested, depth=depth + 1) for nested in item]
        raise TypeError(f"{source} must contain only literal JSON values")

    return visit(value, depth=0)


__all__ = [
    "command_code_identity_sha256",
    "secret_file_argument_indexes",
    "validate_public_command",
    "validate_public_json",
]
