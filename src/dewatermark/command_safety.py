"""Credential-safe validation shared by bounded command adapters.

Command arguments are visible to other local processes on many platforms, and
configuration fingerprints are deliberately public.  Neither channel may be
used to smuggle a credential, a credential-derived value, or a private path.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
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
_PUBLIC_PATH_OR_FILE = re.compile(r"(?:[/\\]|^\.{1,2}$|\.[A-Za-z][A-Za-z0-9]{0,15}$)")
_MAX_PUBLIC_DEPTH = 16
_MAX_PUBLIC_NODES = 4096
_MAX_PUBLIC_STRING_CHARACTERS = 4096
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_SCRIPT_BYTES = 16 * 1024 * 1024
_PYTHON_INTERPRETER = re.compile(r"(?i)^(?:pythonw?|pypy)(?:\d+(?:\.\d+)*)?(?:t)?(?:\.exe)?$")
# These executables dispatch code supplied somewhere else in argv.  Until a
# language-specific parser can identify and normalize that complete code
# boundary, their executable bytes alone are not an implementation identity.
# In particular, hashing /bin/sh, env, node, or pwsh while ignoring the script
# would let arbitrarily different detectors appear identical.
_UNPARSED_LAUNCHER = re.compile(
    r"(?i)^(?:"
    r"ash|awk|bash|busybox|bun|chroot|clojure|cmd|command|cscript|csh|dash|deno|"
    r"doas|dotnet|elixir|env|erl|escript|fish|gawk|ghci|groovy|java|jruby|julia|"
    r"ksh|lua|luajit|mawk|mono|nice|node|nodejs|nohup|npm|npx|osascript|perl|"
    r"php|pnpm|powershell|pwsh|py|r|ruby|rscript|runghc|scala|setsid|sh|stdbuf|"
    r"sudo|swift|tclsh|tcsh|timeout|tsx|uv|wish|wscript|xargs|yarn|zsh"
    r")(?:\d+(?:\.\d+)*)?(?:\.exe)?$"
)
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


def _public_path_or_file(value: str) -> bool:
    """Recognize path-shaped public argv without mistaking decimals for files."""
    return bool(value and _PUBLIC_PATH_OR_FILE.search(value))


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


def _command_basename(path: Path) -> str:
    return path.name.lower()


def _python_script_index(argv: tuple[str, ...]) -> tuple[int, tuple[str, ...]] | None:
    """Return one unambiguous Python script position and identity-affecting flags."""
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
    return index, tuple(flags)


def _code_argument_indexes(argv: tuple[str, ...], executable: Path | None) -> frozenset[int]:
    """Identify code paths whose bytes replace their local paths in public identity."""
    indexes = {0}
    if executable is None:
        return frozenset(indexes)
    if _PYTHON_INTERPRETER.fullmatch(_command_basename(executable)):
        parsed = _python_script_index(argv)
        if parsed is not None:
            indexes.add(parsed[0])
    return frozenset(indexes)


def public_command_identity_projection(command: Any) -> tuple[str, ...]:
    """Return the deterministic, path-safe argv projection used in public digests.

    Executable and parsed Python-script paths are represented by stable role
    markers because their exact bytes are bound separately. Operator-managed
    secret-file paths get a distinct marker, and every other path/file-looking
    value is replaced rather than fed to a public digest. Non-path arguments
    remain exact, so changing ordinary public behavior/configuration changes
    the identity.
    """
    argv = validate_public_command(command)
    executable = _resolved_command_file(argv[0])
    code_indexes = _code_argument_indexes(argv, executable)
    private_indexes = secret_file_argument_indexes(argv)
    projected: list[str] = []
    for index, argument in enumerate(argv):
        if index in code_indexes:
            role = "executable" if index == 0 else "python-script"
            projected.append(f"<command-code:{role}>")
        elif index in private_indexes:
            option, separator, _value = argument.partition("=")
            projected.append(
                f"{option}=<operator-managed-secret-file>"
                if separator
                else "<operator-managed-secret-file>"
            )
        else:
            option, separator, value = argument.partition("=")
            if separator and _public_path_or_file(value):
                projected.append(f"{option}=<command-file-argument>")
            elif _public_path_or_file(argument):
                projected.append("<command-file-argument>")
            else:
                projected.append(argument)
    return tuple(projected)


def public_command_identity_sha256(command: Any) -> str:
    """Hash the public command shape without code paths or secret-file paths."""
    encoded = json.dumps(
        {
            "identity": "command-public-shape-v1",
            "argv": public_command_identity_projection(command),
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _bounded_regular_file_bytes(path: Path, *, limit: int) -> bytes | None:
    descriptor = -1
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            return None
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > limit
            or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
        ):
            return None
        blocks: list[bytes] = []
        total = 0
        while total <= limit:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not block:
                break
            blocks.append(block)
            total += len(block)
        if total > limit:
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


def _python_source_identity_sha256(content: bytes) -> str | None:
    """Hash executable Python syntax, ignoring comments and formatting only."""
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


def command_code_identities_sha256(command: Any) -> tuple[str | None, str | None]:
    """Return semantic and exact-raw identities for one bounded code entrypoint.

    Arguments after the code entrypoint are deliberately excluded because they
    can reference operator-private configuration or secret files. Ambiguous
    interpreter forms (for example ``python -m`` or ``python -c``) return two
    ``None`` values because the complete executable code cannot be identified.

    Python semantic identity ignores comments, formatting, pass statements, and
    unused module constants so cosmetic copies cannot manufacture held-out
    independence. Exact-raw identity binds every byte of the executable and an
    unambiguous script; it is the identity used for caches and drift checks.
    """
    argv = validate_public_command(command)
    executable = _resolved_command_file(argv[0])
    if executable is None:
        return None, None
    basename = _command_basename(executable)
    if _UNPARSED_LAUNCHER.fullmatch(basename):
        # These programs interpret or dispatch another argv entry. Hashing only
        # the launcher would bind neither the code that receives source nor its
        # semantics, so it cannot establish profile or held-out identity.
        return None, None
    executable_content = _bounded_regular_file_bytes(executable, limit=_MAX_EXECUTABLE_BYTES)
    if executable_content is None:
        return None, None
    raw_executable_digest = hashlib.sha256(executable_content).hexdigest()
    if executable_content.startswith(b"#!"):
        shebang = executable_content.splitlines()[0].lower()
        if b"python" not in shebang:
            # Direct shell/other scripts need a language-specific semantic
            # identity. Ordinary execution is still allowed, but they cannot
            # establish held-out implementation independence.
            semantic_executable_digest = None
        else:
            semantic_executable_digest = _python_source_identity_sha256(executable_content)
    else:
        semantic_executable_digest = raw_executable_digest
    semantic_parts = (
        ["command-code-v1", semantic_executable_digest]
        if semantic_executable_digest is not None
        else None
    )
    raw_parts = ["command-code-raw-v1", raw_executable_digest]
    if _PYTHON_INTERPRETER.fullmatch(basename):
        parsed = _python_script_index(argv)
        if parsed is None:
            return None, None
        index, flags = parsed
        try:
            script = Path(argv[index]).resolve(strict=True)
        except OSError:
            return None, None
        script_content = _bounded_regular_file_bytes(script, limit=_MAX_SCRIPT_BYTES)
        if script_content is None:
            return None, None
        script_digest = _python_source_identity_sha256(script_content)
        raw_script_digest = hashlib.sha256(script_content).hexdigest()
        if semantic_parts is not None:
            if script_digest is None:
                semantic_parts = None
            else:
                semantic_parts.extend(flags)
                semantic_parts.append(script_digest)
        raw_parts.extend(flags)
        raw_parts.append(raw_script_digest)
    semantic_identity = (
        hashlib.sha256("\0".join(semantic_parts).encode("utf-8")).hexdigest()
        if semantic_parts is not None
        else None
    )
    raw_identity = hashlib.sha256("\0".join(raw_parts).encode("utf-8")).hexdigest()
    return semantic_identity, raw_identity


def command_code_identity_sha256(command: Any) -> str | None:
    """Return the semantic command identity used for held-out distinctness."""
    return command_code_identities_sha256(command)[0]


def command_code_raw_identity_sha256(command: Any) -> str | None:
    """Return the exact bounded executable/script identity used for drift."""
    return command_code_identities_sha256(command)[1]


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
    "command_code_identities_sha256",
    "command_code_identity_sha256",
    "command_code_raw_identity_sha256",
    "public_command_identity_projection",
    "public_command_identity_sha256",
    "secret_file_argument_indexes",
    "validate_public_command",
    "validate_public_json",
]
