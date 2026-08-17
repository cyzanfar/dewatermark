"""Structure-preserving chunking for bounded-context rewrite backends."""

from __future__ import annotations

import re

from .extension_safety import require_extension

_BOUNDARY = re.compile(r"(\n\s*\n|(?<=[.!?])(?=\s+))")


def chunk_text(text: str, max_chars: int) -> list[str]:
    if max_chars < 256:
        raise ValueError("max_chars must be at least 256")
    if len(text) <= max_chars:
        return [text]
    parts = _BOUNDARY.split(text)
    chunks: list[str] = []
    current = ""
    for part in parts:
        if len(part) > max_chars:
            if current:
                chunks.append(current)
                current = ""
            chunks.extend(part[i : i + max_chars] for i in range(0, len(part), max_chars))
        elif current and len(current) + len(part) > max_chars:
            chunks.append(current)
            current = part
        else:
            current += part
    if current:
        chunks.append(current)
    return chunks


def split_for_config(text: str, config) -> list[str]:
    """Use an injected chunker or the formatting-preserving built-in splitter."""
    if config.chunker is None:
        return chunk_text(text, config.max_chunk_chars)
    require_extension(config.chunker, "chunker", config)
    chunks = list(config.chunker.split(text, config.max_chunk_chars))
    if not all(isinstance(chunk, str) for chunk in chunks):
        raise TypeError("custom chunker must return strings")
    if "".join(chunks) != text:
        raise ValueError("custom chunker must reconstruct the source exactly")
    return chunks
