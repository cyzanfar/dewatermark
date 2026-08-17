"""Structural extension contracts; implementations need not inherit them."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from .quality import QualityReport


@runtime_checkable
class Scorer(Protocol):
    def available(self) -> bool: ...
    def self_information(self, text: str) -> list[dict[str, Any]]: ...
    def score(self, text: str) -> Mapping[str, Any]: ...


@runtime_checkable
class Rewriter(Protocol):
    def available(self) -> bool: ...
    def rewrite(self, text: str, **options: Any) -> tuple[str, Mapping[str, Any]]: ...


@runtime_checkable
class QualityGate(Protocol):
    def evaluate(self, source: str, candidate: str) -> QualityReport: ...


@runtime_checkable
class Detector(Protocol):
    def detect(self, text: str) -> float: ...


@runtime_checkable
class Chunker(Protocol):
    def split(self, text: str, max_chars: int) -> Sequence[str]: ...
