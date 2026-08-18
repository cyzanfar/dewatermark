"""Deterministic word-level watermark references for tests and education.

These deliberately small schemes make detector integration, abstention, and
evidence workflows reproducible without a model or network.  They are *not*
drop-in implementations of KGW, SynthID Text, Gemini, Claude, or any production
watermark.  In particular, their whitespace-independent word tokenizer and
public fixture key are incompatible with provider watermarks.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, Optional, Sequence, cast

from .models import CapabilityManifest, DetectionEvidence, DetectionStatus

REFERENCE_DETECTOR_PROTOCOL_VERSION = "1.0"
REFERENCE_GAMMA = 0.25
REFERENCE_Z_THRESHOLD = 4.0
REFERENCE_MINIMUM_EFFECTIVE_TOKENS = 32
REFERENCE_TOKENIZER_REVISION = "unicode-nfc-regex-v1"
_PUBLIC_FIXTURE_KEY = "dewatermark-public-research-fixture-v1"
_TOKEN_PATTERN = re.compile(r"[^\W_]+(?:['’][^\W_]+)*|[^\w\s]", re.UNICODE)

ReferenceScheme = Literal["kgw-word-v1", "unigram-word-v1", "tournament-word-v1"]

_SCHEME_IDENTIFIERS: dict[ReferenceScheme, str] = {
    "kgw-word-v1": "research-reference/kgw-word-v1",
    "unigram-word-v1": "research-reference/unigram-word-v1",
    "tournament-word-v1": "research-reference/tournament-word-v1",
}
_SCHEME_SOURCES: dict[ReferenceScheme, str] = {
    "kgw-word-v1": "https://arxiv.org/abs/2301.10226",
    "unigram-word-v1": "https://arxiv.org/abs/2306.17439",
    "tournament-word-v1": "https://github.com/google-deepmind/synthid-text",
}

# A stable vocabulary used only to build public golden fixtures. It is not a
# language model, and generated sequences are not presented as natural text.
_FIXTURE_VOCABULARY = (
    "analysis",
    "artifact",
    "assurance",
    "balanced",
    "baseline",
    "benchmark",
    "boundary",
    "calibration",
    "candidate",
    "careful",
    "channel",
    "check",
    "claim",
    "clear",
    "compare",
    "configuration",
    "consent",
    "constraint",
    "context",
    "control",
    "corpus",
    "data",
    "decision",
    "detector",
    "deterministic",
    "document",
    "evidence",
    "experiment",
    "explicit",
    "failure",
    "fixture",
    "generator",
    "golden",
    "independent",
    "inspect",
    "language",
    "length",
    "local",
    "manifest",
    "matched",
    "measure",
    "metadata",
    "mitigation",
    "model",
    "network",
    "offline",
    "operator",
    "policy",
    "population",
    "privacy",
    "protocol",
    "quality",
    "reference",
    "reliable",
    "report",
    "research",
    "revision",
    "sample",
    "scheme",
    "score",
    "source",
    "statistical",
    "status",
    "test",
    "text",
    "threshold",
    "token",
    "transform",
    "transparent",
    "unmarked",
    "validation",
    "vector",
    "verification",
    "version",
    "watermark",
    "workflow",
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _fixture_key_fingerprint() -> str:
    return hashlib.sha256(_PUBLIC_FIXTURE_KEY.encode("ascii")).hexdigest()


def _configuration(scheme: ReferenceScheme) -> dict[str, Any]:
    common = {
        "protocol_version": REFERENCE_DETECTOR_PROTOCOL_VERSION,
        "scheme": scheme,
        "tokenizer_revision": REFERENCE_TOKENIZER_REVISION,
        "normalization": "NFC",
        "public_fixture_key_sha256": _fixture_key_fingerprint(),
        "threshold": REFERENCE_Z_THRESHOLD,
        "minimum_effective_tokens": REFERENCE_MINIMUM_EFFECTIVE_TOKENS,
    }
    if scheme in ("kgw-word-v1", "unigram-word-v1"):
        common["gamma"] = REFERENCE_GAMMA
    if scheme == "kgw-word-v1":
        common.update({"context_width": 1, "ignore_repeated_bigrams": True})
    if scheme == "tournament-word-v1":
        common.update({"context_width": 4, "watermarking_depth": 4})
    return common


def reference_configuration_sha256(scheme: ReferenceScheme) -> str:
    """Return the immutable public-fixture configuration fingerprint."""
    return hashlib.sha256(_canonical_json(_configuration(scheme))).hexdigest()


def reference_tokenize(text: str) -> tuple[str, ...]:
    """Tokenize with the pinned word-level policy used by every reference."""
    if not isinstance(text, str):
        raise TypeError("reference detector text must be a string")
    normalized = unicodedata.normalize("NFC", text)
    return tuple(match.group(0).casefold() for match in _TOKEN_PATTERN.finditer(normalized))


def _uniform(namespace: str, *parts: str) -> float:
    framed = "\x1f".join((_PUBLIC_FIXTURE_KEY, namespace, *parts)).encode("utf-8")
    value = int.from_bytes(hashlib.sha256(framed).digest()[:8], "big")
    return (value + 0.5) / float(1 << 64)


def _green(scheme: ReferenceScheme, context: tuple[str, ...], token: str) -> bool:
    if scheme == "unigram-word-v1":
        context = ()
    return _uniform(scheme, *context, token) < REFERENCE_GAMMA


def _tournament_value(context: tuple[str, ...], token: str) -> float:
    values = [
        _uniform("tournament-word-v1", str(depth), *context[-(depth + 1) :], token)
        for depth in range(4)
    ]
    return sum(values) / len(values)


def _normal_survival(z_score: float) -> float:
    return 0.5 * math.erfc(z_score / math.sqrt(2.0))


@dataclass(frozen=True)
class _Score:
    value: float
    effective_tokens: int
    auxiliary_name: str
    auxiliary_value: float


def _greenlist_score(tokens: tuple[str, ...], scheme: ReferenceScheme) -> _Score:
    contexts: set[tuple[str, str]] = set()
    hits = 0
    scored: list[tuple[tuple[str, ...], str]]
    if scheme == "unigram-word-v1":
        scored = [((), token) for token in tokens]
    else:
        scored = []
        for previous, token in zip(tokens, tokens[1:]):
            bigram = (previous, token)
            if bigram in contexts:
                continue
            contexts.add(bigram)
            scored.append(((previous,), token))
    for context, token in scored:
        hits += int(_green(scheme, context, token))
    total = len(scored)
    denominator = math.sqrt(total * REFERENCE_GAMMA * (1.0 - REFERENCE_GAMMA))
    z_score = (hits - REFERENCE_GAMMA * total) / denominator if denominator else 0.0
    return _Score(z_score, total, "green_hits", float(hits))


def _tournament_score(tokens: tuple[str, ...]) -> _Score:
    context_width = 4
    if len(tokens) <= context_width:
        return _Score(0.0, 0, "mean_g_value", 0.0)
    values = [
        _tournament_value(tokens[index - context_width : index], tokens[index])
        for index in range(context_width, len(tokens))
    ]
    mean = sum(values) / len(values)
    # Each layer is uniform under this synthetic null. Averaging four layers
    # gives variance 1/(12*4); the normalization is an explicitly approximate
    # fixture statistic, not a production false-positive calibration.
    z_score = (mean - 0.5) * math.sqrt(12.0 * 4.0 * len(values))
    return _Score(z_score, len(values), "mean_g_value", mean)


def _capability(scheme: ReferenceScheme, description: str) -> CapabilityManifest:
    return CapabilityManifest(
        identifier=_SCHEME_IDENTIFIERS[scheme],
        kind="detector",
        version=REFERENCE_DETECTOR_PROTOCOL_VERSION,
        schemes=(f"research-reference/{scheme}",),
        description=description,
        calibrated=False,
        independent=False,
        metadata={
            "status": "research_fixture_only",
            "evidence_level": "same_implementation",
            "source": _SCHEME_SOURCES[scheme],
            "license": "MIT (fixture implementation); cited upstream work retains its license",
            "configuration_sha256": reference_configuration_sha256(scheme),
            "tokenizer_revision": REFERENCE_TOKENIZER_REVISION,
            "score_direction": "higher",
            "threshold": REFERENCE_Z_THRESHOLD,
            "minimum_effective_tokens": REFERENCE_MINIMUM_EFFECTIVE_TOKENS,
            "public_fixture_key": True,
            "vendor_equivalent": False,
            "production_detection": False,
        },
    )


class ReferenceStatisticalDetector:
    """Common implementation for intentionally non-independent fixtures."""

    scheme: ReferenceScheme
    capability: CapabilityManifest
    threshold = REFERENCE_Z_THRESHOLD

    def __init__(self, _config: Any = None) -> None:
        pass

    def available(self) -> bool:
        return True

    def detect(self, text: str) -> DetectionEvidence:
        tokens = reference_tokenize(text)
        score = (
            _tournament_score(tokens)
            if self.scheme == "tournament-word-v1"
            else _greenlist_score(tokens, self.scheme)
        )
        details: dict[str, Any] = {
            "protocol_version": REFERENCE_DETECTOR_PROTOCOL_VERSION,
            "configuration_sha256": reference_configuration_sha256(self.scheme),
            "effective_tokens": score.effective_tokens,
            "score_direction": "higher",
            "z_score": score.value,
            score.auxiliary_name: score.auxiliary_value,
            "reference_only": True,
            "vendor_equivalent": False,
        }
        if score.effective_tokens < REFERENCE_MINIMUM_EFFECTIVE_TOKENS:
            status: DetectionStatus = "insufficient_evidence"
            reason = (
                "research reference requires at least "
                f"{REFERENCE_MINIMUM_EFFECTIVE_TOKENS} effective tokens"
            )
        else:
            status = "detected" if score.value >= self.threshold else "not_detected"
            reason = None
        details["p_value"] = _normal_survival(score.value)
        return DetectionEvidence(
            detector=self.capability.identifier,
            scheme=self.capability.schemes[0],
            status=status,
            score=score.value,
            threshold=self.threshold,
            text_characters=len(text),
            reason=reason,
            details=details,
        )


class KGWReferenceDetector(ReferenceStatisticalDetector):
    """Word-level contextual green-list fixture inspired by KGW."""

    scheme: ReferenceScheme = "kgw-word-v1"
    capability = _capability(
        scheme,
        "Synthetic word-level KGW-style research fixture; not KGW model-token detection.",
    )


class UnigramReferenceDetector(ReferenceStatisticalDetector):
    """Word-level fixed green-list fixture inspired by Unigram watermarking."""

    scheme: ReferenceScheme = "unigram-word-v1"
    capability = _capability(
        scheme,
        "Synthetic word-level Unigram research fixture; not model-token detection.",
    )


class TournamentReferenceDetector(ReferenceStatisticalDetector):
    """Synthetic multilayer tournament fixture; explicitly not SynthID Text."""

    scheme: ReferenceScheme = "tournament-word-v1"
    capability = _capability(
        scheme,
        "Synthetic multilayer tournament fixture inspired by published ideas; not SynthID Text.",
    )


_DETECTOR_CLASSES: dict[ReferenceScheme, type[ReferenceStatisticalDetector]] = {
    "kgw-word-v1": KGWReferenceDetector,
    "unigram-word-v1": UnigramReferenceDetector,
    "tournament-word-v1": TournamentReferenceDetector,
}


def reference_detector_factories() -> dict[str, type[ReferenceStatisticalDetector]]:
    """Return built-in aliases without constructing or executing a detector."""
    return {
        "reference-kgw": KGWReferenceDetector,
        "reference-kgw-v1": KGWReferenceDetector,
        "reference-unigram": UnigramReferenceDetector,
        "reference-unigram-v1": UnigramReferenceDetector,
        "reference-tournament": TournamentReferenceDetector,
        "reference-tournament-v1": TournamentReferenceDetector,
    }


def _counter_index(seed: int, position: int, size: int, label: str) -> int:
    payload = f"{seed}\x1f{position}\x1f{label}".encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big") % size


def generate_reference_text(
    scheme: ReferenceScheme,
    *,
    token_count: int = 96,
    seed: int = 1,
    watermarked: bool = True,
) -> str:
    """Generate a deterministic synthetic fixture, never model-produced prose."""
    if scheme not in _DETECTOR_CLASSES:
        raise ValueError("unknown research-reference scheme")
    if isinstance(token_count, bool) or not isinstance(token_count, int):
        raise TypeError("token_count must be an integer")
    if not 1 <= token_count <= 4096:
        raise ValueError("token_count must be between 1 and 4096")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("seed must be an integer")
    output: list[str] = []
    for position in range(token_count):
        if watermarked and scheme in ("kgw-word-v1", "unigram-word-v1"):
            context: tuple[str, ...] = (output[-1],) if output and scheme == "kgw-word-v1" else ()
            candidates = [token for token in _FIXTURE_VOCABULARY if _green(scheme, context, token)]
        elif watermarked:
            context = tuple(output[-4:])
            ranked = sorted(
                _FIXTURE_VOCABULARY,
                key=lambda token: (_tournament_value(context, token), token),
                reverse=True,
            )
            candidates = ranked[: max(1, len(ranked) // 8)]
        else:
            candidates = list(_FIXTURE_VOCABULARY)
        index = _counter_index(seed, position, len(candidates), f"{scheme}:{watermarked}")
        output.append(candidates[index])
    return " ".join(output)


@dataclass(frozen=True, repr=False)
class ReferenceGoldenVector:
    name: str
    scheme: ReferenceScheme
    text: str
    expected_status: DetectionStatus
    expected_score: float
    expected_effective_tokens: int
    configuration_sha256: str

    def __repr__(self) -> str:
        return f"ReferenceGoldenVector(name={self.name!r}, scheme={self.scheme!r}, text=<redacted>)"


@dataclass(frozen=True)
class ReferenceConformanceCase:
    name: str
    detector: str
    passed: bool
    mismatches: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReferenceConformanceReport:
    protocol_version: str
    vectors_sha256: str
    cases: tuple[ReferenceConformanceCase, ...]

    @property
    def passed(self) -> bool:
        return bool(self.cases) and all(case.passed for case in self.cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "vectors_sha256": self.vectors_sha256,
            "passed": self.passed,
            "cases": [
                {
                    "name": case.name,
                    "detector": case.detector,
                    "passed": case.passed,
                    "mismatches": list(case.mismatches),
                }
                for case in self.cases
            ],
        }


class ReferenceConformanceError(RuntimeError):
    """A content-redacting failure of packaged public reference vectors."""


def _vectors_bytes() -> bytes:
    packaged = files("dewatermark").joinpath("data").joinpath("reference-detector-vectors-v1.json")
    try:
        return packaged.read_bytes()
    except FileNotFoundError:
        source = Path(__file__).resolve().parent / "data" / "reference-detector-vectors-v1.json"
        return source.read_bytes()


def load_reference_golden_vectors() -> tuple[ReferenceGoldenVector, ...]:
    """Load and validate the checked-in public vector bundle."""
    try:
        payload = json.loads(_vectors_bytes().decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ReferenceConformanceError("reference vector bundle is invalid") from None
    if not isinstance(payload, dict) or payload.get("protocol_version") != (
        REFERENCE_DETECTOR_PROTOCOL_VERSION
    ):
        raise ReferenceConformanceError("reference vector protocol is incompatible")
    raw_vectors = payload.get("vectors")
    if not isinstance(raw_vectors, list) or not raw_vectors:
        raise ReferenceConformanceError("reference vector bundle is empty")
    vectors: list[ReferenceGoldenVector] = []
    allowed_statuses: tuple[DetectionStatus, ...] = (
        "detected",
        "not_detected",
        "insufficient_evidence",
        "unsupported",
        "configuration_mismatch",
        "detector_error",
    )
    try:
        for raw in raw_vectors:
            if not isinstance(raw, dict):
                raise TypeError
            scheme = cast(ReferenceScheme, raw["scheme"])
            if scheme not in _DETECTOR_CLASSES:
                raise ValueError
            status = cast(DetectionStatus, raw["expected_status"])
            if status not in allowed_statuses:
                raise ValueError
            vector = ReferenceGoldenVector(
                name=str(raw["name"]),
                scheme=scheme,
                text=str(raw["text"]),
                expected_status=status,
                expected_score=float(raw["expected_score"]),
                expected_effective_tokens=int(raw["expected_effective_tokens"]),
                configuration_sha256=str(raw["configuration_sha256"]),
            )
            if not vector.name or not math.isfinite(vector.expected_score):
                raise ValueError
            vectors.append(vector)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ReferenceConformanceError("reference vector bundle has an invalid case") from None
    return tuple(vectors)


def run_reference_conformance(
    schemes: Optional[Sequence[ReferenceScheme]] = None,
    *,
    absolute_tolerance: float = 1e-12,
) -> ReferenceConformanceReport:
    """Run packaged vectors and report names/field mismatches, never their text."""
    if not math.isfinite(absolute_tolerance) or absolute_tolerance < 0:
        raise ValueError("absolute_tolerance must be finite and non-negative")
    selected = set(schemes) if schemes is not None else set(_DETECTOR_CLASSES)
    if not selected or not selected.issubset(_DETECTOR_CLASSES):
        raise ValueError("schemes must contain known research-reference schemes")
    cases: list[ReferenceConformanceCase] = []
    for vector in load_reference_golden_vectors():
        if vector.scheme not in selected:
            continue
        detector = _DETECTOR_CLASSES[vector.scheme]()
        evidence = detector.detect(vector.text)
        mismatches: list[str] = []
        if evidence.status != vector.expected_status:
            mismatches.append("status")
        if evidence.score is None or not math.isclose(
            evidence.score,
            vector.expected_score,
            rel_tol=0.0,
            abs_tol=absolute_tolerance,
        ):
            mismatches.append("score")
        if evidence.details.get("effective_tokens") != vector.expected_effective_tokens:
            mismatches.append("effective_tokens")
        if evidence.details.get("configuration_sha256") != vector.configuration_sha256:
            mismatches.append("configuration_sha256")
        cases.append(
            ReferenceConformanceCase(
                name=vector.name,
                detector=detector.capability.identifier,
                passed=not mismatches,
                mismatches=tuple(sorted(mismatches)),
            )
        )
    return ReferenceConformanceReport(
        protocol_version=REFERENCE_DETECTOR_PROTOCOL_VERSION,
        vectors_sha256=hashlib.sha256(_vectors_bytes()).hexdigest(),
        cases=tuple(cases),
    )


def assert_reference_conformance(
    schemes: Optional[Sequence[ReferenceScheme]] = None,
) -> ReferenceConformanceReport:
    report = run_reference_conformance(schemes)
    if not report.passed:
        failed_count = sum(not case.passed for case in report.cases)
        raise ReferenceConformanceError(
            f"reference detector conformance failed for {failed_count} case(s)"
        )
    return report


__all__ = [
    "KGWReferenceDetector",
    "REFERENCE_DETECTOR_PROTOCOL_VERSION",
    "REFERENCE_MINIMUM_EFFECTIVE_TOKENS",
    "REFERENCE_TOKENIZER_REVISION",
    "REFERENCE_Z_THRESHOLD",
    "ReferenceConformanceCase",
    "ReferenceConformanceError",
    "ReferenceConformanceReport",
    "ReferenceGoldenVector",
    "ReferenceScheme",
    "ReferenceStatisticalDetector",
    "TournamentReferenceDetector",
    "UnigramReferenceDetector",
    "assert_reference_conformance",
    "generate_reference_text",
    "load_reference_golden_vectors",
    "reference_configuration_sha256",
    "reference_detector_factories",
    "reference_tokenize",
    "run_reference_conformance",
]
