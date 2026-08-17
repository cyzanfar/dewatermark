from __future__ import annotations

from dataclasses import replace

import pytest

import dewatermark
import dewatermark.providers as registry
import dewatermark.scoring as scoring
from dewatermark import CapabilityManifest, DewatermarkConfig
from dewatermark.assurance_api import (
    PlanMismatchError,
    apply_plan,
    create_plan,
    inspect_text,
    verify_text,
)
from dewatermark.chunking import split_for_config
from dewatermark.models import DetectionEvidence
from dewatermark.providers import (
    register_detector,
    register_provider,
    unregister_detector,
    unregister_provider,
)
from dewatermark.quality import QualityReport, evaluate_candidate, evaluate_quality

OFFLINE = DewatermarkConfig(local_lm_enabled=False)


def test_every_text_receiver_requires_a_static_manifest():
    calls: list[str] = []

    class Gate:
        def evaluate(self, _source, _candidate):
            calls.append("gate")
            return QualityReport(True, 1.0, 1.0)

    class Semantic:
        def __call__(self, _source, _candidate):
            calls.append("semantic")
            return 1.0

    class Chunker:
        def split(self, text, _limit):
            calls.append("chunker")
            return [text]

    class Detector:
        def detect(self, _text):
            calls.append("detector")
            return 0.0

    with pytest.raises(dewatermark.ConfigurationError):
        evaluate_candidate("source", "candidate", replace(OFFLINE, quality_gate=Gate()))
    with pytest.raises(dewatermark.ConfigurationError):
        evaluate_quality(
            "source",
            "candidate",
            semantic_scorer=Semantic(),
            min_semantic_score=0.5,
        )
    with pytest.raises(dewatermark.ConfigurationError):
        split_for_config("source", replace(OFFLINE, chunker=Chunker()))
    with pytest.raises(dewatermark.ConfigurationError):
        dewatermark.inspect("source", Detector(), config=OFFLINE)
    with pytest.raises(dewatermark.ConfigurationError):
        register_provider("missing-manifest", lambda _cfg: object())
    assert calls == []


def test_declared_permissions_and_secrets_fail_before_construction():
    constructed: list[str] = []

    class NetworkProvider:
        capability = CapabilityManifest(
            identifier="network-provider", kind="transformer", network_required=True
        )

        def __init__(self, _config):
            constructed.append("network")

    class SecretProvider:
        capability = CapabilityManifest(
            identifier="secret-provider", kind="transformer", requires_secret=True
        )

        def __init__(self, _config):
            constructed.append("secret")

    register_provider("network-denied", NetworkProvider)
    register_provider("secret-denied", SecretProvider)
    try:
        for name in ("network-denied", "secret-denied"):
            result = dewatermark.remove(
                "private source",
                mode="full",
                config=replace(OFFLINE, rewriter_provider=name),
            )
            assert result.report.transformation_status == "failed"
    finally:
        unregister_provider("network-denied")
        unregister_provider("secret-denied")
    assert constructed == []


def test_factories_receive_credential_stripped_config():
    observed: list[tuple[str, object, object]] = []

    class Provider:
        capability = CapabilityManifest(identifier="safe-provider", kind="transformer")

        def __init__(self, config):
            observed.append(("provider", config.fireworks_api_key, config.llm_api_key))

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text.replace("large", "broad"), {"strategy": "fixture"}

    class Scorer:
        capability = CapabilityManifest(identifier="safe-scorer", kind="scorer")

        def __init__(self, config):
            observed.append(("scorer", config.fireworks_api_key, config.llm_api_key))

        def available(self):
            return True

        def self_information(self, _text):
            return []

    register_provider("credential-projection", Provider)
    register_provider("credential-projection-scorer", Scorer)
    try:
        config = replace(
            OFFLINE,
            rewriter_provider="credential-projection",
            scorer_provider="credential-projection-scorer",
            fireworks_api_key="fw-secret",
            llm_api_key="llm-secret",
        )
        assert dewatermark.remove("A large change.", mode="full", config=config).cleaned_text
        assert scoring.self_information("private", config) == []
    finally:
        unregister_provider("credential-projection")
        unregister_provider("credential-projection-scorer")
    assert observed == [("provider", None, None), ("scorer", None, None)]


def test_factory_and_instance_manifests_must_match_before_text():
    rewritten: list[str] = []
    declared = CapabilityManifest(identifier="declared", kind="transformer")

    class Instance:
        capability = CapabilityManifest(identifier="different", kind="transformer")

        def available(self):
            return True

        def rewrite(self, text, **_options):
            rewritten.append(text)
            return text, {}

    def factory(_config):
        return Instance()

    factory.capability = declared  # type: ignore[attr-defined]
    register_provider("mismatched-instance", factory)
    try:
        result = dewatermark.remove(
            "private source",
            mode="full",
            config=replace(OFFLINE, rewriter_provider="mismatched-instance"),
        )
    finally:
        unregister_provider("mismatched-instance")
    assert result.report.transformation_status == "failed"
    assert rewritten == []


def test_registry_revision_rejects_same_manifest_replacement():
    invoked: list[str] = []
    shared_manifest = CapabilityManifest(identifier="stable-name", kind="transformer")

    class First:
        capability = shared_manifest

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text, {}

    class Replacement(First):
        capability = shared_manifest

        def rewrite(self, text, **_options):
            invoked.append(text)
            return text, {}

    register_provider("replace-me", First)
    config = replace(OFFLINE, rewriter_provider="replace-me")
    try:
        planned = create_plan("private source", "full", config=config)
        register_provider("replace-me", Replacement, replace=True)
        with pytest.raises(PlanMismatchError):
            apply_plan(
                "private source",
                planned["plan_digest"],
                "full",
                consent=True,
                config=config,
            )
    finally:
        unregister_provider("replace-me")
    assert invoked == []


def test_agent_inspect_and_verify_do_not_load_untrusted_entry_points(monkeypatch):
    loaded: list[bool] = []

    class EntryPoint:
        def load(self):
            loaded.append(True)
            raise AssertionError("plugin code was loaded")

    monkeypatch.setattr(registry, "_detector_entry_points", {"unloaded": EntryPoint()})
    with pytest.raises(ValueError, match="static capability manifest"):
        inspect_text("private source", "unloaded", config=OFFLINE)
    with pytest.raises(ValueError, match="static capability manifest"):
        verify_text("private source", "candidate", "unloaded", config=OFFLINE)
    assert loaded == []


def test_provider_and_paraphrase_paths_do_not_run_configured_scorer():
    scored: list[str] = []

    class Scorer:
        capability = CapabilityManifest(identifier="unused-scorer", kind="scorer")

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def self_information(self, text):
            scored.append(text)
            return []

    class Provider:
        capability = CapabilityManifest(identifier="rewrite-only", kind="transformer")

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text, {"strategy": "fixture"}

    register_provider("unused-scorer", Scorer)
    register_provider("rewrite-only", Provider)
    try:
        dewatermark.remove(
            "private source",
            mode="full",
            config=replace(
                OFFLINE,
                scorer_provider="unused-scorer",
                rewriter_provider="rewrite-only",
            ),
        )
        dewatermark.remove(
            "private source",
            mode="paraphrase",
            config=replace(OFFLINE, scorer_provider="unused-scorer"),
        )
    finally:
        unregister_provider("unused-scorer")
        unregister_provider("rewrite-only")
    assert scored == []


def test_untrusted_extension_metadata_and_reasons_are_redacted():
    source = "private-source-sentinel"

    class Provider:
        capability = CapabilityManifest(identifier="metadata-provider", kind="transformer")

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text, {
                "note": source,
                "strategy": "fixture",
                "nan": float("nan"),
                "positive_infinity": float("inf"),
            }

    class Gate:
        capability = CapabilityManifest(identifier="metadata-gate", kind="quality_gate")

        def evaluate(self, _source, _candidate):
            return QualityReport(False, 1.0, 1.0, reasons=[source], structure_errors=[source])

    register_provider("metadata-provider", Provider)
    try:
        result = dewatermark.remove(
            source,
            mode="full",
            config=replace(OFFLINE, rewriter_provider="metadata-provider"),
        )
    finally:
        unregister_provider("metadata-provider")
    provider_stage = next(stage for stage in result.stages if stage.name == "provider")
    assert provider_stage["note"] == "<redacted>"
    assert provider_stage["nan"] == "<redacted>"
    assert provider_stage["positive_infinity"] == "<redacted>"
    report = evaluate_candidate(source, source, replace(OFFLINE, quality_gate=Gate()))
    assert source not in repr(report)


def test_sanitize_ignores_unused_unmanifested_extensions():
    class Unmanifested:
        pass

    config = replace(
        OFFLINE,
        quality_gate=Unmanifested(),
        semantic_scorer=Unmanifested(),  # type: ignore[arg-type]
        chunker=Unmanifested(),
    )
    planned = create_plan("a\u200bb", "sanitize", config=config)
    result = dewatermark.remove("a\u200bb", mode="sanitize", config=config)
    assert planned["execution"]["available"] is True
    assert result.cleaned_text == "ab"


def test_detector_factory_gets_no_secrets_and_instance_must_match():
    observed: list[tuple[object, object]] = []
    detected: list[str] = []

    class Detector:
        capability = CapabilityManifest(identifier="safe-detector", kind="detector")

        def __init__(self, config):
            observed.append((config.fireworks_api_key, config.llm_api_key))

        def available(self):
            return True

        def detect(self, text):
            detected.append(text)
            return DetectionEvidence(
                detector="safe-detector",
                status="not_detected",
                text_characters=len(text),
            )

    register_detector("safe-detector", Detector)
    try:
        config = replace(OFFLINE, fireworks_api_key="fw", llm_api_key="llm")
        dewatermark.inspect("private", "safe-detector", config=config)
    finally:
        unregister_detector("safe-detector")
    assert observed == [(None, None)]
    assert detected == ["private"]


def test_detector_factory_type_error_is_not_retried_without_safe_config():
    constructed: list[object] = []

    def factory(config):
        constructed.append(config)
        raise TypeError("fixture constructor failure")

    factory.capability = CapabilityManifest(  # type: ignore[attr-defined]
        identifier="one-shot-detector", kind="detector"
    )
    register_detector("one-shot-detector", factory)
    try:
        with pytest.raises(TypeError, match="fixture constructor failure"):
            dewatermark.inspect("private", "one-shot-detector", config=OFFLINE)
    finally:
        unregister_detector("one-shot-detector")
    assert len(constructed) == 1
    assert constructed[0].fireworks_api_key is None
    assert constructed[0].llm_api_key is None
