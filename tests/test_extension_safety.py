from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import dewatermark
import dewatermark.assurance_api as assurance_api_module
import dewatermark.extension_safety as extension_safety
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
from dewatermark.quality import (
    QualityGateBinding,
    QualityGateDecision,
    QualityReport,
    evaluate_candidate,
    evaluate_quality,
)
from dewatermark.request_context import (
    RequestContext,
    ResourceBudgetExceeded,
    extension_resource_accounting,
    request_scope,
)

OFFLINE = DewatermarkConfig(local_lm_enabled=False)


@pytest.mark.parametrize(
    ("network_required", "model_download_possible", "declared", "expected"),
    [
        (True, False, "none", "network"),
        (True, True, "none", "network"),
        (False, True, "none", "model"),
        (False, True, "network", "network"),
        (False, False, "none", "none"),
    ],
)
def test_extension_resource_accounting_cannot_weaken_static_resource_flags(
    network_required, model_download_possible, declared, expected
):
    capability = CapabilityManifest(
        identifier="accounting-floor",
        kind="chunker",
        network_required=network_required,
        model_download_possible=model_download_possible,
        metadata={"resource_accounting": declared},
    )

    assert extension_resource_accounting(capability) == expected


def test_instance_identity_does_not_retain_extension_objects():
    class Extension:
        pass

    extension = Extension()
    identity = id(extension)
    extension_safety.implementation_sha256(extension, instance_sensitive=True)
    assert identity in extension_safety._instance_tokens

    del extension
    gc.collect()

    assert identity not in extension_safety._instance_tokens


def test_static_state_fingerprint_is_stable_and_one_way_across_processes():
    root = Path(__file__).parents[1]
    env = os.environ.copy()
    python_paths = [str(root / "src"), str(root / "eval")]
    if env.get("PYTHONPATH"):
        python_paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_paths)
    script = (
        "import json,sys; "
        "from dewatermark.extension_safety import static_state_sha256; "
        "print(static_state_sha256(json.load(sys.stdin)))"
    )

    def fingerprint(value):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            env=env,
            input=json.dumps(value),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return completed.stdout.strip()

    private_value = "low-entropy-private-state"
    first = fingerprint({"revision": 1, "value": private_value})
    second = fingerprint({"revision": 1, "value": private_value})
    changed = fingerprint({"revision": 2, "value": private_value})

    assert len(first) == 64
    assert first == second
    assert first != changed
    assert private_value not in first


def test_plan_rejects_custom_option_mapping_without_invoking_hooks():
    invoked: list[str] = []

    class HostileMapping:
        def __iter__(self):
            invoked.append("iter")
            raise AssertionError("custom mapping was iterated")

        def __len__(self):
            invoked.append("len")
            raise AssertionError("custom mapping length was read")

        def __getitem__(self, _key):
            invoked.append("getitem")
            raise AssertionError("custom mapping value was read")

    with pytest.raises(ValueError, match="options must be an object"):
        create_plan(
            "private source",
            "sanitize",
            options=HostileMapping(),  # type: ignore[arg-type]
            config=OFFLINE,
        )
    assert invoked == []


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


def test_zero_network_budget_blocks_every_extension_before_execution():
    invoked: list[str] = []

    class NetworkProvider:
        capability = CapabilityManifest(
            identifier="budget-network-provider", kind="transformer", network_required=True
        )

        def __init__(self, _config):
            invoked.append("provider-construction")

        def available(self):
            return True

        def rewrite(self, text, **_options):
            invoked.append("provider-text")
            return text, {}

    class NetworkScorer:
        capability = CapabilityManifest(
            identifier="budget-network-scorer", kind="scorer", network_required=True
        )

        def __init__(self, _config):
            invoked.append("scorer-construction")

        def self_information(self, _text):
            invoked.append("scorer-text")
            return []

    class NetworkDetector:
        capability = CapabilityManifest(
            identifier="budget-network-detector",
            kind="detector",
            network_required=True,
        )

        def __init__(self, _config):
            invoked.append("detector-construction")

        def available(self):
            return True

        def detect(self, _text):
            invoked.append("detector-text")
            return 0.0

    class NetworkChunker:
        capability = CapabilityManifest(
            identifier="budget-network-chunker", kind="chunker", network_required=True
        )

        def split(self, text, _limit):
            invoked.append("chunker-text")
            return [text]

    class NetworkGate:
        capability = CapabilityManifest(
            identifier="budget-network-gate", kind="quality_gate", network_required=True
        )

        def evaluate(self, _source, _candidate):
            invoked.append("gate-text")
            return QualityGateDecision(status="passed", checked_items=1)

    register_provider("budget-network-provider", NetworkProvider)
    register_provider("budget-network-scorer", NetworkScorer)
    register_detector("budget-network-detector", NetworkDetector)
    base = replace(OFFLINE, allow_remote_processing=True, max_remote_calls=0)
    try:
        result = dewatermark.remove(
            "private source",
            mode="full",
            config=replace(base, rewriter_provider="budget-network-provider"),
        )
        assert result.report.transformation_status == "failed"

        with pytest.raises(ResourceBudgetExceeded):
            dewatermark.inspect("private source", "budget-network-detector", config=base)

        scorer_config = replace(base, scorer_provider="budget-network-scorer")
        with request_scope(RequestContext.from_config(scorer_config)):
            with pytest.raises(scoring.ScorerUnavailable):
                scoring.self_information("private source", scorer_config)

        chunker_config = replace(base, chunker=NetworkChunker())
        with request_scope(RequestContext.from_config(chunker_config)):
            with pytest.raises(ResourceBudgetExceeded):
                split_for_config("private source", chunker_config)

        gate_config = replace(
            base,
            quality_gates=(QualityGateBinding(NetworkGate()),),
        )
        with request_scope(RequestContext.from_config(gate_config)):
            gate_report = evaluate_candidate("private source", "private candidate", gate_config)
        assert not gate_report.passed
        assert gate_report.gate_outcomes[-1].status == "error"
    finally:
        unregister_provider("budget-network-provider")
        unregister_provider("budget-network-scorer")
        unregister_detector("budget-network-detector")
    assert invoked == []


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


def test_mutable_registered_provider_state_invalidates_reviewed_plan():
    invoked: list[str] = []

    class Base:
        replacement = "before"

        def rewrite(self, _text, **_options):
            invoked.append(self.replacement)
            return self.replacement, {}

    class Provider(Base):
        capability = CapabilityManifest(identifier="state-bound", kind="transformer")

        def __init__(self, _config):
            pass

        def available(self):
            return True

    register_provider("state-bound", Provider)
    config = replace(OFFLINE, rewriter_provider="state-bound")
    try:
        planned = create_plan("private source", "full", config=config)
        Base.replacement = "after"
        with pytest.raises(PlanMismatchError, match="no longer available"):
            apply_plan(
                "private source",
                planned["plan_digest"],
                "full",
                consent=True,
                config=config,
            )
        with pytest.raises(dewatermark.ConfigurationError, match="identity changed"):
            create_plan("private source", "full", config=config)

        register_provider("state-bound", Provider, replace=True)
        replacement_plan = create_plan("private source", "full", config=config)
        assert replacement_plan["plan_digest"] != planned["plan_digest"]
    finally:
        unregister_provider("state-bound")
    assert invoked == []


def test_registered_factory_closure_and_defaults_are_plan_bound():
    invoked: list[str] = []
    closure_state = {"replacement": "before"}
    default_state = {"enabled": False}

    class Instance:
        capability = CapabilityManifest(identifier="closure-bound", kind="transformer")

        def available(self):
            return True

        def rewrite(self, _text, **_options):
            invoked.append(closure_state["replacement"])
            return closure_state["replacement"], {}

    def factory(_config, state=default_state):
        if state["enabled"]:
            invoked.append("constructed")
        return Instance()

    factory.capability = Instance.capability  # type: ignore[attr-defined]
    register_provider("closure-bound", factory)
    config = replace(OFFLINE, rewriter_provider="closure-bound")
    try:
        planned = create_plan("private source", "full", config=config)
        closure_state["replacement"] = "after"
        default_state["enabled"] = True
        with pytest.raises(PlanMismatchError):
            apply_plan(
                "private source",
                planned["plan_digest"],
                "full",
                consent=True,
                config=config,
            )
    finally:
        unregister_provider("closure-bound")
    assert invoked == []


def test_mutable_registered_scorer_and_detector_state_invalidates_plans():
    constructed: list[str] = []

    class Scorer:
        capability = CapabilityManifest(identifier="state-scorer", kind="scorer")
        armed = False

        def __init__(self, _config):
            constructed.append("scorer")

    class Detector:
        capability = CapabilityManifest(identifier="state-detector", kind="detector")
        armed = False

        def __init__(self, _config):
            constructed.append("detector")

    register_provider("state-scorer", Scorer)
    register_detector("state-detector", Detector)
    scorer_config = replace(OFFLINE, scorer_provider="state-scorer")
    try:
        scorer_plan = create_plan("private source", "sira", config=scorer_config)
        detector_plan = create_plan(
            "private source", "sanitize", detector="state-detector", config=OFFLINE
        )
        Scorer.armed = True
        Detector.armed = True
        with pytest.raises(PlanMismatchError):
            apply_plan(
                "private source",
                scorer_plan["plan_digest"],
                "sira",
                consent=True,
                config=scorer_config,
            )
        with pytest.raises(PlanMismatchError):
            apply_plan(
                "private source",
                detector_plan["plan_digest"],
                "sanitize",
                detector="state-detector",
                consent=True,
                config=OFFLINE,
            )
    finally:
        unregister_provider("state-scorer")
        unregister_detector("state-detector")
    assert constructed == []


def test_method_and_nested_manifest_mutation_requires_reregistration():
    manifest = CapabilityManifest(
        identifier="method-bound",
        kind="transformer",
        metadata={"configuration": {"revision": "one"}},
    )

    class Provider:
        capability = manifest

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text, {}

    register_provider("method-bound", Provider)
    config = replace(OFFLINE, rewriter_provider="method-bound")
    try:
        method_plan = create_plan("private source", "full", config=config)

        def changed_rewrite(self, _text, **_options):
            return "changed", {}

        Provider.rewrite = changed_rewrite
        with pytest.raises(PlanMismatchError):
            apply_plan(
                "private source",
                method_plan["plan_digest"],
                "full",
                consent=True,
                config=config,
            )

        register_provider("method-bound", Provider, replace=True)
        metadata_plan = create_plan("private source", "full", config=config)
        manifest.metadata["configuration"]["revision"] = "two"
        with pytest.raises(PlanMismatchError):
            apply_plan(
                "private source",
                metadata_plan["plan_digest"],
                "full",
                consent=True,
                config=config,
            )
    finally:
        unregister_provider("method-bound")


@pytest.mark.parametrize(
    ("kind", "mode", "config_field"),
    [
        ("quality_gate", "full", "quality_gate"),
        ("semantic_scorer", "full", "semantic_scorer"),
        ("chunker", "sira", "chunker"),
    ],
)
def test_direct_extension_instance_state_is_plan_bound(kind, mode, config_field):
    class Extension:
        capability = CapabilityManifest(identifier=f"state-{kind}", kind=kind)

        def __init__(self):
            self.armed = False

    extension = Extension()
    values = {config_field: extension}
    if kind == "semantic_scorer":
        values["quality_min_semantic_score"] = 0.5
    config = replace(OFFLINE, **values)
    planned = create_plan("private source", mode, config=config)
    extension.armed = True
    assert (
        create_plan("private source", mode, config=config)["plan_digest"] != planned["plan_digest"]
    )
    with pytest.raises(PlanMismatchError):
        apply_plan(
            "private source",
            planned["plan_digest"],
            mode,
            consent=True,
            config=config,
        )


def test_apply_time_mutation_is_rejected_before_extension_text_access(monkeypatch):
    invoked: list[str] = []

    class Provider:
        capability = CapabilityManifest(identifier="stable-provider", kind="transformer")

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text, {}

    class Gate:
        capability = CapabilityManifest(identifier="guarded-gate", kind="quality_gate")

        def __init__(self):
            self.armed = False

        def evaluate(self, _source, _candidate):
            invoked.append("armed" if self.armed else "safe")
            return QualityReport(True, 1.0, 1.0)

    gate = Gate()
    register_provider("stable-provider", Provider)
    config = replace(OFFLINE, rewriter_provider="stable-provider", quality_gate=gate)
    planned = create_plan("private source", "full", config=config)
    actual_remove = assurance_api_module.remove

    def mutate_then_remove(*args, **kwargs):
        gate.armed = True
        return actual_remove(*args, **kwargs)

    monkeypatch.setattr(assurance_api_module, "remove", mutate_then_remove)
    try:
        with pytest.raises(PlanMismatchError, match="changed before execution"):
            apply_plan(
                "private source",
                planned["plan_digest"],
                "full",
                consent=True,
                config=config,
            )
    finally:
        unregister_provider("stable-provider")
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


@pytest.mark.parametrize(
    "group",
    [registry.ENTRY_POINT_GROUP, registry.DETECTOR_ENTRY_POINT_GROUP],
)
def test_entry_point_discovery_rejects_case_normalized_name_collisions(monkeypatch, group):
    class EntryPoint:
        def __init__(self, name):
            self.name = name

        def load(self):
            raise AssertionError("collision discovery must not load plugin code")

    class EntryPoints:
        def select(self, *, group):
            return [EntryPoint("Collision"), EntryPoint("collision")]

    monkeypatch.setattr(registry.metadata, "entry_points", lambda: EntryPoints())

    with pytest.raises(dewatermark.ConfigurationError, match="discovery failed"):
        registry._entry_points(group)


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
    applied = apply_plan(
        "a\u200bb",
        planned["plan_digest"],
        "sanitize",
        consent=True,
        config=config,
    )
    result = dewatermark.remove("a\u200bb", mode="sanitize", config=config)
    assert planned["execution"]["available"] is True
    assert applied["result"]["cleaned_text"] == "ab"
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
