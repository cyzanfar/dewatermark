from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest
from jsonschema import Draft202012Validator

import dewatermark
import dewatermark.profiles as profile_module
from dewatermark.cli import EXIT_OK, main
from dewatermark.command_detector import (
    command_detector_manifest,
    make_command_detector_factory,
)
from dewatermark.config import DewatermarkConfig
from dewatermark.models import CapabilityManifest
from dewatermark.optimizer import SearchLimits, SignalSpan
from dewatermark.profiles import (
    MitigationProfileConsentError,
    MitigationProfileError,
    build_mitigation_profile,
    inspect_mitigation_profile,
    load_mitigation_profile,
    mitigate_with_profile,
    mitigation_profile_sha256,
    quality_policy_sha256,
    validate_mitigation_profile,
)
from dewatermark.providers import (
    register_detector,
    register_provider,
    unregister_detector,
    unregister_provider,
)
from dewatermark.quality import QualityGateBinding, QualityGateDecision

SOURCE = "alpha blue beta blue gamma blue delta epsilon zeta eta theta"
SCHEME = "profile-test-v1"
TARGET = "c" * 64


def _write_profile_command(path, *, implementation: str) -> None:
    score_expression = (
        "float(text.count('blue'))"
        if implementation == "primary"
        else "float(sum(token == 'blue' for token in text.split()))"
    )
    path.write_text(
        "import json,sys\n"
        "from pathlib import Path\n"
        "request=json.load(sys.stdin)\n"
        "text=request['text']\n"
        f"score={score_expression}\n"
        "status='detected' if score>=2.0 else 'not_detected'\n"
        "Path(sys.argv[1]).write_text('invoked',encoding='utf-8')\n"
        "json.dump({'protocol_version':'1.1','action':'detect.result',"
        "'detector':request['detector'],'scheme':'profile-test-v1',"
        "'status':status,'score':score,'threshold':2.0,"
        "'score_direction':'higher','threshold_operator':'>=',"
        "'effective_tokens':len(text.split()),"
        "'configuration_sha256':request['configuration_sha256'],"
        "'p_value':0.001 if status=='detected' else 0.8},sys.stdout)\n",
        encoding="utf-8",
    )


def _command_profile(
    *,
    primary_name: str = "profile-command-primary",
    verifier_name: str = "profile-command-verifier",
) -> dewatermark.MitigationProfile:
    return build_mitigation_profile(
        "operator/profile-command-test-v1",
        scheme=SCHEME,
        watermark_target_sha256=TARGET,
        key_id="opaque-command-profile-key-id",
        primary_detector=primary_name,
        verifier_detectors=[verifier_name],
        strategies=[("profile-strategy", {"replacements": 2})],
        protocol_sha256="d" * 64,
        limits=SearchLimits(
            max_rounds=1,
            beam_width=2,
            max_candidates=4,
            max_transform_calls=4,
            max_detector_queries=16,
            max_candidate_characters=10_000,
            max_verification_candidates=4,
        ),
    )


def _profile_command_factory(
    script,
    marker,
    *,
    identifier: str,
    implementation_sha256: str,
):
    configuration_sha256 = hashlib.sha256(identifier.encode("ascii")).hexdigest()
    capability = command_detector_manifest(
        identifier=identifier,
        schemes=(SCHEME,),
        configuration_sha256=configuration_sha256,
        implementation_sha256=implementation_sha256,
        threshold=2.0,
        threshold_operator=">=",
        watermark_target_sha256=TARGET,
        calibrated=True,
        independent=True,
    )
    return make_command_detector_factory(
        (sys.executable, str(script), str(marker)),
        capability,
        timeout_seconds=2.0,
    )


def _capability(identifier: str) -> CapabilityManifest:
    return CapabilityManifest(
        identifier=identifier,
        kind="detector",
        schemes=(SCHEME,),
        calibrated=True,
        independent=True,
        metadata={
            "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
            "resource_accounting": "none",
            "score_direction": "higher",
            "threshold": 2.0,
            "threshold_operator": ">=",
            "watermark_target_sha256": TARGET,
        },
    )


class ProfilePrimary:
    capability = _capability("profile-primary")

    def __init__(self, _config=None):
        pass

    def available(self):
        return True

    def detect(self, text):
        score = float(text.count("blue"))
        return {
            "scheme": SCHEME,
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "threshold_operator": ">=",
            "configuration_sha256": self.capability.metadata["configuration_sha256"],
            "p_value": 0.001 if score >= 2 else 0.8,
        }


class ProfileVerifier:
    capability = _capability("profile-verifier")

    def __init__(self, _config=None):
        pass

    def available(self):
        return True

    def detect(self, text):
        score = float(sum(token == "blue" for token in text.split()))
        return {
            "scheme": SCHEME,
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
            "threshold_operator": ">=",
            "configuration_sha256": self.capability.metadata["configuration_sha256"],
            "p_value": 0.001 if score >= 2 else 0.8,
        }


class ProfileStrategy:
    capability = CapabilityManifest(
        identifier="profile-strategy",
        kind="transformer",
        metadata={"resource_accounting": "none"},
    )

    def __init__(self, _config=None):
        pass

    def available(self):
        return True

    def generate(self, text, *, context, replacements=2):
        assert context.random_seed == 13
        return [text.replace("blue", "teal", replacements)]


class ProfileNestedStrategy:
    capability = CapabilityManifest(
        identifier="profile-nested-strategy",
        kind="transformer",
        metadata={"resource_accounting": "none"},
    )

    def __init__(self, _config=None):
        pass

    def available(self):
        return True

    def generate(self, text, *, context, nested):
        assert context.random_seed == 13
        assert type(nested) is dict
        assert type(nested["replacements"]) is list
        return [text.replace("blue", "teal", nested["replacements"][0])]


@pytest.fixture
def registered_profile_components():
    register_detector("profile-primary", ProfilePrimary)
    register_detector("profile-verifier", ProfileVerifier)
    register_provider("profile-strategy", ProfileStrategy)
    register_provider("profile-nested-strategy", ProfileNestedStrategy)
    try:
        yield
    finally:
        unregister_detector("profile-primary")
        unregister_detector("profile-verifier")
        unregister_provider("profile-strategy")
        unregister_provider("profile-nested-strategy")


def _profile(
    *,
    protocol_sha256: str = "d" * 64,
    config: DewatermarkConfig | None = None,
) -> dewatermark.MitigationProfile:
    return build_mitigation_profile(
        "operator/profile-test-v1",
        scheme=SCHEME,
        watermark_target_sha256=TARGET,
        key_id="opaque-research-key-id-v1",
        primary_detector="profile-primary",
        verifier_detectors=["profile-verifier"],
        strategies=[("profile-strategy", {"replacements": 2})],
        protocol_sha256=protocol_sha256,
        config=config,
        limits=SearchLimits(
            max_rounds=1,
            beam_width=2,
            max_candidates=4,
            max_transform_calls=4,
            max_detector_queries=16,
            max_candidate_characters=10_000,
            max_verification_candidates=4,
        ),
    )


class ProfileRequiredGate:
    capability = CapabilityManifest(
        identifier="profile-required-gate",
        kind="quality_gate",
        metadata={"gate_type": "external", "resource_accounting": "none"},
    )

    def __init__(self, *, allow: bool) -> None:
        self.allow = allow

    def evaluate(self, _source: str, _candidate: str) -> QualityGateDecision:
        return QualityGateDecision(
            status="passed" if self.allow else "failed",
            checked_items=1,
            reason_code="gate_passed" if self.allow else "gate_failed",
        )


def test_profile_build_validate_schema_inspect_and_execute(registered_profile_components):
    profile = _profile()
    serialized = profile.to_dict()
    Draft202012Validator.check_schema(dewatermark.mitigation_profile_schema())
    Draft202012Validator(dewatermark.mitigation_profile_schema()).validate(serialized)
    assert mitigation_profile_sha256(serialized) == profile.profile_sha256

    report = inspect_mitigation_profile(profile)
    assert report["side_effect_free"] is True
    assert report["static_bindings_ready"] is True
    assert report["runtime_availability"] == "not_checked"
    assert report["evidence_status"] == "protocol_only_no_results"

    with pytest.raises(MitigationProfileConsentError):
        mitigate_with_profile(SOURCE, profile, consent=False)
    result = mitigate_with_profile(SOURCE, profile, consent=True)
    assert result.status == "verified"
    assert result.cleaned_text == SOURCE.replace("blue", "teal", 2)
    assert result.receipt.profile_id == profile.profile_id
    assert result.receipt.profile_sha256 == profile.profile_sha256
    assert "evidence_bundle_id" not in result.receipt.to_dict()
    Draft202012Validator(dewatermark.mitigation_result_schema()).validate(result.to_dict())


def test_profile_build_rejects_an_existing_unparsed_launcher_shape(
    registered_profile_components, tmp_path
):
    launcher = tmp_path / "sh"
    script = tmp_path / "detector.sh"
    launcher.write_bytes(b"reviewed launcher fixture")
    script.write_text("reviewed detector fixture\n", encoding="utf-8")
    name = "profile-unparsed-launcher"
    manifest = command_detector_manifest(
        identifier=name,
        schemes=(SCHEME,),
        configuration_sha256="a" * 64,
        implementation_sha256="b" * 64,
        threshold=2.0,
        threshold_operator=">=",
        watermark_target_sha256=TARGET,
        calibrated=True,
    )
    register_detector(
        name,
        make_command_detector_factory((str(launcher), str(script)), manifest),
    )
    try:
        with pytest.raises(MitigationProfileError):
            build_mitigation_profile(
                "operator/profile-unparsed-launcher-v1",
                scheme=SCHEME,
                watermark_target_sha256=TARGET,
                key_id="opaque-launcher-test-key-id",
                primary_detector=name,
                verifier_detectors=["profile-verifier"],
                strategies=[("profile-strategy", {"replacements": 2})],
                protocol_sha256="d" * 64,
            )
    finally:
        unregister_detector(name)


def test_profile_rejects_tampering_private_values_and_ambiguous_json(
    registered_profile_components, tmp_path
):
    value = _profile().to_dict()
    value["random_seed"] += 1
    with pytest.raises(MitigationProfileError, match="content digest"):
        validate_mitigation_profile(value)

    value = _profile().to_dict()
    value["profile_id"] = "sk-live-PRIVATEPROFILECREDENTIAL123456789"
    value["profile_sha256"] = mitigation_profile_sha256({**value, "profile_id": "safe-placeholder"})
    with pytest.raises(MitigationProfileError) as error:
        validate_mitigation_profile(value)
    assert "PRIVATEPROFILECREDENTIAL" not in str(error.value)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(MitigationProfileError, match="duplicate"):
        load_mitigation_profile(duplicate)

    misleading_policy = _profile().to_dict()
    misleading_policy["quality_policy"]["policy_id"] = "perfect-semantic-review-v9"
    misleading_policy["profile_sha256"] = mitigation_profile_sha256(misleading_policy)
    with pytest.raises(MitigationProfileError, match="policy id is unsupported"):
        validate_mitigation_profile(misleading_policy)


def test_profile_rejects_aliases_of_the_same_detector_implementation(
    registered_profile_components,
):
    register_detector("profile-primary-alias", ProfilePrimary)
    try:
        with pytest.raises(MitigationProfileError, match="implementations must be distinct"):
            build_mitigation_profile(
                "operator/profile-alias-test-v1",
                scheme=SCHEME,
                watermark_target_sha256=TARGET,
                key_id="opaque-research-key-id-v1",
                primary_detector="profile-primary",
                verifier_detectors=["profile-primary-alias"],
                strategies=[("profile-strategy", {"replacements": 2})],
                protocol_sha256="d" * 64,
            )
    finally:
        unregister_detector("profile-primary-alias")


def test_profile_binds_and_executes_distinct_exact_command_factories(
    registered_profile_components, tmp_path
):
    primary_script = tmp_path / "profile_primary_command.py"
    verifier_script = tmp_path / "profile_verifier_command.py"
    primary_marker = tmp_path / "primary-invoked"
    verifier_marker = tmp_path / "verifier-invoked"
    _write_profile_command(primary_script, implementation="primary")
    _write_profile_command(verifier_script, implementation="verifier")
    primary_factory = _profile_command_factory(
        primary_script,
        primary_marker,
        identifier="profile-command-primary",
        implementation_sha256="1" * 64,
    )
    verifier_factory = _profile_command_factory(
        verifier_script,
        verifier_marker,
        identifier="profile-command-verifier",
        implementation_sha256="2" * 64,
    )
    register_detector("profile-command-primary", primary_factory)
    register_detector("profile-command-verifier", verifier_factory)
    try:
        profile = _command_profile()
        value = profile.to_dict()
        assert (
            value["primary"]["implementation_sha256"]
            == value["verifiers"][0]["implementation_sha256"]
        )
        assert value["primary"]["external_implementation_sha256"] == "1" * 64
        assert value["verifiers"][0]["external_implementation_sha256"] == "2" * 64
        assert (
            value["primary"]["command_code_sha256"] != value["verifiers"][0]["command_code_sha256"]
        )
        assert (
            value["primary"]["command_code_raw_sha256"]
            != value["verifiers"][0]["command_code_raw_sha256"]
        )
        Draft202012Validator(dewatermark.mitigation_profile_schema()).validate(value)

        report = inspect_mitigation_profile(profile)
        assert report["side_effect_free"] is True
        assert report["static_bindings_ready"] is True
        assert not primary_marker.exists()
        assert not verifier_marker.exists()

        result = mitigate_with_profile(SOURCE, profile, consent=True)
        assert result.status == "verified"
        assert result.cleaned_text == SOURCE.replace("blue", "teal", 2)
        assert primary_marker.exists()
        assert verifier_marker.exists()
    finally:
        unregister_detector("profile-command-primary")
        unregister_detector("profile-command-verifier")


def test_profile_rejects_same_command_code_even_with_distinct_public_contracts(
    registered_profile_components, tmp_path
):
    shared_script = tmp_path / "profile_shared_command.py"
    _write_profile_command(shared_script, implementation="primary")
    register_detector(
        "profile-command-primary",
        _profile_command_factory(
            shared_script,
            tmp_path / "alias-primary-invoked",
            identifier="profile-command-primary",
            implementation_sha256="1" * 64,
        ),
    )
    register_detector(
        "profile-command-verifier",
        _profile_command_factory(
            shared_script,
            tmp_path / "alias-verifier-invoked",
            identifier="profile-command-verifier",
            implementation_sha256="2" * 64,
        ),
    )
    try:
        with pytest.raises(MitigationProfileError, match="implementations must be distinct"):
            _command_profile()
    finally:
        unregister_detector("profile-command-primary")
        unregister_detector("profile-command-verifier")


def test_profile_rejects_same_external_command_implementation_commitment(
    registered_profile_components, tmp_path
):
    primary_script = tmp_path / "profile_commitment_primary.py"
    verifier_script = tmp_path / "profile_commitment_verifier.py"
    _write_profile_command(primary_script, implementation="primary")
    _write_profile_command(verifier_script, implementation="verifier")
    shared_commitment = "1" * 64
    register_detector(
        "profile-command-primary",
        _profile_command_factory(
            primary_script,
            tmp_path / "commitment-primary-invoked",
            identifier="profile-command-primary",
            implementation_sha256=shared_commitment,
        ),
    )
    register_detector(
        "profile-command-verifier",
        _profile_command_factory(
            verifier_script,
            tmp_path / "commitment-verifier-invoked",
            identifier="profile-command-verifier",
            implementation_sha256=shared_commitment,
        ),
    )
    try:
        with pytest.raises(MitigationProfileError, match="implementations must be distinct"):
            _command_profile()
    finally:
        unregister_detector("profile-command-primary")
        unregister_detector("profile-command-verifier")


def test_profile_detects_command_script_drift_before_text(registered_profile_components, tmp_path):
    primary_script = tmp_path / "profile_drift_primary.py"
    verifier_script = tmp_path / "profile_drift_verifier.py"
    primary_marker = tmp_path / "drift-primary-invoked"
    verifier_marker = tmp_path / "drift-verifier-invoked"
    _write_profile_command(primary_script, implementation="primary")
    _write_profile_command(verifier_script, implementation="verifier")
    register_detector(
        "profile-command-primary",
        _profile_command_factory(
            primary_script,
            primary_marker,
            identifier="profile-command-primary",
            implementation_sha256="1" * 64,
        ),
    )
    register_detector(
        "profile-command-verifier",
        _profile_command_factory(
            verifier_script,
            verifier_marker,
            identifier="profile-command-verifier",
            implementation_sha256="2" * 64,
        ),
    )
    try:
        profile = _command_profile()
        primary_script.write_text(
            primary_script.read_text(encoding="utf-8").replace(
                "text.count('blue')", "text.count('teal')"
            ),
            encoding="utf-8",
        )

        report = inspect_mitigation_profile(profile)
        primary_check = next(
            item for item in report["checks"] if item["name"] == "profile-command-primary"
        )
        assert report["static_bindings_ready"] is False
        assert primary_check["status"] == "mismatch"
        assert "command_code_sha256" in primary_check["mismatch_fields"]
        assert "command_code_raw_sha256" in primary_check["mismatch_fields"]
        with pytest.raises(MitigationProfileError, match="components"):
            mitigate_with_profile(SOURCE, profile, consent=True)
        assert not primary_marker.exists()
        assert not verifier_marker.exists()
    finally:
        unregister_detector("profile-command-primary")
        unregister_detector("profile-command-verifier")


def test_profile_exact_raw_pin_detects_comment_only_drift(registered_profile_components, tmp_path):
    primary_script = tmp_path / "profile_comment_drift_primary.py"
    verifier_script = tmp_path / "profile_comment_drift_verifier.py"
    primary_marker = tmp_path / "comment-drift-primary-invoked"
    verifier_marker = tmp_path / "comment-drift-verifier-invoked"
    _write_profile_command(primary_script, implementation="primary")
    _write_profile_command(verifier_script, implementation="verifier")
    register_detector(
        "profile-command-primary",
        _profile_command_factory(
            primary_script,
            primary_marker,
            identifier="profile-command-primary",
            implementation_sha256="1" * 64,
        ),
    )
    register_detector(
        "profile-command-verifier",
        _profile_command_factory(
            verifier_script,
            verifier_marker,
            identifier="profile-command-verifier",
            implementation_sha256="2" * 64,
        ),
    )
    try:
        profile = _command_profile()
        primary_script.write_text(
            primary_script.read_text(encoding="utf-8") + "\n# exact-only profile drift\n",
            encoding="utf-8",
        )

        report = inspect_mitigation_profile(profile)
        primary_check = next(
            item for item in report["checks"] if item["name"] == "profile-command-primary"
        )

        assert report["static_bindings_ready"] is False
        assert primary_check["status"] == "mismatch"
        assert "command_code_raw_sha256" in primary_check["mismatch_fields"]
        assert "command_code_sha256" not in primary_check["mismatch_fields"]
        with pytest.raises(MitigationProfileError, match="components"):
            mitigate_with_profile(SOURCE, profile, consent=True)
        assert not primary_marker.exists()
        assert not verifier_marker.exists()
    finally:
        unregister_detector("profile-command-primary")
        unregister_detector("profile-command-verifier")


def test_profile_bound_command_rechecks_code_at_first_detector_use(
    registered_profile_components, tmp_path, monkeypatch
):
    primary_script = tmp_path / "profile_late_drift_primary.py"
    verifier_script = tmp_path / "profile_late_drift_verifier.py"
    primary_marker = tmp_path / "late-drift-primary-invoked"
    verifier_marker = tmp_path / "late-drift-verifier-invoked"
    _write_profile_command(primary_script, implementation="primary")
    _write_profile_command(verifier_script, implementation="verifier")
    register_detector(
        "profile-command-primary",
        _profile_command_factory(
            primary_script,
            primary_marker,
            identifier="profile-command-primary",
            implementation_sha256="1" * 64,
        ),
    )
    register_detector(
        "profile-command-verifier",
        _profile_command_factory(
            verifier_script,
            verifier_marker,
            identifier="profile-command-verifier",
            implementation_sha256="2" * 64,
        ),
    )
    original_mitigate = profile_module.mitigate

    def drift_after_profile_pinning(*args, **kwargs):
        primary_script.write_text(
            primary_script.read_text(encoding="utf-8") + "\n# drift after raw pin\n",
            encoding="utf-8",
        )
        return original_mitigate(*args, **kwargs)

    monkeypatch.setattr(profile_module, "mitigate", drift_after_profile_pinning)
    try:
        result = mitigate_with_profile(SOURCE, _command_profile(), consent=True)
        assert result.changed is False
        assert result.cleaned_text == SOURCE
        assert not primary_marker.exists()
        assert not verifier_marker.exists()
    finally:
        unregister_detector("profile-command-primary")
        unregister_detector("profile-command-verifier")


def test_profile_direct_construction_is_validated_detached_and_deeply_immutable(
    registered_profile_components,
):
    caller_value = _profile().to_dict()
    direct = dewatermark.MitigationProfile(caller_value)
    caller_value["primary"]["name"] = "mutated-after-construction"
    assert direct.to_dict()["primary"]["name"] == "profile-primary"

    with pytest.raises(TypeError):
        direct.value["profile_id"] = "mutated"  # type: ignore[index]
    with pytest.raises(TypeError):
        direct.value["primary"]["name"] = "mutated"  # type: ignore[index]

    invalid = direct.to_dict()
    invalid["profile_sha256"] = "0" * 64
    with pytest.raises(MitigationProfileError, match="content digest"):
        dewatermark.MitigationProfile(invalid)


def test_profile_loader_rejects_fifo_before_open(tmp_path, monkeypatch):
    fifo = tmp_path / "profile.fifo"
    os.mkfifo(fifo)
    opened = False

    def unexpected_open(*_args, **_kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("FIFO must be rejected by lstat before open")

    monkeypatch.setattr(profile_module.os, "open", unexpected_open)
    with pytest.raises(MitigationProfileError, match="bounded regular file"):
        load_mitigation_profile(fifo)
    assert opened is False


def test_profile_component_drift_is_reported_and_execution_fails_before_text(
    registered_profile_components,
):
    profile = _profile()

    class Replacement(ProfileStrategy):
        capability = CapabilityManifest(
            identifier="profile-strategy-replacement",
            kind="transformer",
            metadata={"resource_accounting": "none"},
        )

    register_provider("profile-strategy", Replacement, replace=True)
    report = inspect_mitigation_profile(profile)
    assert report["static_bindings_ready"] is False
    assert any(item["status"] == "mismatch" for item in report["checks"])
    with pytest.raises(MitigationProfileError, match="components"):
        mitigate_with_profile(SOURCE, profile, consent=True)


def test_profile_rejects_uncommitted_source_localization_override(
    registered_profile_components,
):
    with pytest.raises(MitigationProfileError, match="cannot override"):
        mitigate_with_profile(
            SOURCE,
            _profile(),
            consent=True,
            source_localization=(SignalSpan(0, 5, p_value=0.001),),
        )


def test_profile_rejects_invalid_text_before_component_loading(
    registered_profile_components, monkeypatch
):
    lookups: list[str] = []

    def unexpected_lookup(name):
        lookups.append(name)
        raise AssertionError("invalid text must fail before component loading")

    monkeypatch.setattr(profile_module, "get_detector", unexpected_lookup)
    with pytest.raises(ValueError, match="non-empty string"):
        mitigate_with_profile(123, _profile(), consent=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="configured input limit"):
        mitigate_with_profile(
            "x" * 10_001,
            _profile(),
            consent=True,
        )
    assert lookups == []


def test_profile_quality_policy_is_cross_instance_stable_and_runtime_pinned(
    registered_profile_components, monkeypatch
):
    build_gate = ProfileRequiredGate(allow=True)
    run_gate = ProfileRequiredGate(allow=True)
    build_config = DewatermarkConfig(
        quality_gates=(QualityGateBinding(build_gate),),
        random_seed=13,
    )
    run_config = DewatermarkConfig(
        quality_gates=(QualityGateBinding(run_gate),),
        random_seed=13,
    )
    assert quality_policy_sha256(build_config) == quality_policy_sha256(run_config)
    profile = _profile(config=build_config)
    assert (
        mitigate_with_profile(SOURCE, profile, consent=True, config=run_config).status == "verified"
    )

    drifting_gate = ProfileRequiredGate(allow=False)
    drifting_config = DewatermarkConfig(
        quality_gates=(QualityGateBinding(drifting_gate),),
        random_seed=13,
    )
    drifting_profile = _profile(config=drifting_config)
    original_inspect = profile_module.inspect_mitigation_profile

    def mutate_after_inspection(*args, **kwargs):
        report = original_inspect(*args, **kwargs)
        drifting_gate.allow = True
        return report

    monkeypatch.setattr(profile_module, "inspect_mitigation_profile", mutate_after_inspection)
    with pytest.raises(MitigationProfileError, match="identity changed"):
        mitigate_with_profile(
            SOURCE,
            drifting_profile,
            consent=True,
            config=drifting_config,
        )


def test_profile_restores_nested_json_strategy_options_before_execution(
    registered_profile_components,
):
    profile = build_mitigation_profile(
        "operator/profile-nested-options-v1",
        scheme=SCHEME,
        watermark_target_sha256=TARGET,
        key_id="opaque-nested-options-key-id",
        primary_detector="profile-primary",
        verifier_detectors=["profile-verifier"],
        strategies=[
            (
                "profile-nested-strategy",
                {"nested": {"replacements": [2]}},
            )
        ],
        protocol_sha256="d" * 64,
        limits=SearchLimits(
            max_rounds=1,
            max_candidates=4,
            max_transform_calls=4,
            max_detector_queries=16,
        ),
    )

    result = mitigate_with_profile(SOURCE, profile, consent=True)

    assert result.status == "verified"
    assert result.cleaned_text == SOURCE.replace("blue", "teal", 2)


def test_profile_pins_strategy_instance_across_registry_replacement(
    registered_profile_components, monkeypatch
):
    profile = _profile()

    class LateReplacement(ProfileStrategy):
        capability = ProfileStrategy.capability

        def generate(self, text, *, context, replacements=2):
            return [text.replace("blue", "amber", replacements)]

    original_mitigate = profile_module.mitigate

    def replace_registration_after_pinning(*args, **kwargs):
        register_provider("profile-strategy", LateReplacement, replace=True)
        return original_mitigate(*args, **kwargs)

    monkeypatch.setattr(profile_module, "mitigate", replace_registration_after_pinning)
    result = mitigate_with_profile(SOURCE, profile, consent=True)
    assert result.status == "verified"
    assert result.cleaned_text == SOURCE.replace("blue", "teal", 2)


def test_profile_rechecks_pinned_provider_before_it_receives_text(
    registered_profile_components,
):
    class MutatingStrategy(ProfileStrategy):
        capability = ProfileStrategy.capability

        def available(self):
            self.changed_after_pin = True
            return True

    register_provider("profile-strategy", MutatingStrategy, replace=True)
    profile = _profile()
    with pytest.raises(MitigationProfileError, match="identity changed"):
        mitigate_with_profile(SOURCE, profile, consent=True)


def test_profile_rejects_aggregate_evidence_construction_and_has_no_promotion_api(
    registered_profile_components,
):
    profile = _profile()
    aggregate = profile.to_dict()
    aggregate["evidence"] = {
        "status": "aggregate_verified",
        "protocol_sha256": "d" * 64,
        "bundle_id": "a" * 64,
        "aggregate_verified": True,
    }
    aggregate["profile_sha256"] = mitigation_profile_sha256(aggregate)

    assert not Draft202012Validator(dewatermark.mitigation_profile_schema()).is_valid(aggregate)
    with pytest.raises(MitigationProfileError, match="protocol-only evidence"):
        validate_mitigation_profile(aggregate)
    assert not hasattr(dewatermark, "bind_mitigation_profile_evidence")
    assert not hasattr(dewatermark, "mitigation_profile_core_sha256")


def test_protocol_only_profile_executes_without_result_evidence(
    registered_profile_components,
):
    profile = _profile()
    assert profile.value["evidence"]["status"] == "protocol_only_no_results"

    result = mitigate_with_profile(SOURCE, profile, consent=True)

    assert result.status == "verified"
    assert result.receipt.profile_sha256 == profile.profile_sha256
    assert "evidence_bundle_id" not in result.to_dict()["receipt"]

    legacy_result = result.to_dict()
    legacy_result["receipt"]["evidence_bundle_id"] = "a" * 64
    assert not Draft202012Validator(dewatermark.mitigation_result_schema()).is_valid(legacy_result)


def test_profile_cli_inspect_doctor_and_mitigate(registered_profile_components, tmp_path, capsys):
    profile = _profile()
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile.to_dict()), encoding="utf-8")

    assert main(["profiles", "inspect", str(path)]) == EXIT_OK
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["profile_sha256"] == profile.profile_sha256

    assert main(["profiles", "doctor", str(path)]) == EXIT_OK
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["static_bindings_ready"] is True

    assert main(["mitigate", SOURCE, "--profile", str(path), "--consent"]) == EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "verified"
    assert result["receipt"]["profile_sha256"] == profile.profile_sha256


def test_profile_can_bind_the_builtin_context_strategy_without_plugin_loading(
    registered_profile_components,
):
    profile = build_mitigation_profile(
        "operator/profile-builtin-strategy-v1",
        scheme=SCHEME,
        watermark_target_sha256=TARGET,
        key_id="opaque-research-key-id-v2",
        primary_detector="profile-primary",
        verifier_detectors=["profile-verifier"],
        strategies=[
            (
                "context-aware-minimal-edit-v1",
                {"context_influence": 2, "max_edits": 2, "max_candidates": 8},
            )
        ],
        protocol_sha256="e" * 64,
        limits=SearchLimits(max_candidates=8, max_detector_queries=16),
    )

    assert inspect_mitigation_profile(profile)["static_bindings_ready"] is True
    result = mitigate_with_profile(SOURCE, profile, consent=True)
    assert result.status == "rolled_back"
    assert result.cleaned_text == SOURCE
    assert result.receipt.profile_sha256 == profile.profile_sha256
