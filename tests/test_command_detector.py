import asyncio
import json
import shutil
import sys
import time
from dataclasses import replace
from pathlib import Path
from threading import Event

import pytest

import dewatermark.detector_session as detector_session_module
from dewatermark.assurance import inspect
from dewatermark.command_detector import (
    CommandDetector,
    CommandDetectorConformanceError,
    CommandDetectorContractError,
    CommandDetectorExecutionError,
    DetectorGoldenVector,
    assert_command_detector_conformance,
    command_detector_manifest,
    detector_configuration_sha256,
    make_command_detector_factory,
    run_command_detector_conformance,
)
from dewatermark.config import DewatermarkConfig
from dewatermark.detector_session import DetectorSession
from dewatermark.providers import register_detector, unregister_detector
from dewatermark.request_context import RequestContext, ResourceBudgetExceeded, request_scope

PUBLIC_CONFIGURATION = {
    "algorithm": "offline-fixture-v1",
    "key_id": "fixture-public-key-id",
}
CONFIGURATION_SHA256 = detector_configuration_sha256(PUBLIC_CONFIGURATION)
OFFLINE = DewatermarkConfig(local_lm_enabled=False, request_timeout=1)


@pytest.fixture
def command_fixture(tmp_path: Path) -> Path:
    script = tmp_path / "command_fixture.py"
    script.write_text(
        "import json,os,sys,time\n"
        "from pathlib import Path\n"
        "mode=sys.argv[1]\n"
        "marker=Path(sys.argv[2])\n"
        "p=json.load(sys.stdin)\n"
        "record={'request':p,'environment':dict(os.environ)} if mode=='environment' else p\n"
        "marker.write_text(json.dumps(record,sort_keys=True),encoding='utf-8')\n"
        f"fp={CONFIGURATION_SHA256!r}\n"
        "if mode=='timeout': time.sleep(2)\n"
        "if mode=='large': sys.stdout.write('x'*4096);sys.exit(0)\n"
        "if mode=='stderr': print('private-source='+p.get('text',''),file=sys.stderr);sys.exit(9)\n"
        "if mode=='invalid_json': sys.stdout.write('private-source='+p.get('text',''));sys.exit(0)\n"
        "score=2.0 if 'marked' in p.get('text','') else 0.0\n"
        "threshold=0.5\n"
        "status='detected' if score>=threshold else 'not_detected'\n"
        "r={'protocol_version':'1.1','action':'detect.result',"
        "'detector':p['detector'],'scheme':'fixture-scheme','status':status,"
        "'score':score,'threshold':threshold,'score_direction':'higher',"
        "'threshold_operator':'>=',"
        "'effective_tokens':len(p.get('text','').split()),'configuration_sha256':fp}\n"
        "if mode=='reason': r['reason_code']=p.get('text','').split()[0]\n"
        "if mode=='fingerprint': r['configuration_sha256']='0'*64\n"
        "if mode=='threshold': r.update(threshold=9.0,status='not_detected')\n"
        "if mode=='low_tokens': r['effective_tokens']=1\n"
        "if mode=='bad_number': r['score']=True\n"
        "if mode=='bad_status': r['status']='yes'\n"
        "if mode=='contradiction': r['status']='not_detected'\n"
        "if mode=='wrong_version': r['protocol_version']='2.0'\n"
        "if mode=='unknown_field': r['private_debug']='must-not-cross-boundary'\n"
        "if mode=='legacy': r.pop('threshold_operator');r['legacy_extension']='ignored'\n"
        "if mode=='legacy_number': r.update(protocol_version='1.0',threshold_operator=42)\n"
        "if mode=='legacy_conflict': r.update(protocol_version='1.0',threshold_operator='<')\n"
        "json.dump(r,sys.stdout)\n",
        encoding="utf-8",
    )
    return script


def _manifest(**overrides):
    values = {
        "identifier": "fixture-command",
        "schemes": ("fixture-scheme",),
        "configuration_sha256": CONFIGURATION_SHA256,
        "threshold": 0.5,
        "score_direction": "higher",
        "threshold_operator": ">=",
        "calibrated": True,
        "independent": True,
    }
    values.update(overrides)
    return command_detector_manifest(**values)


def _detector(
    script: Path,
    marker: Path,
    mode: str = "ok",
    *,
    manifest=None,
    config=OFFLINE,
    timeout_seconds=0.5,
    max_stdout_bytes=2048,
):
    return CommandDetector(
        (sys.executable, str(script), mode, str(marker), "argv-public-marker"),
        manifest or _manifest(),
        config,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=512,
    )


def test_static_manifest_and_availability_never_start_command(command_fixture, tmp_path):
    marker = tmp_path / "invoked.json"
    detector = _detector(command_fixture, marker)

    assert detector.capability.identifier == "fixture-command"
    assert detector.available()
    assert "argv-public-marker" not in repr(detector)
    assert not marker.exists()

    evidence = detector.detect("marked text")
    assert marker.exists()
    request = json.loads(marker.read_text(encoding="utf-8"))
    assert request["action"] == "detect"
    assert request["text"] == "marked text"
    assert request["policy"] == {
        "allow_model_download": False,
        "allow_network": False,
    }
    assert evidence.status == "detected"
    assert evidence.score == 2.0
    assert evidence.threshold == 0.5
    assert evidence.details["effective_tokens"] == 2


def test_command_reason_code_cannot_echo_source_text(command_fixture, tmp_path):
    source = "privateword marked text"
    evidence = _detector(command_fixture, tmp_path / "reason.json", mode="reason").detect(source)

    assert "privateword" not in str(evidence.to_dict())
    assert evidence.details["reason_code"] == "detector_reported_reason"
    assert evidence.reason == "command detector reported a reason code"
    assert evidence.details["configuration_sha256"] == CONFIGURATION_SHA256


def test_factory_registers_without_invoking_and_integrates_with_inspect(command_fixture, tmp_path):
    marker = tmp_path / "registered.json"
    factory = make_command_detector_factory(
        (sys.executable, str(command_fixture), "ok", str(marker)), _manifest()
    )
    assert factory.capability.identifier == "fixture-command"
    assert not marker.exists()
    register_detector("fixture-command-runtime", factory)
    try:
        evidence = inspect("clean text", "fixture-command-runtime", config=OFFLINE)
    finally:
        unregister_detector("fixture-command-runtime")
    assert evidence.status == "not_detected"
    assert marker.exists()


@pytest.mark.parametrize("requirement", ["network", "download", "secret"])
def test_manifest_requirements_are_enforced_before_text_is_sent(
    command_fixture, tmp_path, requirement, monkeypatch
):
    marker = tmp_path / "denied.json"
    manifest = _manifest(
        network_required=requirement == "network",
        model_download_possible=requirement == "download",
        requires_secret=requirement == "secret",
    )
    invoked = False

    def forbidden_popen(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("denied command detector must not launch a process")

    monkeypatch.setattr("dewatermark.bounded_process.subprocess.Popen", forbidden_popen)
    evidence = _detector(command_fixture, marker, manifest=manifest).detect("marked private text")
    assert evidence.status == "configuration_mismatch"
    assert "requires" in (evidence.reason or "")
    assert not invoked
    assert not marker.exists()


def test_manifest_requirements_run_only_after_explicit_consent(command_fixture, tmp_path):
    marker = tmp_path / "allowed.json"
    manifest = _manifest(network_required=True, model_download_possible=True)
    config = replace(OFFLINE, allow_remote_processing=True, allow_model_download=True)
    evidence = _detector(command_fixture, marker, manifest=manifest, config=config).detect(
        "marked text"
    )
    assert evidence.status == "detected"
    assert marker.exists()


@pytest.mark.parametrize("termination", ("deadline", "cancellation"))
def test_valid_detector_output_is_rejected_if_request_ends_before_acceptance(
    command_fixture,
    tmp_path,
    monkeypatch,
    termination,
):
    config = replace(OFFLINE, allow_remote_processing=True, max_remote_calls=2)
    detector = _detector(
        command_fixture,
        tmp_path / "must-not-run.json",
        manifest=_manifest(network_required=True),
        config=config,
    )
    cancel_event = Event()
    active = RequestContext.from_config(config, cancel_event)

    def completed_run(_command, payload, **_limits):
        request = json.loads(payload)
        response = {
            "protocol_version": "1.1",
            "action": "detect.result",
            "detector": request["detector"],
            "scheme": "fixture-scheme",
            "status": "detected",
            "score": 2.0,
            "threshold": 0.5,
            "score_direction": "higher",
            "threshold_operator": ">=",
            "effective_tokens": 2,
            "configuration_sha256": request["configuration_sha256"],
        }
        if termination == "deadline":
            active.deadline = time.monotonic() - 1
        else:
            cancel_event.set()
        return json.dumps(response).encode("ascii")

    monkeypatch.setattr("dewatermark.command_detector._run_bounded_command", completed_run)
    expected_error = ResourceBudgetExceeded if termination == "deadline" else asyncio.CancelledError

    with request_scope(active):
        with pytest.raises(expected_error):
            detector.detect("marked text")

    ledger = active.ledger()
    assert ledger["remote_calls_used"] == 1
    assert ledger["deadline_exceeded"] is (termination == "deadline")
    assert ledger["cancelled"] is (termination == "cancellation")


@pytest.mark.parametrize(
    ("adapter_allows", "request_allows"),
    ((True, False), (False, True)),
    ids=("permissive-adapter-strict-request", "strict-adapter-permissive-request"),
)
def test_nested_consent_is_intersected_in_detector_policy_and_model_accounting(
    command_fixture,
    tmp_path,
    adapter_allows,
    request_allows,
):
    marker = tmp_path / "nested-policy.json"
    adapter_config = replace(
        OFFLINE,
        allow_remote_processing=adapter_allows,
        allow_model_download=adapter_allows,
    )
    request_config = replace(
        OFFLINE,
        allow_remote_processing=request_allows,
        allow_model_download=request_allows,
    )
    detector = _detector(
        command_fixture,
        marker,
        manifest=_manifest(metadata={"resource_accounting": "model"}),
        config=adapter_config,
    )
    active = RequestContext.from_config(request_config)

    with request_scope(active):
        evidence = detector.detect("marked text")

    assert evidence.status == "detected"
    request = json.loads(marker.read_text(encoding="utf-8"))
    assert request["policy"] == {
        "allow_model_download": False,
        "allow_network": False,
    }
    assert len(active.model_accesses) == 1
    assert active.model_accesses[0]["cached"] is True
    assert active.model_accesses[0]["download_allowed"] is False


@pytest.mark.parametrize(
    ("adapter_allows", "request_allows"),
    ((True, False), (False, True)),
    ids=("permissive-adapter-strict-request", "strict-adapter-permissive-request"),
)
@pytest.mark.parametrize("requirement", ("network", "download"))
def test_nested_required_detector_permission_is_denied_before_launch(
    command_fixture,
    tmp_path,
    monkeypatch,
    adapter_allows,
    request_allows,
    requirement,
):
    marker = tmp_path / f"nested-denied-{requirement}.json"
    adapter_config = replace(
        OFFLINE,
        allow_remote_processing=adapter_allows,
        allow_model_download=adapter_allows,
    )
    request_config = replace(
        OFFLINE,
        allow_remote_processing=request_allows,
        allow_model_download=request_allows,
    )
    detector = _detector(
        command_fixture,
        marker,
        manifest=_manifest(
            network_required=requirement == "network",
            model_download_possible=requirement == "download",
        ),
        config=adapter_config,
    )
    invoked = False

    def forbidden_popen(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("denied command detector must not launch")

    monkeypatch.setattr("dewatermark.bounded_process.subprocess.Popen", forbidden_popen)
    active = RequestContext.from_config(request_config)
    with request_scope(active):
        evidence = detector.detect("marked private text")

    assert evidence.status == "configuration_mismatch"
    assert "requires" in (evidence.reason or "")
    assert invoked is False
    assert not marker.exists()
    assert active.remote_calls == 0
    assert active.model_accesses == []


def test_command_inherits_only_minimal_non_secret_environment(
    command_fixture, tmp_path, monkeypatch
):
    marker = tmp_path / "environment.json"
    monkeypatch.setenv("GITHUB_TOKEN", "private-ci-token")
    monkeypatch.setenv("DEWATERMARK_LLM_API_KEY", "private-model-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "private-cloud-secret")
    monkeypatch.setenv("UNDECLARED_PUBLIC_VALUE", "also-not-declared")

    evidence = _detector(command_fixture, marker, "environment").detect("marked text")

    assert evidence.status == "detected"
    record = json.loads(marker.read_text(encoding="utf-8"))
    environment = record["environment"]
    allowed = {"PATH"}
    if sys.platform == "win32":
        allowed.update({"SYSTEMROOT", "WINDIR", "PATHEXT"})
    elif sys.platform in {"darwin", "linux"}:
        # The Python runtime may add this locale value inside the child even
        # when it is absent from Popen's explicit environment.
        allowed.add("LC_CTYPE")
        if sys.platform == "darwin":
            # CoreFoundation also adds its user-text encoding on macOS.
            allowed.add("__CF_USER_TEXT_ENCODING")
    assert set(environment).issubset(allowed)
    assert "PATH" in environment
    assert all(
        not key.upper().endswith(("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")) for key in environment
    )
    rendered = json.dumps(evidence.to_dict(), sort_keys=True)
    assert "private-ci-token" not in rendered
    assert "private-model-key" not in rendered
    assert "private-cloud-secret" not in rendered


@pytest.mark.parametrize("mode", ["fingerprint", "threshold"])
def test_static_configuration_mismatch_cannot_be_verified(command_fixture, tmp_path, mode):
    evidence = _detector(command_fixture, tmp_path / mode, mode).detect("marked text")
    assert evidence.status == "configuration_mismatch"
    assert evidence.details["mismatch_fields"]


def test_large_threshold_cannot_pass_relative_tolerance_and_invert_status():
    threshold = 1_000_000_000_000.0
    manifest = _manifest(threshold=threshold)
    detector = CommandDetector((sys.executable,), manifest, OFFLINE)
    response = {
        "protocol_version": "1.1",
        "action": "detect.result",
        "detector": "fixture-command",
        "scheme": "fixture-scheme",
        "status": "not_detected",
        "score": threshold + 0.25,
        "threshold": threshold + 0.5,
        "score_direction": "higher",
        "threshold_operator": ">=",
        "effective_tokens": 100,
        "configuration_sha256": CONFIGURATION_SHA256,
    }

    evidence = detector._normalize_response(response, "private text")

    assert evidence.status == "configuration_mismatch"
    assert evidence.details["mismatch_fields"] == ["threshold"]
    assert evidence.threshold == threshold


def test_effective_floor_overrides_positive_claim(command_fixture, tmp_path):
    manifest = _manifest(minimum_effective_tokens=4)
    evidence = _detector(
        command_fixture, tmp_path / "floor", "low_tokens", manifest=manifest
    ).detect("marked text")
    assert evidence.status == "insufficient_evidence"
    assert evidence.details["reported_status"] == "detected"
    assert evidence.details["effective_tokens"] == 1


def test_strict_threshold_operator_does_not_accept_equality():
    manifest = _manifest(threshold=4.0, threshold_operator=">")
    detector = CommandDetector((sys.executable,), manifest, OFFLINE)
    response = {
        "protocol_version": "1.1",
        "action": "detect.result",
        "detector": "fixture-command",
        "scheme": "fixture-scheme",
        "status": "not_detected",
        "score": 4.0,
        "threshold": 4.0,
        "score_direction": "higher",
        "threshold_operator": ">",
        "effective_tokens": 48,
        "configuration_sha256": CONFIGURATION_SHA256,
    }

    evidence = detector._normalize_response(response, "private text")

    assert evidence.status == "not_detected"
    assert evidence.details["threshold_operator"] == ">"


def test_operator_managed_file_binding_is_the_only_supported_secret_channel(
    command_fixture, tmp_path
):
    marker = tmp_path / "bound.json"
    manifest = _manifest(
        requires_secret=True,
        secret_binding="operator_managed_file",
    )

    evidence = _detector(command_fixture, marker, manifest=manifest).detect("marked text")

    assert evidence.status == "detected"
    assert marker.exists()


@pytest.mark.parametrize("mode", ["bad_number", "bad_status", "contradiction", "wrong_version"])
def test_malformed_or_inconsistent_evidence_is_rejected(command_fixture, tmp_path, mode):
    detector = _detector(command_fixture, tmp_path / mode, mode)
    with pytest.raises(CommandDetectorContractError):
        detector.detect("marked text")


def test_v1_response_extensions_are_ignored_without_becoming_public(command_fixture, tmp_path):
    evidence = _detector(command_fixture, tmp_path / "extension", "unknown_field").detect(
        "marked text"
    )

    assert evidence.status == "detected"
    assert "private_debug" not in evidence.details


def test_legacy_v1_operator_default_preserves_detection_but_not_verification(
    command_fixture, tmp_path
):
    target = "a" * 64
    current = _manifest(watermark_target_sha256=target)
    legacy_metadata = dict(current.metadata)
    legacy_metadata["command_protocol_version"] = "1.0"
    legacy_metadata.pop("threshold_operator")
    legacy = replace(current, metadata=legacy_metadata)
    primary_marker = tmp_path / "legacy.json"
    primary = _detector(command_fixture, primary_marker, "legacy", manifest=legacy)

    evidence = primary.detect("marked text")

    assert evidence.status == "detected"
    assert evidence.details["threshold_operator"] == ">="
    assert "legacy_extension" not in evidence.details

    verifier_marker = tmp_path / "verifier.json"
    verifier = _detector(
        command_fixture,
        verifier_marker,
        manifest=_manifest(identifier="fixture-verifier", watermark_target_sha256=target),
    )
    primary_marker.unlink()
    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "command_detector_implementation_unbound"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


@pytest.mark.parametrize(
    ("mode", "manifest_extension"),
    [("legacy_number", 42), ("legacy_conflict", "<")],
)
def test_legacy_v1_ignores_colliding_operator_extensions(
    command_fixture, tmp_path, mode, manifest_extension
):
    current = _manifest()
    metadata = dict(current.metadata)
    metadata["command_protocol_version"] = "1.0"
    metadata["threshold_operator"] = manifest_extension
    metadata["implementation_sha256"] = "legacy-extension-value"
    metadata["watermark_target_sha256"] = "legacy-extension-value"
    metadata["secret_binding"] = "legacy-extension-value"
    legacy = replace(current, metadata=metadata)

    marker = tmp_path / f"{mode}.json"
    evidence = _detector(command_fixture, marker, mode, manifest=legacy).detect("marked text")

    assert evidence.status == "detected"
    assert evidence.details["threshold_operator"] == ">="
    assert json.loads(marker.read_text(encoding="utf-8"))["protocol_version"] == "1.0"


def test_distinct_command_implementation_commitments_can_verify(command_fixture, tmp_path):
    target = "a" * 64
    verifier_fixture = tmp_path / "independent_command_fixture.py"
    shutil.copyfile(command_fixture, verifier_fixture)
    verifier_fixture.write_text(
        verifier_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=3.0 if"),
        encoding="utf-8",
    )
    primary_marker = tmp_path / "primary.json"
    verifier_marker = tmp_path / "verifier.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        verifier_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert type(primary) is CommandDetector
    assert type(verifier) is CommandDetector
    assert result.status == "verified"
    assert primary_marker.exists()
    assert verifier_marker.exists()


def test_command_verification_does_not_walk_generic_extension_state(
    command_fixture, tmp_path, monkeypatch
):
    target = "a" * 64
    verifier_fixture = tmp_path / "independent_without_generic_state.py"
    shutil.copyfile(command_fixture, verifier_fixture)
    verifier_fixture.write_text(
        verifier_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=3.0 if"),
        encoding="utf-8",
    )
    primary = _detector(
        command_fixture,
        tmp_path / "no-generic-state-primary.json",
        manifest=_manifest(
            identifier="fixture-no-generic-state-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        verifier_fixture,
        tmp_path / "no-generic-state-verifier.json",
        manifest=_manifest(
            identifier="fixture-no-generic-state-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )

    def generic_identity_must_not_receive_commands(*_args, **_kwargs):
        raise AssertionError("exact command detectors have a bounded identity projection")

    monkeypatch.setattr(
        detector_session_module,
        "extension_identity",
        generic_identity_must_not_receive_commands,
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "verified"
    assert result.verified is True


def test_distinct_declared_commitments_cannot_alias_one_command(command_fixture, tmp_path):
    target = "a" * 64
    primary_marker = tmp_path / "primary-code-alias.json"
    verifier_marker = tmp_path / "verifier-code-alias.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-primary-code-alias",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        command_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-verifier-code-alias",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_comment_only_script_copy_cannot_manufacture_independence(command_fixture, tmp_path):
    target = "a" * 64
    cosmetic_fixture = tmp_path / "cosmetic_command_fixture.py"
    shutil.copyfile(command_fixture, cosmetic_fixture)
    cosmetic_fixture.write_text(
        cosmetic_fixture.read_text(encoding="utf-8") + "\n# cosmetic difference only\n",
        encoding="utf-8",
    )
    primary_marker = tmp_path / "primary-cosmetic.json"
    verifier_marker = tmp_path / "verifier-cosmetic.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-primary-cosmetic",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        cosmetic_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-verifier-cosmetic",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_unused_constant_script_copy_cannot_manufacture_independence(command_fixture, tmp_path):
    target = "a" * 64
    cosmetic_fixture = tmp_path / "unused_constant_command_fixture.py"
    shutil.copyfile(command_fixture, cosmetic_fixture)
    cosmetic_fixture.write_text(
        cosmetic_fixture.read_text(encoding="utf-8") + "\nUNUSED_NOOP_CONSTANT = 1\n",
        encoding="utf-8",
    )
    primary = _detector(
        command_fixture,
        tmp_path / "unused-primary.json",
        manifest=_manifest(
            identifier="fixture-unused-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        cosmetic_fixture,
        tmp_path / "unused-verifier.json",
        manifest=_manifest(
            identifier="fixture-unused-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"


def test_direct_python_script_comments_cannot_manufacture_independence(command_fixture, tmp_path):
    target = "a" * 64
    source = command_fixture.read_text(encoding="utf-8")
    primary_script = tmp_path / "direct-primary.py"
    verifier_script = tmp_path / "direct-verifier.py"
    primary_script.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    verifier_script.write_text(
        "#!/usr/bin/env python3\n" + source + "\n# cosmetic direct-script comment\n",
        encoding="utf-8",
    )
    primary_script.chmod(0o700)
    verifier_script.chmod(0o700)
    primary_marker = tmp_path / "direct-primary.json"
    verifier_marker = tmp_path / "direct-verifier.json"
    primary = CommandDetector(
        (str(primary_script), "ok", str(primary_marker), "argv-public-marker"),
        _manifest(
            identifier="fixture-direct-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
        OFFLINE,
    )
    verifier = CommandDetector(
        (str(verifier_script), "ok", str(verifier_marker), "argv-public-marker"),
        _manifest(
            identifier="fixture-direct-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
        OFFLINE,
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_instance_identity_method_shadow_cannot_spoof_command_code(command_fixture, tmp_path):
    target = "a" * 64
    primary = _detector(
        command_fixture,
        tmp_path / "shadow-identity-primary.json",
        manifest=_manifest(
            identifier="fixture-shadow-identity-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        command_fixture,
        tmp_path / "shadow-identity-verifier.json",
        manifest=_manifest(
            identifier="fixture-shadow-identity-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )
    primary._verification_code_sha256 = lambda: "3" * 64
    verifier._verification_code_sha256 = lambda: "4" * 64

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"


def test_instance_detect_shadow_is_not_used_for_exact_command_detector(command_fixture, tmp_path):
    target = "a" * 64
    verifier_fixture = tmp_path / "shadow_detect_verifier.py"
    shutil.copyfile(command_fixture, verifier_fixture)
    verifier_fixture.write_text(
        verifier_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=3.0 if"),
        encoding="utf-8",
    )
    primary_marker = tmp_path / "shadow-detect-primary.json"
    verifier_marker = tmp_path / "shadow-detect-verifier.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-shadow-detect-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        verifier_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-shadow-detect-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )
    shadow_calls = 0

    def forged(_text):
        nonlocal shadow_calls
        shadow_calls += 1
        raise AssertionError("instance shadow must not execute")

    primary.detect = forged
    verifier.detect = forged

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "verified"
    assert shadow_calls == 0
    assert primary_marker.exists()
    assert verifier_marker.exists()


def test_same_command_implementation_commitment_abstains_before_commands(command_fixture, tmp_path):
    target = "a" * 64
    implementation = "1" * 64
    primary_marker = tmp_path / "primary-alias.json"
    verifier_marker = tmp_path / "verifier-alias.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-primary-alias",
            implementation_sha256=implementation,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        command_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-verifier-alias",
            implementation_sha256=implementation,
            watermark_target_sha256=target,
        ),
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_not_distinct"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_command_detector_subclasses_cannot_manufacture_independence(command_fixture, tmp_path):
    class CosmeticPrimary(CommandDetector):
        pass

    class CosmeticVerifier(CommandDetector):
        pass

    target = "a" * 64
    primary_marker = tmp_path / "subclass-primary.json"
    verifier_marker = tmp_path / "subclass-verifier.json"
    primary = CosmeticPrimary(
        (sys.executable, str(command_fixture), "ok", str(primary_marker)),
        _manifest(
            identifier="fixture-subclass-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
        OFFLINE,
    )
    verifier = CosmeticVerifier(
        (sys.executable, str(command_fixture), "ok", str(verifier_marker)),
        _manifest(
            identifier="fixture-subclass-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
        OFFLINE,
    )

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "command_detector_identity_unverifiable"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_missing_command_implementation_commitment_detects_but_cannot_verify(
    command_fixture, tmp_path
):
    target = "a" * 64
    primary_marker = tmp_path / "unbound-primary.json"
    verifier_marker = tmp_path / "bound-verifier.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-unbound-primary",
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        command_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-bound-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )

    assert primary.detect("marked source").status == "detected"
    assert primary_marker.exists()
    primary_marker.unlink()

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "command_detector_implementation_unbound"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_command_implementation_commitment_drift_fails_before_more_text(command_fixture, tmp_path):
    target = "a" * 64
    verifier_fixture = tmp_path / "stable_verifier_fixture.py"
    shutil.copyfile(command_fixture, verifier_fixture)
    verifier_fixture.write_text(
        verifier_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=3.0 if"),
        encoding="utf-8",
    )
    primary_marker = tmp_path / "drifting-primary.json"
    verifier_marker = tmp_path / "stable-verifier.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-drifting-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        verifier_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-stable-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )
    session = DetectorSession(primary, verifier_detectors=(verifier,))

    assert session.score("marked source").evidence.status == "detected"
    primary_marker.unlink()
    primary.capability.metadata["implementation_sha256"] = "3" * 64

    result = session.verify("marked source", "clear candidate")

    assert result.status == "not_verifiable"
    assert result.reason_code == "command_detector_identity_unverifiable"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_command_code_change_between_score_and_verify_invalidates_cache(command_fixture, tmp_path):
    target = "a" * 64
    verifier_fixture = tmp_path / "cache_verifier_fixture.py"
    shutil.copyfile(command_fixture, verifier_fixture)
    verifier_fixture.write_text(
        verifier_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=3.0 if"),
        encoding="utf-8",
    )
    primary_marker = tmp_path / "cache-primary.json"
    verifier_marker = tmp_path / "cache-verifier.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-cache-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        verifier_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-cache-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )
    session = DetectorSession(primary, verifier_detectors=(verifier,))

    assert session.score("marked source").evidence.status == "detected"
    primary_marker.unlink()
    command_fixture.write_text(
        command_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=2.5 if"),
        encoding="utf-8",
    )
    result = session.verify("marked source", "clear candidate")

    assert result.status == "not_verifiable"
    assert result.reason_code == "detector_policy_drift"
    assert not primary_marker.exists()
    assert not verifier_marker.exists()


def test_command_code_identity_is_rechecked_after_detector_calls(
    command_fixture, tmp_path, monkeypatch
):
    target = "a" * 64
    verifier_fixture = tmp_path / "postflight_verifier_fixture.py"
    shutil.copyfile(command_fixture, verifier_fixture)
    verifier_fixture.write_text(
        verifier_fixture.read_text(encoding="utf-8").replace("score=2.0 if", "score=3.0 if"),
        encoding="utf-8",
    )
    primary_marker = tmp_path / "postflight-primary.json"
    verifier_marker = tmp_path / "postflight-verifier.json"
    primary = _detector(
        command_fixture,
        primary_marker,
        manifest=_manifest(
            identifier="fixture-postflight-primary",
            implementation_sha256="1" * 64,
            watermark_target_sha256=target,
        ),
    )
    verifier = _detector(
        verifier_fixture,
        verifier_marker,
        manifest=_manifest(
            identifier="fixture-postflight-verifier",
            implementation_sha256="2" * 64,
            watermark_target_sha256=target,
        ),
    )
    real_identity = detector_session_module.command_code_identity_sha256
    original_identity = real_identity(primary._command)
    calls = 0

    def drifting_identity(command):
        nonlocal calls
        if command != primary._command:
            return real_identity(command)
        calls += 1
        return original_identity if calls <= 4 else "f" * 64

    monkeypatch.setattr(detector_session_module, "command_code_identity_sha256", drifting_identity)

    result = DetectorSession(primary, verifier_detectors=(verifier,)).verify(
        "marked source", "clear candidate"
    )

    assert result.status == "not_verifiable"
    assert result.reason_code == "held_out_verifier_policy_drift"
    assert primary_marker.exists()
    assert verifier_marker.exists()


@pytest.mark.parametrize("mode", ["stderr", "invalid_json"])
def test_process_output_and_source_are_redacted_from_errors(command_fixture, tmp_path, mode):
    private = "private-source-never-reflect"
    detector = _detector(command_fixture, tmp_path / mode, mode)
    with pytest.raises((CommandDetectorExecutionError, CommandDetectorContractError)) as caught:
        detector.detect(private)
    rendered = str(caught.value)
    assert private not in rendered
    assert "argv-public-marker" not in rendered


def test_timeout_and_output_size_are_hard_bounded(command_fixture, tmp_path):
    timeout_detector = _detector(
        command_fixture, tmp_path / "timeout", "timeout", timeout_seconds=0.05
    )
    with pytest.raises(CommandDetectorExecutionError, match="timed out"):
        timeout_detector.detect("marked text")

    output_detector = _detector(
        command_fixture,
        tmp_path / "large",
        "large",
        max_stdout_bytes=128,
    )
    with pytest.raises(CommandDetectorExecutionError, match="output limit"):
        output_detector.detect("marked text")


def test_golden_vector_conformance_report_contains_no_source(command_fixture, tmp_path):
    detector = _detector(command_fixture, tmp_path / "golden")
    private = "marked private golden text"
    vectors = (
        DetectorGoldenVector("positive", private, "detected", 2.0, 0.5, 4),
        DetectorGoldenVector("negative", "ordinary text", "not_detected", 0.0, 0.5, 2),
    )
    report = assert_command_detector_conformance(detector, vectors)
    assert report.passed
    assert private not in repr(vectors[0])
    assert private not in json.dumps(report.to_dict())

    failed = run_command_detector_conformance(
        detector,
        (DetectorGoldenVector("wrong", private, "not_detected", 0.0, 0.5, 4),),
    )
    assert not failed.passed
    with pytest.raises(CommandDetectorConformanceError) as caught:
        assert_command_detector_conformance(
            detector,
            (DetectorGoldenVector("wrong", private, "not_detected", 0.0, 0.5, 4),),
        )
    assert private not in str(caught.value)


def test_public_configuration_fingerprint_refuses_secret_material():
    assert len(detector_configuration_sha256(PUBLIC_CONFIGURATION)) == 64
    private_configurations = (
        {"api_key": "never-fingerprint"},
        {"api_key_value": "opaque-value"},
        {"secret_value": "opaque-value"},
        {"token_value": "opaque-value"},
        {"authorization_header": "opaque-value"},
        {"password_source": "opaque-value"},
        {"header": "Bearer PRIVATECREDENTIAL123456789"},
        {"endpoint": "https://user:password@example.test"},
        {"value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
        {"model_path": "/Users/alice/private/model.bin"},
    )
    for configuration in private_configurations:
        with pytest.raises(ValueError):
            detector_configuration_sha256(configuration)
    assert len(detector_configuration_sha256({"key_id": "operator-key-2026"})) == 64


def test_direct_manifest_cannot_bypass_public_metadata_validation(command_fixture, tmp_path):
    manifest = _manifest()
    unsafe = replace(manifest, metadata={**manifest.metadata, "api_key": "never-publish"})
    with pytest.raises(ValueError):
        _detector(command_fixture, tmp_path / "unsafe", manifest=unsafe)


def test_watermark_target_digest_is_first_class_and_strictly_lowercase():
    digest = "a" * 64
    manifest = _manifest(watermark_target_sha256=digest)
    assert manifest.metadata["watermark_target_sha256"] == digest
    legacy = _manifest(metadata={"watermark_target_sha256": digest})
    assert legacy.metadata["watermark_target_sha256"] == digest
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        _manifest(watermark_target_sha256="A" * 64)
    with pytest.raises(ValueError, match="do not match"):
        _manifest(
            watermark_target_sha256=digest,
            metadata={"watermark_target_sha256": "b" * 64},
        )


def test_command_implementation_digest_is_first_class_and_strictly_lowercase():
    digest = "c" * 64
    manifest = _manifest(implementation_sha256=digest)
    assert manifest.metadata["implementation_sha256"] == digest
    legacy_form = _manifest(metadata={"implementation_sha256": digest})
    assert legacy_form.metadata["implementation_sha256"] == digest
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        _manifest(implementation_sha256="C" * 64)
    with pytest.raises(ValueError, match="do not match"):
        _manifest(
            implementation_sha256=digest,
            metadata={"implementation_sha256": "d" * 64},
        )


def test_command_requires_tuple_argv(command_fixture, tmp_path):
    marker = tmp_path / "tuple.json"
    with pytest.raises(TypeError, match="tuple"):
        CommandDetector(  # type: ignore[arg-type]
            [sys.executable, str(command_fixture), "ok", str(marker)], _manifest(), OFFLINE
        )

    for command in (
        (sys.executable, "--api-key", "sk-live-PRIVATE-CREDENTIAL-123456"),
        (sys.executable, "--key", "15485863"),
        (sys.executable, "https://user:password@example.test/run"),
        (sys.executable, "--header=Bearer PRIVATE-CREDENTIAL-123456"),
        (sys.executable, "--header=X-Api-Key: PRIVATE_CREDENTIAL_123456789"),
        (sys.executable, "--env=AWS_SECRET_ACCESS_KEY=privatevalue123456789"),
        (sys.executable, "--key-file=privatevalue123456789"),
        (sys.executable, "opaque-private-credential-value-123456789"),
    ):
        with pytest.raises(ValueError, match="cannot carry credentials"):
            CommandDetector(command, _manifest(), OFFLINE)
    CommandDetector((sys.executable, "--key-file", "operator-key.json"), _manifest(), OFFLINE)
