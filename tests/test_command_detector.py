import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

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
from dewatermark.providers import register_detector, unregister_detector

PUBLIC_CONFIGURATION = {
    "algorithm": "offline-fixture-v1",
    "key_fingerprint": "fixture-public-key-id",
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
        "r={'protocol_version':'1.0','action':'detect.result',"
        "'detector':'fixture-command','scheme':'fixture-scheme','status':status,"
        "'score':score,'threshold':threshold,'score_direction':'higher',"
        "'effective_tokens':len(p.get('text','').split()),'configuration_sha256':fp}\n"
        "if mode=='fingerprint': r['configuration_sha256']='0'*64\n"
        "if mode=='threshold': r.update(threshold=9.0,status='not_detected')\n"
        "if mode=='low_tokens': r['effective_tokens']=1\n"
        "if mode=='bad_number': r['score']=True\n"
        "if mode=='bad_status': r['status']='yes'\n"
        "if mode=='contradiction': r['status']='not_detected'\n"
        "if mode=='wrong_version': r['protocol_version']='2.0'\n"
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
        (sys.executable, str(script), mode, str(marker), "argv-private-token"),
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
    assert "argv-private-token" not in repr(detector)
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
        "protocol_version": "1.0",
        "action": "detect.result",
        "detector": "fixture-command",
        "scheme": "fixture-scheme",
        "status": "not_detected",
        "score": threshold + 0.25,
        "threshold": threshold + 0.5,
        "score_direction": "higher",
        "effective_tokens": 100,
        "configuration_sha256": CONFIGURATION_SHA256,
    }

    evidence = detector._normalize_response(response, "private text")

    assert evidence.status == "configuration_mismatch"
    assert evidence.details["mismatch_fields"] == ["threshold"]
    assert evidence.threshold == threshold


def test_effective_token_floor_overrides_positive_claim(command_fixture, tmp_path):
    manifest = _manifest(minimum_effective_tokens=4)
    evidence = _detector(
        command_fixture, tmp_path / "tokens", "low_tokens", manifest=manifest
    ).detect("marked text")
    assert evidence.status == "insufficient_evidence"
    assert evidence.details["reported_status"] == "detected"
    assert evidence.details["effective_tokens"] == 1


@pytest.mark.parametrize("mode", ["bad_number", "bad_status", "contradiction", "wrong_version"])
def test_malformed_or_inconsistent_evidence_is_rejected(command_fixture, tmp_path, mode):
    detector = _detector(command_fixture, tmp_path / mode, mode)
    with pytest.raises(CommandDetectorContractError):
        detector.detect("marked text")


@pytest.mark.parametrize("mode", ["stderr", "invalid_json"])
def test_process_output_and_source_are_redacted_from_errors(command_fixture, tmp_path, mode):
    private = "private-source-never-reflect"
    detector = _detector(command_fixture, tmp_path / mode, mode)
    with pytest.raises((CommandDetectorExecutionError, CommandDetectorContractError)) as caught:
        detector.detect(private)
    rendered = str(caught.value)
    assert private not in rendered
    assert "argv-private-token" not in rendered


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
    with pytest.raises(ValueError, match="not credentials"):
        detector_configuration_sha256({"api_key": "do-not-hash-this"})


def test_direct_manifest_cannot_bypass_public_metadata_validation(command_fixture, tmp_path):
    manifest = _manifest()
    unsafe = replace(manifest, metadata={**manifest.metadata, "api_key": "never-publish"})
    with pytest.raises(ValueError, match="not credentials"):
        _detector(command_fixture, tmp_path / "unsafe", manifest=unsafe)


def test_command_requires_tuple_argv(command_fixture, tmp_path):
    marker = tmp_path / "tuple.json"
    with pytest.raises(TypeError, match="tuple"):
        CommandDetector(  # type: ignore[arg-type]
            [sys.executable, str(command_fixture), "ok", str(marker)], _manifest(), OFFLINE
        )
