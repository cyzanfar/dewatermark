import io
import json
from dataclasses import replace

import pytest
import requests

import dewatermark.providers as providers
import dewatermark.scoring as scoring
from dewatermark import (
    CapabilityManifest,
    ConfigurationError,
    DetectionEvidence,
    EvidenceReceipt,
    StageResult,
    bira,
    detectors,
    extension_safety,
    fireworks,
    http,
    mcp_server,
    paraphraser,
    remove,
    runtime,
    scanner,
    server,
    sira,
)
from dewatermark.assurance_api import create_plan
from dewatermark.cli import EXIT_PROCESSING, main
from dewatermark.config import DewatermarkConfig
from dewatermark.detector_tools import doctor_detectors
from dewatermark.providers import (
    register_detector,
    register_provider,
    unregister_detector,
    unregister_provider,
)
from dewatermark.quality_gates import quality_gate_conformance
from dewatermark.request_context import ResourceBudgetExceeded, safe_error
from dewatermark.scanner import ScanReport
from dewatermark.scanner_config import ScannerConfig

SECRET = "private-source bearer-secret /private/model https://user:pass@example.test"
REMOTE = DewatermarkConfig(
    llm_api_key="credential",
    llm_base_url="http://127.0.0.1:8080/v1",
    fireworks_api_key="credential",
    fireworks_base_url="http://127.0.0.1:8080/v1",
    allow_remote_processing=True,
)


class _MalformedResponse:
    status_code = 200

    def json(self):
        raise ValueError(SECRET)


def _assert_private_error(exc: BaseException) -> None:
    assert SECRET not in str(exc)
    assert exc.__cause__ is None


def test_remote_transport_discards_request_exception(monkeypatch):
    monkeypatch.setattr(
        http.requests,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(requests.ConnectionError(SECRET)),
    )
    with pytest.raises(http.HTTPTransportError) as caught:
        http.post_json(
            "http://127.0.0.1/x",
            headers={"Authorization": SECRET},
            body={"text": SECRET},
            timeout=1,
            retries=0,
            config=REMOTE,
        )
    _assert_private_error(caught.value)


def test_malformed_remote_bodies_and_model_identifiers_are_redacted(monkeypatch):
    monkeypatch.setattr(paraphraser, "post_json", lambda *_args, **_kwargs: _MalformedResponse())
    with pytest.raises(paraphraser.LLMError) as llm_error:
        paraphraser.chat("system", SECRET, 1.0, config=REMOTE)
    _assert_private_error(llm_error.value)

    monkeypatch.setattr(fireworks, "post_json", lambda *_args, **_kwargs: _MalformedResponse())
    with pytest.raises(fireworks.FireworksError) as fireworks_error:
        fireworks.chat("system", SECRET, config=REMOTE)
    _assert_private_error(fireworks_error.value)

    config = DewatermarkConfig(llm_model=SECRET, max_remote_calls=16)
    monkeypatch.setattr(
        paraphraser,
        "chat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(paraphraser.LLMError(SECRET)),
    )
    _, stages = paraphraser.recursive_paraphrase("source", 1, config)
    assert SECRET not in json.dumps(stages)
    assert "model_sha256" in stages[0]


def test_safe_error_never_trusts_custom_budget_messages():
    assert SECRET not in safe_error("operation", ResourceBudgetExceeded(SECRET))
    assert SECRET not in safe_error(SECRET, RuntimeError(SECRET))


def test_cli_and_mcp_hide_custom_exception_messages(monkeypatch, capsys):
    monkeypatch.setattr(
        "dewatermark.cli._remove_one",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    assert main(["remove", "source"]) == EXIT_PROCESSING
    assert SECRET not in capsys.readouterr().err

    monkeypatch.setattr(
        mcp_server,
        "analyze",
        lambda _text: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    with pytest.raises(RuntimeError) as caught:
        mcp_server.analyze_text("source")
    _assert_private_error(caught.value)


def test_http_handler_and_scanner_hide_failure_details(monkeypatch, tmp_path):
    handler = object.__new__(server.DewatermarkHandler)
    handler.path = "/analyze"
    handler.headers = {"Content-Type": "application/json", "Content-Length": "18"}
    handler.rfile = io.BytesIO(b'{"text": "source"}')
    handler._guard = lambda: True
    responses = []
    handler._send = lambda status, value: responses.append((status, value))
    monkeypatch.setattr(
        server,
        "process_request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(SECRET)),
    )
    handler.do_POST()
    assert responses == [(400, {"error": "invalid request"})]

    private_filename = "private-source-bearer-secret-private-model.txt"
    target = tmp_path / private_filename
    target.write_text("text", encoding="utf-8")
    monkeypatch.setattr(
        scanner.Path,
        "open",
        lambda _path, *_args, **_kwargs: (_ for _ in ()).throw(OSError(SECRET)),
    )
    report = scanner.scan_paths([target])
    rendered = json.dumps(report.to_dict())
    assert SECRET not in rendered
    assert private_filename not in rendered
    assert report.errors[0].startswith("file_sha256:")


def test_extension_and_registry_failures_discard_private_details(monkeypatch):
    class BadMetadata:
        capability = CapabilityManifest(
            identifier="privacy-fixture",
            kind="scorer",
            metadata={SECRET: float("nan")},
        )

    with pytest.raises(ConfigurationError) as metadata_error:
        extension_safety.static_capability(BadMetadata, "scorer")
    _assert_private_error(metadata_error.value)

    class EntryPoint:
        def load(self):
            raise RuntimeError(SECRET)

    monkeypatch.setattr(providers, "_provider_entry_points", {"privacy-fixture": EntryPoint()})
    try:
        with pytest.raises(ConfigurationError) as provider_error:
            providers.get_provider("privacy-fixture")
        _assert_private_error(provider_error.value)
        assert providers.provider_errors()["privacy-fixture"] == "entry_point_load_failed"
    finally:
        providers._provider_errors.pop("privacy-fixture", None)


def test_scorer_and_sira_failures_and_cache_metadata_are_private(monkeypatch):
    class LeakyScorer:
        capability = CapabilityManifest(identifier="leaky-scorer", kind="scorer")

        def __init__(self, _config):
            pass

        def self_information(self, _text):
            raise RuntimeError(SECRET)

    register_provider("leaky-scorer", LeakyScorer)
    config = replace(DewatermarkConfig(local_lm_enabled=False), scorer_provider="leaky-scorer")
    try:
        with pytest.raises(scoring.ScorerUnavailable) as scorer_error:
            scoring.self_information("source", config)
        _assert_private_error(scorer_error.value)
        assert SECRET not in json.dumps(scoring.surrogate_score("source", config))
    finally:
        unregister_provider("leaky-scorer")

    scoring.clear_cache()
    try:
        scoring._state["private-cache-key"] = {
            "name": SECRET,
            "device": "cpu",
            "dtype": "float32",
        }
        assert SECRET not in json.dumps(scoring.cache_info())
        assert scoring.cache_info()["models"][0]["name"].startswith("sha256:")
    finally:
        scoring.clear_cache()

    monkeypatch.setattr(
        scoring,
        "self_information",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(SECRET)),
    )
    _, detail = sira.sira_rewrite("source text", config=DewatermarkConfig())
    assert SECRET not in json.dumps(detail)

    monkeypatch.setattr(
        scoring,
        "load",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(scoring.ScorerUnavailable(SECRET)),
    )
    _, detail = bira.bira_rewrite("source text", config=DewatermarkConfig())
    assert SECRET not in json.dumps(detail)


def test_public_models_do_not_invoke_nested_object_representations_or_deepcopy():
    class_secret = "PRIVATE_MODEL_CLASS_BEARER_12345"

    def forbidden(_self, *_args):
        raise AssertionError("public serialization invoked an object hook")

    SecretObject = type(
        class_secret,
        (),
        {
            "__repr__": forbidden,
            "__str__": forbidden,
            "__deepcopy__": forbidden,
        },
    )
    secret_object = SecretObject()
    evidence = DetectionEvidence(
        detector=secret_object,  # type: ignore[arg-type]
        status="insufficient_evidence",
        details={"nested": {"value": secret_object, "api_key": SECRET}},
    )
    receipt = EvidenceReceipt(
        input_sha256="0" * 64,
        output_sha256="1" * 64,
        mode="sanitize",
        detection="insufficient_evidence",
        transformation="unchanged",
        verification="not_verifiable",
        changed=False,
        detector_before=evidence,
        policy={"nested": {"value": secret_object, "password": SECRET}},
    )
    stage = StageResult(name="fixture", details={"nested": secret_object})
    scanner_config = ScannerConfig(
        exclude=(secret_object,),  # type: ignore[arg-type]
        source=secret_object,  # type: ignore[arg-type]
    )

    rendered = json.dumps(
        [evidence.to_dict(), receipt.to_dict(), stage.to_dict(), scanner_config.to_dict()]
    )
    assert SECRET not in rendered
    assert class_secret not in rendered
    assert "<redacted>" in rendered


def test_detector_consent_and_unsupported_reasons_are_static(monkeypatch):
    class Detector:
        capability = CapabilityManifest(
            identifier="privacy-detector",
            kind="detector",
            schemes=("fixture",),
        )

        def available(self):
            return True

        def detect(self, _text):
            return 1.0

    monkeypatch.setattr(
        detectors,
        "require_extension",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError(SECRET)),
    )
    evidence = detectors.run_detector(Detector(), "source", config=DewatermarkConfig())
    assert evidence.status == "configuration_mismatch"
    assert evidence.reason == "detector extension requirements are not explicitly permitted"
    assert SECRET not in json.dumps(evidence.to_dict())

    unsupported = detectors.UnsupportedDetector("fixture", reason=SECRET).detect("source")
    assert unsupported.reason == "No public, independently usable detector is available."
    assert SECRET not in json.dumps(unsupported.to_dict())


def test_public_diagnostics_never_reflect_extension_class_names_or_reprs(caplog):
    class_secret = "PRIVATE_BEARER_CREDENTIAL_8675309"

    def forbidden_representation(_self):
        raise AssertionError("public projection invoked an object representation")

    Gate = type(
        class_secret,
        (),
        {
            "capability": CapabilityManifest(
                identifier="privacy-gate",
                kind="quality_gate",
                metadata={"nested": {"api_key": SECRET}},
            ),
            "evaluate": lambda _self, _source, _candidate: None,
            "__repr__": forbidden_representation,
            "__deepcopy__": forbidden_representation,
        },
    )
    gate = Gate()
    config = DewatermarkConfig(quality_gate=gate, quality_gates=(gate,), chunker=gate)
    public_values = [
        config.to_dict(redact_secrets=False),
        quality_gate_conformance(gate),
        create_plan("plain source", mode="full", config=replace(config, chunker=None)),
        CapabilityManifest(
            identifier="privacy-manifest",
            kind="detector",
            metadata={"nested": {"value": gate, "password": SECRET}},
        ).to_dict(),
        ScanReport(
            0,
            (),
            configuration={"api_key": SECRET, "nested": {"value": gate}},
        ).to_dict(),
        ScannerConfig(source=SECRET).to_dict(),
    ]

    InvalidGate = type(
        class_secret,
        (),
        {
            "__repr__": forbidden_representation,
            "__deepcopy__": forbidden_representation,
        },
    )
    invalid_gate = InvalidGate()
    receipt_result = remove(
        "plain source",
        mode="sanitize",
        config=DewatermarkConfig(
            quality_gate=invalid_gate,
            quality_gates=(invalid_gate,),
            semantic_scorer=invalid_gate,
        ),
    )
    assert receipt_result.receipt is not None
    public_values.append(receipt_result.receipt.to_dict())

    Detector = type(
        class_secret,
        (),
        {
            "capability": CapabilityManifest(
                identifier="privacy-doctor-detector",
                kind="detector",
                schemes=("fixture",),
                metadata={"nested": {"credential": SECRET}},
            ),
            "__call__": lambda self, _config=None: self,
            "available": lambda _self: True,
            "detect": lambda _self, _text: 0.0,
            "__repr__": forbidden_representation,
        },
    )
    register_detector("privacy-doctor-detector", Detector)
    try:
        doctor_report = doctor_detectors()
        public_values.extend([doctor_report.to_dict(), repr(doctor_report)])
    finally:
        unregister_detector("privacy-doctor-detector")

    Broken = type(class_secret, (RuntimeError,), {})

    def broken_handler(_event):
        raise Broken(SECRET)

    runtime.emit(DewatermarkConfig(event_handler=broken_handler), "private-event")
    public_values.append(caplog.text)

    rendered = json.dumps(public_values, default=str)
    assert SECRET not in rendered
    assert class_secret not in rendered


def test_capability_credentials_and_host_paths_cannot_enter_plan_or_removal_json():
    credential = "sk-live-PRIVATE-CAPABILITY-CREDENTIAL-123456789"
    private_path = "/Users/private/Documents/secret-model.bin"

    class Detector:
        capability = CapabilityManifest(
            identifier=credential,
            kind="detector",
            version=private_path,
            schemes=(private_path,),
            description=f"credential {credential}",
            metadata={
                "note": credential,
                "model_path": private_path,
                "nested": [private_path, {private_path: credential}],
            },
        )

        def __init__(self, _config=None):
            pass

        def available(self):
            return True

        def detect(self, text):
            return DetectionEvidence(
                detector=self.capability.identifier,
                scheme=self.capability.schemes[0],
                status="not_detected",
                text_characters=len(text),
            )

    register_detector("public-capability-fixture", Detector)
    try:
        plan = create_plan(
            "plain source",
            mode="sanitize",
            detector="public-capability-fixture",
            config=DewatermarkConfig(),
        )
        result = remove(
            "plain source",
            mode="sanitize",
            detector="public-capability-fixture",
            config=DewatermarkConfig(),
        )
    finally:
        unregister_detector("public-capability-fixture")

    rendered = json.dumps([Detector.capability.to_dict(), plan, result.to_dict()])
    assert credential not in rendered
    assert private_path not in rendered
    assert Detector.capability.identifier == "redacted-identifier"
    assert "<redacted>" in rendered
