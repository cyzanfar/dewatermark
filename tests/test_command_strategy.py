from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from threading import Event

import jsonschema
import pytest

from dewatermark.command_strategy import (
    CommandStrategy,
    CommandStrategyConsentError,
    CommandStrategyContractError,
    CommandStrategyExecutionError,
    command_strategy_manifest,
    make_command_strategy_factory,
    strategy_configuration_sha256,
)
from dewatermark.config import DewatermarkConfig
from dewatermark.detector_session import SignalSpan
from dewatermark.models import CapabilityManifest
from dewatermark.optimizer import DetectorFeedback, SearchLimits, StrategyContext, mitigate
from dewatermark.request_context import RequestContext, ResourceBudgetExceeded, request_scope

PUBLIC_CONFIGURATION = {
    "algorithm": "fixture-rewriter-v1",
    "model_fingerprint": "fixture-public-model-id",
}
CONFIGURATION_SHA256 = strategy_configuration_sha256(PUBLIC_CONFIGURATION)
OFFLINE = DewatermarkConfig(
    local_lm_enabled=False,
    request_timeout=2,
    max_output_tokens=256,
    max_search_candidates=4,
)
PRIVATE_TEXT = "alpha blue beta blue gamma blue delta epsilon zeta eta theta"


@pytest.fixture
def command_fixture(tmp_path: Path) -> Path:
    script = tmp_path / "command_strategy_fixture.py"
    script.write_text(
        "import json,os,sys,time\n"
        "from pathlib import Path\n"
        "mode=sys.argv[1]\n"
        "marker=Path(sys.argv[2])\n"
        "raw=sys.stdin.buffer.read()\n"
        "p=json.loads(raw)\n"
        "record={'request':p,'environment':dict(os.environ)} if mode=='environment' else p\n"
        "marker.write_text(json.dumps(record,sort_keys=True),encoding='utf-8')\n"
        f"fp={CONFIGURATION_SHA256!r}\n"
        "base={'protocol_version':'1.0','action':'generate.result',"
        "'strategy':'fixture-command-strategy','configuration_sha256':fp}\n"
        "text=p.get('text','')\n"
        "base['candidates']=[text.replace('blue','teal',1),text]\n"
        "if mode=='timeout': time.sleep(3)\n"
        "if mode=='stderr': print('private-body='+text,file=sys.stderr);sys.exit(7)\n"
        "if mode=='large_stdout': sys.stdout.write('x'*8192);sys.exit(0)\n"
        "if mode=='invalid_json': sys.stdout.write('private-body='+text);sys.exit(0)\n"
        "if mode=='non_utf8': sys.stdout.buffer.write(b'\\xff\\xfe');sys.exit(0)\n"
        "if mode=='duplicate':\n"
        " good=json.dumps(base,separators=(',',':'))\n"
        ' sys.stdout.write(good.replace(\'"action"\',\'"protocol_version":"1.0","action"\',1));sys.exit(0)\n'
        "if mode=='nan': sys.stdout.write('{\"value\":NaN}');sys.exit(0)\n"
        "if mode=='unknown': base['extra']='private-response'\n"
        "if mode=='wrong_version': base['protocol_version']='2.0'\n"
        "if mode=='wrong_action': base['action']='rewrite.result'\n"
        "if mode=='wrong_strategy': base['strategy']='other-strategy'\n"
        "if mode=='wrong_fingerprint': base['configuration_sha256']='0'*64\n"
        "if mode=='candidate_type': base['candidates']=[{'text':text}]\n"
        "if mode=='too_many': base['candidates']=['x']*(p['policy']['max_candidates']+1)\n"
        "if mode=='too_long': base['candidates']=['x'*(p['policy']['max_candidate_characters']+1)]\n"
        "if mode=='aggregate': base['candidates']=['12345678','abcdefgh']\n"
        "if mode=='output_tokens': base['candidates']=['x'*200]\n"
        "if mode=='surrogate': base['candidates']=['\\ud800']\n"
        "json.dump(base,sys.stdout,ensure_ascii=True,separators=(',',':'))\n",
        encoding="utf-8",
    )
    return script


def _manifest(**overrides):
    values = {
        "identifier": "fixture-command-strategy",
        "configuration_sha256": CONFIGURATION_SHA256,
        "schemes": ("word-count-test",),
    }
    values.update(overrides)
    return command_strategy_manifest(**values)


def _context(candidate_limit=4):
    feedback = DetectorFeedback(
        detector="fixture-detector",
        status="detected",
        score=3.0,
        threshold=2.0,
        p_value=0.01,
        detection_margin=1.0,
        localization=(SignalSpan(6, 10, score=3.0, p_value=0.01),),
    )
    return StrategyContext(
        round_index=0,
        invocation_index=1,
        random_seed=13,
        candidate_limit=candidate_limit,
        feedback=feedback,
        source_localization=(SignalSpan(6, 10, p_value=0.01),),
    )


def _strategy(
    script: Path,
    marker: Path,
    mode="ok",
    *,
    manifest=None,
    config=OFFLINE,
    timeout_seconds=0.5,
    max_stdout_bytes=4096,
    max_candidates=3,
    max_candidate_characters=1000,
    max_aggregate_candidate_characters=3000,
):
    return CommandStrategy(
        (sys.executable, str(script), mode, str(marker), "argv-private-sentinel"),
        manifest or _manifest(),
        config,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=512,
        max_candidates=max_candidates,
        max_candidate_characters=max_candidate_characters,
        max_aggregate_candidate_characters=max_aggregate_candidate_characters,
    )


def test_static_construction_availability_request_and_response(command_fixture, tmp_path):
    marker = tmp_path / "request.json"
    strategy = _strategy(command_fixture, marker)

    assert strategy.capability.identifier == "fixture-command-strategy"
    assert strategy.available() is True
    assert "argv-private-sentinel" not in repr(strategy)
    assert not marker.exists()

    candidates = strategy.generate(PRIVATE_TEXT, context=_context())

    assert candidates == (PRIVATE_TEXT.replace("blue", "teal", 1), PRIVATE_TEXT)
    request = json.loads(marker.read_text(encoding="utf-8"))
    assert request["action"] == "generate"
    assert request["text"] == PRIVATE_TEXT
    assert request["configuration_sha256"] == CONFIGURATION_SHA256
    assert request["policy"]["max_candidates"] == 3
    assert request["policy"]["allow_network"] is False
    assert request["policy"]["allow_model_download"] is False
    assert request["context"] == {
        "round_index": 0,
        "invocation_index": 1,
        "random_seed": 13,
        "candidate_limit": 3,
        "detector_feedback": {
            "detector": "fixture-detector",
            "status": "detected",
            "score": 3.0,
            "threshold": 2.0,
            "p_value": 0.01,
            "detection_margin": 1.0,
            "localization": [{"start": 6, "end": 10, "score": 3.0, "p_value": 0.01}],
        },
        "source_localization": [{"start": 6, "end": 10, "p_value": 0.01}],
    }

    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "command-strategy-protocol-v1.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(request, schema)


def test_factory_is_static_and_never_launches(command_fixture, tmp_path):
    marker = tmp_path / "factory.json"
    factory = make_command_strategy_factory(
        (sys.executable, str(command_fixture), "ok", str(marker)),
        _manifest(),
        max_candidate_characters=1000,
        max_aggregate_candidate_characters=3000,
    )

    assert not marker.exists()
    assert "factory.json" not in repr(factory)
    strategy = factory(OFFLINE)
    assert strategy.available()
    assert not marker.exists()


@pytest.mark.parametrize("requirement", ["network", "download", "secret"])
def test_requirements_fail_before_launch(command_fixture, tmp_path, monkeypatch, requirement):
    marker = tmp_path / "denied.json"
    manifest = _manifest(
        network_required=requirement == "network",
        model_download_possible=requirement == "download",
        requires_secret=requirement == "secret",
    )
    invoked = False

    def forbidden(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("denied strategy must not launch")

    monkeypatch.setattr("dewatermark.bounded_process.subprocess.Popen", forbidden)
    with pytest.raises(CommandStrategyConsentError):
        _strategy(command_fixture, marker, manifest=manifest).generate(
            PRIVATE_TEXT, context=_context()
        )
    assert invoked is False
    assert not marker.exists()


def test_explicit_network_and_model_consent_use_shared_accounting(command_fixture, tmp_path):
    marker = tmp_path / "accounted.json"
    config = replace(
        OFFLINE,
        allow_remote_processing=True,
        allow_model_download=True,
        max_remote_calls=2,
    )
    strategy = _strategy(
        command_fixture,
        marker,
        manifest=_manifest(network_required=True, model_download_possible=True),
        config=config,
    )
    context = RequestContext.from_config(config)

    with request_scope(context):
        candidates = strategy.generate(PRIVATE_TEXT, context=_context())

    assert candidates
    ledger = context.ledger()
    assert ledger["remote_calls_used"] == 1
    assert len(ledger["model_accesses"]) == 1
    assert ledger["model_accesses"][0]["download_allowed"] is True
    assert ledger["token_usage"]["completion_tokens"] > 0
    assert ledger["token_usage"]["completion_tokens_reserved"] == 0
    assert ledger["token_usage"]["usage_reports"] == 1


@pytest.mark.parametrize("termination", ("deadline", "cancellation"))
def test_valid_strategy_output_is_rejected_if_request_ends_before_acceptance(
    command_fixture,
    tmp_path,
    monkeypatch,
    termination,
):
    config = replace(OFFLINE, allow_remote_processing=True, max_remote_calls=2)
    strategy = _strategy(
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
            "protocol_version": "1.0",
            "action": "generate.result",
            "strategy": request["strategy"],
            "configuration_sha256": request["configuration_sha256"],
            "candidates": ["valid completed candidate"],
        }
        if termination == "deadline":
            active.deadline = time.monotonic() - 1
        else:
            cancel_event.set()
        return json.dumps(response).encode("ascii")

    monkeypatch.setattr("dewatermark.command_strategy._run", completed_run)
    expected_error = ResourceBudgetExceeded if termination == "deadline" else asyncio.CancelledError

    with request_scope(active):
        with pytest.raises(expected_error):
            strategy.generate(PRIVATE_TEXT, context=_context())

    ledger = active.ledger()
    assert ledger["remote_calls_used"] == 1
    assert ledger["token_usage"]["completion_tokens"] == config.max_output_tokens
    assert ledger["token_usage"]["total_tokens"] == config.max_output_tokens
    assert ledger["token_usage"]["completion_tokens_reserved"] == 0
    assert ledger["token_usage"]["usage_reports"] == 1
    assert ledger["deadline_exceeded"] is (termination == "deadline")
    assert ledger["cancelled"] is (termination == "cancellation")


@pytest.mark.parametrize(
    ("adapter_allows", "request_allows"),
    ((True, False), (False, True)),
    ids=("permissive-adapter-strict-request", "strict-adapter-permissive-request"),
)
def test_nested_consent_is_intersected_in_strategy_policy_and_model_accounting(
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
    strategy = _strategy(
        command_fixture,
        marker,
        manifest=_manifest(metadata={"resource_accounting": "model"}),
        config=adapter_config,
    )
    active = RequestContext.from_config(request_config)

    with request_scope(active):
        candidates = strategy.generate(PRIVATE_TEXT, context=_context())

    assert candidates
    request = json.loads(marker.read_text(encoding="utf-8"))
    assert request["policy"]["allow_network"] is False
    assert request["policy"]["allow_model_download"] is False
    assert active.model_accesses == [
        {
            "model_sha256": hashlib.sha256(
                strategy.capability.identifier.encode("utf-8")
            ).hexdigest(),
            "cached": True,
            "download_allowed": False,
        }
    ]


@pytest.mark.parametrize(
    ("adapter_allows", "request_allows"),
    ((True, False), (False, True)),
    ids=("permissive-adapter-strict-request", "strict-adapter-permissive-request"),
)
@pytest.mark.parametrize("requirement", ("network", "download"))
def test_nested_required_strategy_permission_is_denied_before_launch(
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
    strategy = _strategy(
        command_fixture,
        marker,
        manifest=_manifest(
            network_required=requirement == "network",
            model_download_possible=requirement == "download",
        ),
        config=adapter_config,
    )
    invoked = False

    def forbidden(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("denied strategy must not launch")

    monkeypatch.setattr("dewatermark.bounded_process.subprocess.Popen", forbidden)
    active = RequestContext.from_config(request_config)
    with request_scope(active):
        with pytest.raises(CommandStrategyConsentError):
            strategy.generate(PRIVATE_TEXT, context=_context())

    assert invoked is False
    assert not marker.exists()
    assert active.remote_calls == 0
    assert active.model_accesses == []


def test_command_receives_only_minimal_environment(command_fixture, tmp_path, monkeypatch):
    marker = tmp_path / "environment.json"
    monkeypatch.setenv("GITHUB_TOKEN", "private-ci-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "private-cloud-secret")
    monkeypatch.setenv("UNDECLARED_VALUE", "private-value")

    _strategy(command_fixture, marker, mode="environment").generate(
        PRIVATE_TEXT, context=_context()
    )

    environment = json.loads(marker.read_text(encoding="utf-8"))["environment"]
    allowed = {"PATH"}
    if sys.platform == "win32":
        allowed.update({"SYSTEMROOT", "WINDIR", "PATHEXT"})
    elif sys.platform in {"darwin", "linux"}:
        allowed.add("LC_CTYPE")
        if sys.platform == "darwin":
            allowed.add("__CF_USER_TEXT_ENCODING")
    assert set(environment).issubset(allowed)
    assert "PATH" in environment
    assert "private-ci-token" not in json.dumps(environment)
    assert "private-cloud-secret" not in json.dumps(environment)


@pytest.mark.parametrize(
    "mode",
    [
        "invalid_json",
        "non_utf8",
        "duplicate",
        "nan",
        "unknown",
        "wrong_version",
        "wrong_action",
        "wrong_strategy",
        "wrong_fingerprint",
        "candidate_type",
        "surrogate",
    ],
)
def test_malformed_closed_json_is_rejected_without_reflection(command_fixture, tmp_path, mode):
    marker = tmp_path / f"{mode}.json"
    strategy = _strategy(command_fixture, marker, mode=mode)

    with pytest.raises(CommandStrategyContractError) as caught:
        strategy.generate(PRIVATE_TEXT, context=_context())

    rendered = str(caught.value)
    assert PRIVATE_TEXT not in rendered
    assert "argv-private-sentinel" not in rendered
    assert "private-response" not in rendered


def test_candidate_count_character_aggregate_and_token_limits(command_fixture, tmp_path):
    cases = (
        ("too_many", {}, "too many"),
        (
            "too_long",
            {
                "max_candidate_characters": 16,
                "max_aggregate_candidate_characters": 32,
            },
            "character limit",
        ),
        (
            "aggregate",
            {
                "max_candidate_characters": 10,
                "max_aggregate_candidate_characters": 12,
            },
            "aggregate",
        ),
        ("output_tokens", {"config": replace(OFFLINE, max_output_tokens=32)}, "output-token"),
    )
    for mode, overrides, message in cases:
        strategy = _strategy(command_fixture, tmp_path / f"{mode}.json", mode, **overrides)
        with pytest.raises(CommandStrategyContractError, match=message):
            strategy.generate(PRIVATE_TEXT, context=_context())


@pytest.mark.parametrize("mode", ["stderr", "invalid_json"])
def test_stderr_and_response_body_are_redacted(command_fixture, tmp_path, mode):
    marker = tmp_path / f"redact-{mode}.json"
    strategy = _strategy(command_fixture, marker, mode)

    with pytest.raises((CommandStrategyExecutionError, CommandStrategyContractError)) as caught:
        strategy.generate(PRIVATE_TEXT, context=_context())

    assert PRIVATE_TEXT not in str(caught.value)
    assert "argv-private-sentinel" not in str(caught.value)


def test_timeout_and_stdout_are_bounded(command_fixture, tmp_path):
    timeout = _strategy(
        command_fixture,
        tmp_path / "timeout.json",
        "timeout",
        timeout_seconds=0.05,
    )
    with pytest.raises(CommandStrategyExecutionError, match="timed out"):
        timeout.generate(PRIVATE_TEXT, context=_context())

    large = _strategy(
        command_fixture,
        tmp_path / "large.json",
        "large_stdout",
        max_stdout_bytes=128,
    )
    with pytest.raises(CommandStrategyExecutionError, match="output limit"):
        large.generate(PRIVATE_TEXT, context=_context())


def test_invalid_options_context_unicode_and_argv_fail_without_launch(command_fixture, tmp_path):
    marker = tmp_path / "invalid-input.json"
    strategy = _strategy(command_fixture, marker)

    with pytest.raises(CommandStrategyContractError, match="options channel"):
        strategy.generate(PRIVATE_TEXT, context=_context(), api_key="private")
    with pytest.raises(CommandStrategyContractError, match="context"):
        strategy.generate(PRIVATE_TEXT, context=object())  # type: ignore[arg-type]
    with pytest.raises(CommandStrategyContractError, match="Unicode"):
        strategy.generate("private\ud800", context=_context())
    assert not marker.exists()

    with pytest.raises(TypeError, match="tuple"):
        CommandStrategy(  # type: ignore[arg-type]
            [sys.executable, str(command_fixture)], _manifest(), OFFLINE
        )

    class StringSubclass(str):
        pass

    with pytest.raises(ValueError, match="exact"):
        CommandStrategy((StringSubclass(sys.executable),), _manifest(), OFFLINE)

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
            CommandStrategy(command, _manifest(), OFFLINE)
    CommandStrategy((sys.executable, "--key-file", "operator-key.json"), _manifest(), OFFLINE)
    assert not marker.exists()


def test_public_configuration_fingerprint_refuses_secret_fields():
    assert len(strategy_configuration_sha256(PUBLIC_CONFIGURATION)) == 64
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
            strategy_configuration_sha256(configuration)

    assert len(strategy_configuration_sha256({"key_id": "operator-key-2026"})) == 64


class _WordDetector:
    def __init__(self, identifier):
        self.capability = CapabilityManifest(
            identifier=identifier,
            kind="detector",
            schemes=("word-count-test",),
            calibrated=True,
            independent=True,
            metadata={
                "configuration_sha256": hashlib.sha256(identifier.encode()).hexdigest(),
                "resource_accounting": "none",
                "score_direction": "higher",
                "threshold": 2.0,
                "threshold_operator": ">=",
                "watermark_target_sha256": "d" * 64,
            },
        )

    def available(self):
        return True

    def detect(self, text):
        score = float(text.count("blue"))
        return {
            "scheme": "word-count-test",
            "status": "detected" if score >= 2 else "not_detected",
            "score": score,
            "threshold": 2.0,
            "score_direction": "higher",
        }


class _HeldoutWordDetector(_WordDetector):
    def detect(self, text):
        return super().detect(text)


def test_command_strategy_integrates_with_central_optimizer(command_fixture, tmp_path):
    marker = tmp_path / "optimizer.json"
    strategy = _strategy(command_fixture, marker)

    result = mitigate(
        PRIVATE_TEXT,
        _WordDetector("command-primary"),
        [strategy],
        verifier_detectors=[_HeldoutWordDetector("command-heldout")],
        config=OFFLINE,
        limits=SearchLimits(max_rounds=3, max_candidates=6, max_transform_calls=6),
    )

    assert result.status == "verified"
    assert result.cleaned_text.count("blue") == 1
    assert result.receipt.selected_strategy == "fixture-command-strategy"
    assert PRIVATE_TEXT not in json.dumps(result.receipt.to_dict())
