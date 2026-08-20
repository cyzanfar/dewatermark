from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from dewatermark.command_detector import CommandDetector, command_detector_manifest
from dewatermark.detector_session import DetectorSession
from dewatermark.models import CapabilityManifest
from dewatermark.optimizer import DetectorFeedback, StrategyContext
from dewatermark.strategies import context_aware_strategy

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "adapters" / "synthid"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def adapter() -> Any:
    return _load(PACK / "operator_adapter.py", "synthid_operator_test")


def _configuration(adapter: Any, **updates: Any) -> dict[str, Any]:
    files = {"tokenizer.json": "1" * 64}
    value: dict[str, Any] = {
        "attribution_kind": "token_character_spans",
        "byteorder": sys.byteorder,
        "context_history_size": 8,
        "context_repetition_handling": "bounded_fifo_context_hash_v1",
        "detector_type": "mean",
        "detector_text_tokenization": "retokenize_add_special_tokens_false_fast_offsets_v1",
        "eos_handling": "mask_first_eos_and_after",
        "eos_token_id": 2,
        "generation_apply_top_k": True,
        "generation_num_leaves": 2,
        "generation_skip_first_ngram_calls": False,
        "generation_temperature": 0.7,
        "generation_text_serialization": (
            "tokenizer_decode_skip_special_tokens_false_cleanup_false_utf8_v1"
        ),
        "generation_top_k": 40,
        "identifier": "operator/synthid-text-mean-v1",
        "key_id": "0123456789abcdef0123456789abcdef",
        "maximum_effective_tokens": 128,
        "maximum_attributions": 3,
        "maximum_input_tokens": 1024,
        "minimum_effective_tokens": 2,
        "ngram_len": 3,
        "offset_mapping": "huggingface_fast_offsets_v1",
        "platform_machine": platform.machine(),
        "platform_system": platform.system(),
        "python_version": platform.python_version(),
        "schema_version": "1.0",
        "scheme": "synthid-text/public-reference-v1",
        "score_direction": "higher",
        "scorer_semantics": adapter.SCORER_SEMANTICS,
        "secret_binding_id": "abcdef0123456789abcdef0123456789",
        "special_token_handling": "tokenizer_add_special_tokens_false",
        "source_files_sha256": dict(adapter.UPSTREAM_SOURCE_SHA256),
        "threshold": 0.5,
        "threshold_evidence_sha256": "2" * 64,
        "threshold_operator": ">",
        "text_scope": "candidate_text_only_no_prompt",
        "tokenizer_conformance_sha256": "3" * 64,
        "tokenizer_files": files,
        "tokenizer_revision": "fixture-tokenizer-v1",
        "tokenizer_snapshot_sha256": adapter._sha256(adapter._canonical(files)),
        "tokenizer_type": "transformers_local_files_v1",
        "tokenizers_version": "1.0.0",
        "transformers_version": "1.0.0",
        "upstream_repository": adapter.UPSTREAM_REPOSITORY,
        "upstream_revision": adapter.UPSTREAM_REVISION,
        "vocab_size": 256,
        "watermarking_depth": 3,
        "weights": [],
    }
    value.update(updates)
    value["watermark_target_sha256"] = adapter._sha256(
        adapter._canonical(adapter._target_material(value))
    )
    value["configuration_sha256"] = adapter._sha256(adapter._canonical(value))
    return value


def _request(configuration: dict[str, Any], text: str = "public fixture") -> dict[str, Any]:
    return {
        "action": "detect",
        "attribution": {
            "kind": configuration["attribution_kind"],
            "maximum_attributions": configuration["maximum_attributions"],
        },
        "configuration_sha256": configuration["configuration_sha256"],
        "detector": configuration["identifier"],
        "policy": {"allow_model_download": False, "allow_network": False},
        "protocol_version": "1.2",
        "text": text,
    }


def test_public_conformance_replays_hash_masks_and_both_mean_paths():
    conformance = _load(PACK / "conformance.py", "synthid_conformance_test")

    report = conformance.run(PACK)

    assert report["passed"] is True
    assert report["case_count"] == 6
    assert len(report["vectors_sha256"]) == 64
    assert len(report["implementation_sha256"]) == 64
    assert set(report) == {
        "case_count",
        "fixture_ids_sha256",
        "implementation_sha256",
        "passed",
        "report_sha256",
        "schema_version",
        "scorer_semantics",
        "source_files_sha256",
        "upstream_revision",
        "vectors_sha256",
    }


def test_scorer_applies_bounded_repetition_and_first_eos_masks(adapter):
    repeated = adapter.score_token_ids(
        [7, 8, 9, 7, 8, 9, 7, 8, 9, 42, 43, 44],
        keys=[1, 2, 3, 4],
        ngram_len=3,
        context_history_size=3,
        eos_token_id=999,
        detector_type="mean",
        weights=[],
    )
    eos = adapter.score_token_ids(
        [5, 6, 7, 8, 9, 2, 11, 12, 13],
        keys=[987654321, 123456789],
        ngram_len=5,
        context_history_size=16,
        eos_token_id=2,
        detector_type="weighted_mean",
        weights=[10.0, 1.0],
    )

    assert repeated["mask"] == [1, 1, 1, 0, 0, 0, 0, 0, 1, 1]
    assert repeated["effective_tokens"] == 5
    assert repeated["score"] == 0.75
    assert eos["mask"] == [1, 0, 0, 0, 0]
    assert eos["effective_tokens"] == 1
    assert eos["score"] == pytest.approx(1 / 11)


def test_weight_normalization_rejects_overflow_and_handles_subnormal(adapter):
    assert adapter._valid_weights([1e308, 1e308], "weighted_mean", 2) is False
    assert adapter._valid_weights([10**10_000], "weighted_mean", 1) is False
    assert adapter._valid_weights([5e-324], "weighted_mean", 1) is True

    result = adapter.score_token_ids(
        [11, 12, 13, 14],
        keys=[12345],
        ngram_len=3,
        context_history_size=8,
        eos_token_id=99,
        detector_type="weighted_mean",
        weights=[5e-324],
    )

    assert isinstance(result["score"], float)
    assert adapter.math.isfinite(result["score"])

    binary64_edge = adapter.score_token_ids(
        [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        keys=[12345, 67890, 13579],
        ngram_len=4,
        context_history_size=8,
        eos_token_id=99,
        detector_type="mean",
        weights=[],
    )["score"]
    assert binary64_edge == 0.6666666666666666
    assert binary64_edge <= 0.66666668


def test_attribution_selects_top_token_contributions_then_orders_character_spans(adapter):
    text = "aa bb cc dd ee ff gg hh ii jj"
    offsets = [(index * 3, index * 3 + 2) for index in range(10)]
    result = adapter.score_token_ids(
        [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        keys=[12345, 67890, 13579],
        ngram_len=4,
        context_history_size=8,
        eos_token_id=99,
        detector_type="mean",
        weights=[],
    )

    spans = adapter._attributions(
        text,
        offsets,
        result,
        ngram_len=4,
        detector_type="mean",
        weights=[],
        maximum_attributions=3,
    )

    assert spans == [
        {"start": 9, "end": 11, "score": 1.0},
        {"start": 18, "end": 20, "score": 1.0},
        {"start": 27, "end": 29, "score": 1.0},
    ]
    with pytest.raises(ValueError, match="offset_mapping_invalid"):
        adapter._attributions(
            text,
            [*offsets[:4], (10, 13), *offsets[5:]],
            result,
            ngram_len=4,
            detector_type="mean",
            weights=[],
            maximum_attributions=3,
        )


def test_configuration_is_closed_and_binds_public_target(adapter):
    configuration = _configuration(adapter)

    assert adapter._validate_configuration(configuration) == configuration
    assert "keys" not in json.dumps(configuration)
    assert configuration["key_id"] == "0123456789abcdef0123456789abcdef"

    for mutation in (
        {"thresholds_by_effective_length": []},
        {"watermark_target_sha256": "f" * 64},
        {"identifier": "sk-live-PRIVATEIDENTIFIER123456789"},
        {"source_files_sha256": {**adapter.UPSTREAM_SOURCE_SHA256, "extra.py": "0" * 64}},
    ):
        changed = dict(configuration)
        changed.update(mutation)
        public = {key: item for key, item in changed.items() if key != "configuration_sha256"}
        changed["configuration_sha256"] = adapter._sha256(adapter._canonical(public))
        with pytest.raises(ValueError):
            adapter._validate_configuration(changed)


def test_target_is_generation_identity_not_detector_score_identity(adapter):
    mean = _configuration(adapter)
    weighted = _configuration(
        adapter,
        detector_type="weighted_mean",
        identifier="operator/synthid-text-weighted-mean-v1",
        threshold=0.75,
        weights=[10.0, 5.5, 1.0],
    )
    different_runtime = _configuration(adapter, tokenizers_version="1.0.1")

    assert mean["watermark_target_sha256"] == weighted["watermark_target_sha256"]
    assert mean["configuration_sha256"] != weighted["configuration_sha256"]
    assert mean["watermark_target_sha256"] != different_runtime["watermark_target_sha256"]
    target = adapter._target_material(mean)
    assert target["scheme"] == "synthid-text/public-reference-v1"
    assert "scorer_semantics" not in target
    assert "detector_type" not in target
    assert "weights" not in target
    assert set(target["generation_source_files_sha256"]) == {
        "src/synthid_text/hashing_function.py",
        "src/synthid_text/logits_processing.py",
    }


def test_configuration_rejects_vendor_names_and_modern_access_tokens(adapter):
    for updates in (
        {"identifier": "anthropic/claude-official"},
        {"identifier": "operator/synthid-text-mean-claude-official"},
        {"identifier": "operator/synthid-text-weighted-mean-gemini"},
        {"identifier": "operator/synthid-text-mean-v1", "scheme": "claude/synthid-production"},
        {"tokenizer_revision": "github_pat_PRIVATECREDENTIAL12345678901234567890"},
    ):
        changed = _configuration(adapter, **updates)
        with pytest.raises(ValueError):
            adapter._validate_configuration(changed)


@pytest.mark.skipif(os.name != "posix", reason="owner-only mode checks require POSIX")
def test_key_record_requires_owner_only_closed_json(adapter, tmp_path):
    key_file = tmp_path / "operator-key.json"
    key_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "key_id": "0123456789abcdef0123456789abcdef",
                "keys": [1, 2, 3],
            }
        ),
        encoding="ascii",
    )
    key_file.chmod(0o600)
    assert adapter._read_key_record(key_file) == (
        (1, 2, 3),
        "0123456789abcdef0123456789abcdef",
    )

    key_file.chmod(0o644)
    with pytest.raises(ValueError, match="key_unavailable"):
        adapter._read_key_record(key_file)
    key_file.chmod(0o600)
    key_file.write_text(
        '{"schema_version":"1.0","key_id":"0123456789abcdef0123456789abcdef",'
        '"keys":[1],"keys":[2]}',
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="key_unavailable"):
        adapter._read_key_record(key_file)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation requires POSIX")
@pytest.mark.parametrize("private", [False, True], ids=["public", "owner-only"])
def test_synthid_bounded_readers_reject_fifo_before_open(adapter, tmp_path, monkeypatch, private):
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo, 0o600)
    opened = False

    def unexpected_open(*_args, **_kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("FIFO must be rejected by lstat before open")

    monkeypatch.setattr(adapter.os, "open", unexpected_open)
    if private:
        with pytest.raises(ValueError) as raised:
            adapter._read_owner_only_record(fifo, 1024)
        assert str(raised.value) == "key_unavailable"
    else:
        with pytest.raises(ValueError) as raised:
            adapter._read_regular(fifo, 1024, "public_unavailable")
        assert str(raised.value) == "public_unavailable"
    assert opened is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation requires POSIX")
@pytest.mark.parametrize("private", [False, True], ids=["public", "owner-only"])
def test_synthid_bounded_readers_reject_fifo_replacement_without_blocking(
    adapter, tmp_path, monkeypatch, private
):
    selected = tmp_path / "input.json"
    selected.write_text("{}", encoding="ascii")
    selected.chmod(0o600)
    real_open = os.open
    replaced = False

    def replace_with_fifo(path, flags, *args, **kwargs):
        nonlocal replaced
        replaced = True
        assert flags & os.O_NONBLOCK
        assert flags & os.O_NOFOLLOW
        selected.unlink()
        os.mkfifo(selected, 0o600)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(adapter.os, "open", replace_with_fifo)
    if private:
        with pytest.raises(ValueError) as raised:
            adapter._read_owner_only_record(selected, 1024)
        assert str(raised.value) == "key_unavailable"
    else:
        with pytest.raises(ValueError) as raised:
            adapter._read_regular(selected, 1024, "public_unavailable")
        assert str(raised.value) == "public_unavailable"
    assert replaced is True


def test_tokenizer_snapshot_rejects_secrets_before_hashing(adapter, tmp_path):
    safe = tmp_path / "safe"
    safe.mkdir()
    (safe / "tokenizer.json").write_text('{"model":{"vocab":{"hello":0}}}', encoding="utf-8")
    snapshot = adapter._tokenizer_snapshot(safe)
    assert set(snapshot) == {"tokenizer.json"}

    binary = tmp_path / "binary"
    binary.mkdir()
    (binary / "sentencepiece.model").write_bytes(b"\x00\x01\xff\x10public-model-data")
    assert set(adapter._tokenizer_snapshot(binary)) == {"sentencepiece.model"}

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    (unsafe / "tokenizer.json").write_text(
        '{"authorization":"Bearer private-credential-value"}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="tokenizer_contains_unsafe_content"):
        adapter._tokenizer_snapshot(unsafe)

    named = tmp_path / "named"
    named.mkdir()
    (named / "api-key.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="tokenizer_contains_sensitive_file"):
        adapter._tokenizer_snapshot(named)

    modern = tmp_path / "modern"
    modern.mkdir()
    (modern / "tokenizer.json").write_text(
        '{"note":"github_pat_PRIVATECREDENTIAL12345678901234567890"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="tokenizer_contains_unsafe_content"):
        adapter._tokenizer_snapshot(modern)


def test_tokenizer_conformance_requires_decode_policy_and_usable_offsets(adapter):
    class BadOffsets:
        def __call__(self, text: str, **_kwargs: Any) -> dict[str, list[Any]]:
            return {"input_ids": [1, 2], "offset_mapping": [(0, 0), (0, 0)]}

        def decode(self, _ids: list[int], **_kwargs: Any) -> str:
            return "public"

    with pytest.raises(ValueError, match="tokenizer_conformance_failed"):
        adapter._tokenizer_conformance(BadOffsets())


def test_handle_is_offline_strict_and_uses_fixed_threshold(adapter, monkeypatch, tmp_path):
    configuration = _configuration(adapter)
    calls: list[str] = []

    class Tokenizer:
        def __call__(
            self, _text: str, *, add_special_tokens: bool, return_offsets_mapping: bool
        ) -> dict[str, list[Any]]:
            assert add_special_tokens is False
            assert return_offsets_mapping is True
            calls.append("tokenize")
            return {
                "input_ids": [11, 12, 13, 14, 15],
                "offset_mapping": [(0, 6), (7, 14), (0, 0), (0, 0), (0, 0)],
            }

    monkeypatch.setattr(
        adapter,
        "_load_key",
        lambda *_args: calls.append("key") or (12345, 67890, 13579),
    )
    monkeypatch.setattr(adapter, "_verify_sources", lambda *_args: calls.append("source"))
    monkeypatch.setattr(
        adapter, "_load_runtime", lambda *_args: calls.append("runtime") or Tokenizer()
    )
    monkeypatch.setattr(
        adapter,
        "score_token_ids",
        lambda *_args, **_kwargs: {
            "effective_tokens": 3,
            "g_values": [[1, 0, 1], [0, 1, 0], [1, 1, 0]],
            "mask": [1, 1, 1],
            "score": 0.5,
        },
    )

    response = adapter.handle(
        _request(configuration),
        configuration=configuration,
        upstream_dir=tmp_path,
        tokenizer_dir=tmp_path,
        key_file=tmp_path / "private-key.json",
        secret_binding_file=tmp_path / "private-binding.json",
    )
    assert calls == ["key", "source", "runtime", "tokenize"]
    assert response["status"] == "not_detected"
    assert response["threshold"] == 0.5
    assert response["threshold_operator"] == ">"
    assert set(response) == {
        "action",
        "attributions",
        "configuration_sha256",
        "detector",
        "effective_tokens",
        "protocol_version",
        "scheme",
        "score",
        "score_direction",
        "status",
        "threshold",
        "threshold_operator",
    }

    request = _request(configuration)
    request["policy"]["allow_network"] = True
    calls.clear()
    blocked = adapter.handle(
        request,
        configuration=configuration,
        upstream_dir=tmp_path,
        tokenizer_dir=tmp_path,
        key_file=tmp_path / "private-key.json",
        secret_binding_file=tmp_path / "private-binding.json",
    )
    assert blocked["status"] == "unsupported"
    assert blocked["reason_code"] == "offline_policy_required"
    assert calls == []


def test_handle_abstains_outside_sealed_effective_length(adapter, monkeypatch, tmp_path):
    configuration = _configuration(adapter, maximum_effective_tokens=4)
    monkeypatch.setattr(adapter, "_load_key", lambda *_args: (1, 2, 3))
    monkeypatch.setattr(adapter, "_verify_sources", lambda *_args: None)
    monkeypatch.setattr(
        adapter,
        "_load_runtime",
        lambda *_args: (
            lambda text, **_kwargs: {
                "input_ids": [1, 2, 3],
                "offset_mapping": [(0, min(1, len(text))), (0, 0), (0, 0)],
            }
        ),
    )
    effective = 1

    def score(*_args, **_kwargs):
        return {
            "effective_tokens": effective,
            "g_values": [[1, 1, 1]],
            "mask": [1],
            "score": 0.9,
        }

    monkeypatch.setattr(adapter, "score_token_ids", score)
    response = adapter.handle(
        _request(configuration),
        configuration=configuration,
        upstream_dir=tmp_path,
        tokenizer_dir=tmp_path,
        key_file=tmp_path / "key.json",
        secret_binding_file=tmp_path / "binding.json",
    )
    assert response["status"] == "insufficient_evidence"
    assert response["reason_code"] == "too_few_effective_tokens"

    effective = 5
    response = adapter.handle(
        _request(configuration),
        configuration=configuration,
        upstream_dir=tmp_path,
        tokenizer_dir=tmp_path,
        key_file=tmp_path / "key.json",
        secret_binding_file=tmp_path / "binding.json",
    )
    assert response["status"] == "unsupported"
    assert response["reason_code"] == "too_many_effective_tokens"


def test_short_tokenized_text_abstains_with_empty_attributions(adapter, monkeypatch, tmp_path):
    configuration = _configuration(adapter, minimum_effective_tokens=1)

    class Tokenizer:
        def __call__(self, _text: str, **_kwargs: Any) -> dict[str, list[Any]]:
            return {"input_ids": [11, 12], "offset_mapping": [(0, 3), (4, 7)]}

    monkeypatch.setattr(adapter, "_load_key", lambda *_args: (1, 2, 3))
    monkeypatch.setattr(adapter, "_verify_sources", lambda *_args: None)
    monkeypatch.setattr(adapter, "_load_runtime", lambda *_args: Tokenizer())

    response = adapter.handle(
        _request(configuration, "one two"),
        configuration=configuration,
        upstream_dir=tmp_path,
        tokenizer_dir=tmp_path,
        key_file=tmp_path / "key.json",
        secret_binding_file=tmp_path / "binding.json",
    )

    assert response["status"] == "insufficient_evidence"
    assert response["reason_code"] == "too_few_effective_tokens"
    assert response["attributions"] == []


def test_swapped_key_fails_before_source_or_tokenizer_access(adapter, monkeypatch, tmp_path):
    configuration = _configuration(adapter)
    key_file = tmp_path / "key.json"
    key_file.write_text(
        json.dumps(
            {
                "key_id": configuration["key_id"],
                "keys": [101, 202, 303],
                "schema_version": "1.0",
            }
        ),
        encoding="ascii",
    )
    key_file.chmod(0o600)
    binding = tmp_path / "binding.json"
    binding.write_text(
        json.dumps(
            {
                "binding_id": configuration["secret_binding_id"],
                "configuration_sha256": configuration["configuration_sha256"],
                "key_id": configuration["key_id"],
                "key_material_sha256": adapter._sha256(adapter._canonical({"keys": [1, 2, 3]})),
                "schema_version": "1.0",
            }
        ),
        encoding="ascii",
    )
    binding.chmod(0o600)
    monkeypatch.setattr(
        adapter,
        "_verify_sources",
        lambda *_args: pytest.fail("source must not be read after key mismatch"),
    )
    monkeypatch.setattr(
        adapter,
        "_load_runtime",
        lambda *_args: pytest.fail("tokenizer must not load after key mismatch"),
    )

    response = adapter.handle(
        _request(configuration),
        configuration=configuration,
        upstream_dir=tmp_path,
        tokenizer_dir=tmp_path,
        key_file=key_file,
        secret_binding_file=binding,
    )

    assert response["status"] == "detector_error"
    assert response["reason_code"] == "operator_runtime_failed"


def test_synthid_attribution_reaches_context_aware_minimal_edit(adapter, monkeypatch, tmp_path):
    import dewatermark.command_detector as command_runtime

    source = "However signal prose remains clear."
    configuration = _configuration(
        adapter,
        context_history_size=8,
        maximum_attributions=1,
        minimum_effective_tokens=1,
        ngram_len=2,
        threshold=0.2,
        watermarking_depth=1,
    )

    class Tokenizer:
        def __call__(self, text: str, **_kwargs: Any) -> dict[str, list[Any]]:
            assert text == source
            return {
                "input_ids": [1, 2, 3, 4, 5],
                "offset_mapping": [(0, 7), (8, 14), (15, 20), (21, 28), (29, 34)],
            }

    monkeypatch.setattr(adapter, "_load_key", lambda *_args: (12345,))
    monkeypatch.setattr(adapter, "_verify_sources", lambda *_args: None)
    monkeypatch.setattr(adapter, "_load_runtime", lambda *_args: Tokenizer())
    monkeypatch.setattr(
        adapter,
        "score_token_ids",
        lambda *_args, **_kwargs: {
            "effective_tokens": 4,
            "g_values": [[1], [0], [0], [0]],
            "mask": [1, 1, 1, 1],
            "score": 0.25,
        },
    )

    def execute(_command, payload, **_limits):
        request = json.loads(payload)
        response = adapter.handle(
            request,
            configuration=configuration,
            upstream_dir=tmp_path,
            tokenizer_dir=tmp_path,
            key_file=tmp_path / "key.json",
            secret_binding_file=tmp_path / "binding.json",
        )
        return json.dumps(response).encode("ascii")

    monkeypatch.setattr(command_runtime, "_run_bounded_command", execute)
    manifest = command_detector_manifest(
        identifier=configuration["identifier"],
        schemes=(configuration["scheme"],),
        configuration_sha256=configuration["configuration_sha256"],
        implementation_sha256="4" * 64,
        threshold=configuration["threshold"],
        threshold_operator=">",
        minimum_effective_tokens=configuration["minimum_effective_tokens"],
        attribution_kind="token_character_spans",
        maximum_attributions=configuration["maximum_attributions"],
        requires_secret=True,
        secret_binding="operator_managed_file",
        watermark_target_sha256=configuration["watermark_target_sha256"],
    )
    detector = CommandDetector((sys.executable, str(PACK / "operator_adapter.py")), manifest)

    observation = DetectorSession(detector, max_queries=1).score(source)
    assert [span.to_dict() for span in observation.localization] == [
        {"start": 8, "end": 14, "score": 1.0}
    ]
    context = StrategyContext(
        round_index=0,
        invocation_index=1,
        random_seed=7,
        candidate_limit=2,
        feedback=DetectorFeedback.from_observation(observation),
    )
    strategy = context_aware_strategy(context_influence=1, max_edits=1, max_candidates=2)
    assert strategy.generate(source, context=context) == ("Yet signal prose remains clear.",)


@pytest.mark.skipif(os.name != "posix", reason="owner-only sealing requires POSIX")
def test_sealer_emits_private_key_free_false_claims_transactionally(monkeypatch, tmp_path, adapter):
    sealer = _load(PACK / "seal_operator.py", "synthid_sealer_test")
    key_file = tmp_path / "key.json"
    key_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "key_id": "0123456789abcdef0123456789abcdef",
                "keys": [11, 22, 33],
            }
        ),
        encoding="ascii",
    )
    key_file.chmod(0o600)
    evidence = tmp_path / "evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "detector_type": "mean",
                "empirical_calibration": True,
                "evidence_id": "abcdef0123456789abcdef0123456789",
                "maximum_effective_tokens": 128,
                "minimum_effective_tokens": 2,
                "schema_version": "1.0",
                "score": "mean_g_value",
                "threshold": 0.5,
                "threshold_operator": ">",
            }
        ),
        encoding="ascii",
    )
    tokenizer_dir = tmp_path / "tokenizer"
    tokenizer_dir.mkdir()
    (tokenizer_dir / "tokenizer.json").write_text(
        '{"model":{"vocab":{"hello":0}}}', encoding="utf-8"
    )
    monkeypatch.setattr(adapter, "_verify_sources", lambda _path: None)
    report = {
        "case_count": 5,
        "implementation_sha256": "4" * 64,
        "passed": True,
        "report_sha256": "5" * 64,
        "vectors_sha256": "6" * 64,
    }
    conformance = SimpleNamespace(run=lambda _directory: report)
    modules = iter((adapter, conformance))
    monkeypatch.setattr(sealer, "_load_module", lambda *_args: next(modules))

    class FakeTokenizer:
        eos_token_id = 2
        is_fast = True

        def __len__(self) -> int:
            return 256

        def __call__(self, text: str, **_kwargs: Any) -> dict[str, list[Any]]:
            return {
                "input_ids": [(ord(character) % 250) + 3 for character in text],
                "offset_mapping": [(index, index + 1) for index in range(len(text))],
            }

        def decode(self, _token_ids: list[int], **kwargs: Any) -> str:
            assert kwargs == {
                "skip_special_tokens": False,
                "clean_up_tokenization_spaces": False,
            }
            return "decoded public fixture"

    fake_transformers = SimpleNamespace(
        __version__="1.0.0",
        AutoTokenizer=SimpleNamespace(from_pretrained=lambda *_args, **_kwargs: FakeTokenizer()),
    )
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)
    monkeypatch.setitem(sys.modules, "tokenizers", SimpleNamespace(__version__="1.0.0"))
    monkeypatch.setattr(sealer.secrets, "token_hex", lambda _size: "a" * 32)
    output = tmp_path / "sealed"
    binding_output = tmp_path / "private-binding.json"
    args = argparse.Namespace(
        context_history_size=8,
        detector_type="mean",
        eos_token_id=2,
        generation_apply_top_k=True,
        generation_num_leaves=2,
        generation_skip_first_ngram_calls=False,
        generation_temperature=0.7,
        generation_top_k=40,
        identifier="operator/synthid-text-mean-v1",
        key_file=key_file,
        maximum_effective_tokens=128,
        maximum_attributions=3,
        maximum_input_tokens=1024,
        minimum_effective_tokens=2,
        ngram_len=3,
        output_dir=output,
        scheme="synthid-text/public-reference-v1",
        secret_binding_output=binding_output,
        threshold=0.5,
        threshold_evidence=evidence,
        tokenizer_dir=tokenizer_dir,
        tokenizer_revision="fixture-tokenizer-v1",
        upstream_dir=tmp_path / "upstream",
        vocab_size=256,
        watermarking_depth=3,
        weights_json=None,
    )

    sealer.seal(args)

    assert sorted(path.name for path in output.iterdir()) == [
        "operator-capability.json",
        "operator-config.json",
    ]
    configuration = json.loads((output / "operator-config.json").read_text(encoding="ascii"))
    capability = json.loads((output / "operator-capability.json").read_text(encoding="ascii"))
    assert adapter._validate_configuration(configuration) == configuration
    manifest = CapabilityManifest(**capability)
    detector = CommandDetector(
        (
            sys.executable,
            str(PACK / "operator_adapter.py"),
            "--configuration",
            str(output / "operator-config.json"),
            "--upstream-dir",
            str(args.upstream_dir),
            "--tokenizer-dir",
            str(tokenizer_dir),
            "--key-file",
            str(key_file),
            "--secret-file",
            str(binding_output),
        ),
        manifest,
    )
    assert detector.capability.metadata["command_protocol_version"] == "1.2"
    assert detector.capability.metadata["attribution_kind"] == "token_character_spans"
    assert detector.capability.metadata["maximum_attributions"] == 3
    assert capability["calibrated"] is False
    assert capability["independent"] is False
    assert capability["metadata"]["production_detection"] is False
    assert capability["metadata"]["vendor_equivalent"] is False
    assert capability["network_required"] is False
    assert capability["model_download_possible"] is False
    assert binding_output.stat().st_mode & 0o777 == 0o600
    assert adapter._load_key(key_file, binding_output, configuration) == (11, 22, 33)
    public = json.dumps([configuration, capability], sort_keys=True)
    assert "[11, 22, 33]" not in public
    key_material_sha256 = adapter._sha256(adapter._canonical({"keys": [11, 22, 33]}))
    assert key_material_sha256 not in public
    assert capability["metadata"]["key_id"] == "0123456789abcdef0123456789abcdef"
    assert capability["metadata"]["implementation_sha256"] != report["implementation_sha256"]

    substituted = tmp_path / "substituted-key.json"
    substituted.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "key_id": "0123456789abcdef0123456789abcdef",
                "keys": [101, 202, 303],
            }
        ),
        encoding="ascii",
    )
    substituted.chmod(0o600)
    with pytest.raises(ValueError, match="key_mismatch"):
        adapter._load_key(substituted, binding_output, configuration)

    with pytest.raises(ValueError, match="already exists"):
        sealer._publish_seal(
            output,
            tmp_path / "unused-binding.json",
            configuration,
            capability,
            {},
            adapter.MAX_CONFIGURATION_BYTES,
            adapter.MAX_BINDING_BYTES,
        )


@pytest.mark.skipif(os.name != "posix", reason="owner-only sealing requires POSIX")
def test_sealer_rolls_back_interrupted_pair_publication(monkeypatch, tmp_path):
    sealer = _load(PACK / "seal_operator.py", "synthid_sealer_rollback_test")
    output = tmp_path / "sealed"
    binding = tmp_path / "binding.json"
    monkeypatch.setattr(
        sealer.os,
        "rename",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture interruption")),
    )
    with pytest.raises(OSError, match="fixture interruption"):
        sealer._publish_seal(
            output,
            binding,
            {"one": 1},
            {"two": 2},
            {"private": 3},
            1024,
            1024,
        )
    assert not output.exists()
    assert not binding.exists()
    assert not list(tmp_path.glob(".dewatermark-synthid-seal-*"))


def test_sealer_refuses_private_binding_replacement(tmp_path):
    sealer = _load(PACK / "seal_operator.py", "synthid_sealer_replacement_test")
    output = tmp_path / "sealed"
    binding = tmp_path / "binding.json"
    binding.write_text("existing private record", encoding="ascii")
    binding.chmod(0o600)

    with pytest.raises(ValueError, match="already exists"):
        sealer._publish_seal(
            output,
            binding,
            {"one": 1},
            {"two": 2},
            {"private": 3},
            1024,
            1024,
        )

    assert binding.read_text(encoding="ascii") == "existing private record"
    assert not output.exists()


def test_threshold_evidence_rejects_boolean_numbers(adapter):
    sealer = _load(PACK / "seal_operator.py", "synthid_threshold_evidence_test")
    args = argparse.Namespace(
        detector_type="mean",
        maximum_effective_tokens=1,
        minimum_effective_tokens=1,
        threshold=1.0,
    )
    evidence = {
        "detector_type": "mean",
        "empirical_calibration": False,
        "evidence_id": "0" * 32,
        "maximum_effective_tokens": True,
        "minimum_effective_tokens": True,
        "schema_version": "1.0",
        "score": "mean_g_value",
        "threshold": True,
        "threshold_operator": ">",
    }

    with pytest.raises(ValueError, match="threshold evidence is invalid"):
        sealer._validate_threshold_evidence(evidence, args, adapter)


def test_template_advertises_only_operator_scoped_nonproduction_support():
    manifest = json.loads((PACK / "adapter-manifest.template.json").read_text(encoding="utf-8"))
    readme = (PACK / "README.md").read_text(encoding="utf-8")

    assert manifest["status"] == "operator_sealable_research_pack"
    assert manifest["calibrated"] is False
    assert manifest["independent"] is False
    assert manifest["production_detection"] is False
    assert manifest["vendor_equivalent"] is False
    assert manifest["golden_conformance"]["passed"] is True
    assert "sampling_table" not in json.dumps(manifest)
    assert "not a Gemini or Claude detector" in readme
    assert "local_files_only=True" in readme
    assert "trust_remote_code=False" in readme
    assert "calibrated=false" in readme
    assert set(manifest["available_commands"]) == {
        "conformance.py",
        "operator_adapter.py",
        "seal_operator.py",
        "upstream_conformance.py",
    }


def test_upstream_conformance_record_is_content_free_and_transitively_bound(adapter):
    conformance = _load(PACK / "conformance.py", "synthid_record_portable_conformance_test")
    portable_report = conformance.run(PACK)
    manifest = json.loads((PACK / "adapter-manifest.template.json").read_text(encoding="utf-8"))
    record = json.loads((PACK / "upstream-conformance-record.json").read_text(encoding="ascii"))
    declared = record.pop("report_sha256")

    assert record["portable_report_sha256"] == portable_report["report_sha256"]
    assert declared == adapter._sha256(adapter._canonical(record))
    assert manifest["golden_conformance"]["upstream_record_sha256"] == declared
    assert record["passed"] is True
    assert record["scope"] == "g_values_and_repetition_eos_masks"
    assert record["byteorder"] == "little"
    assert record["torch_version"] == "2.4.0"
    assert record["transformers_version"] == "4.43.3"
    serialized = json.dumps(record, sort_keys=True)
    assert "token_ids" not in serialized
    assert "keys" not in serialized
    source = (PACK / "upstream_conformance.py").read_text(encoding="utf-8")
    assert "_verify_sources" in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source


def test_runtime_source_has_no_network_client_or_model_identifier_path():
    source = (PACK / "operator_adapter.py").read_text(encoding="utf-8")
    assert "local_files_only=True" in source
    assert "trust_remote_code=False" in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" in source  # The prohibition is stated in the module contract.
