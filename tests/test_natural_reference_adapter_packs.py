from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import math
import os
import platform
import shutil
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from dewatermark.command_detector import CommandDetectorFactory
from dewatermark.models import CapabilityManifest

ROOT = Path(__file__).resolve().parents[1]
PACKS = {
    "kgw": ROOT / "adapters" / "kgw",
    "unigram": ROOT / "adapters" / "unigram",
}


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(configuration: dict[str, Any], text: str) -> dict[str, Any]:
    return {
        "action": "detect",
        "configuration_sha256": configuration["configuration_sha256"],
        "detector": configuration["identifier"],
        "policy": {"allow_model_download": False, "allow_network": False},
        "protocol_version": "1.1",
        "text": text,
    }


def _capability(value: dict[str, Any]) -> CapabilityManifest:
    return CapabilityManifest(
        identifier=value["identifier"],
        kind="detector",
        version=value["version"],
        schemes=tuple(value["schemes"]),
        description=value["description"],
        network_required=value["network_required"],
        model_download_possible=value["model_download_possible"],
        requires_secret=value["requires_secret"],
        minimum_characters=value["minimum_characters"],
        calibrated=value["calibrated"],
        independent=value["independent"],
        metadata=value["metadata"],
    )


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_adapter_population_count_supports_python_39(name):
    adapter = _load(PACKS[name] / "natural_adapter.py", f"population_count_{name}_adapter")

    assert adapter._population_count(0) == 0
    assert adapter._population_count(0b101010101) == 5
    assert adapter._population_count((1 << 256) - 1) == 256


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_profile_builder_transactionally_refreshes_behavior_preserving_bindings(
    name, tmp_path
):
    copied = tmp_path / name
    shutil.copytree(PACKS[name], copied)
    adapter_path = copied / "natural_adapter.py"
    adapter_path.write_text(
        adapter_path.read_text(encoding="utf-8") + "\n# Behavior-preserving maintenance edit.\n",
        encoding="utf-8",
    )
    builder = _load(copied / "build_natural_profile.py", f"refresh_{name}_builder")
    old_configuration = json.loads(
        (copied / "natural-adapter-config.json").read_text(encoding="utf-8")
    )

    builder.refresh_bindings(copied)

    material = json.loads((copied / "natural-profile-material.json").read_text(encoding="utf-8"))
    configuration = json.loads((copied / "natural-adapter-config.json").read_text(encoding="utf-8"))
    assert (
        material["files"]["natural_adapter.py"]
        == hashlib.sha256(adapter_path.read_bytes()).hexdigest()
    )
    assert configuration["configuration_sha256"] != old_configuration["configuration_sha256"]
    runner = _load(copied / "natural_conformance.py", f"refreshed_{name}_conformance")
    assert runner.run(copied)["passed"] is True

    binding_names = (
        "natural-profile-material.json",
        "natural-adapter-config.json",
        "natural-conformance-record.json",
        "natural-capability.json",
    )
    refreshed = {item: (copied / item).read_bytes() for item in binding_names}
    builder.refresh_bindings(copied)
    assert {item: (copied / item).read_bytes() for item in binding_names} == refreshed


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_profile_binding_refresh_rejects_semantic_drift_without_publication(name, tmp_path):
    copied = tmp_path / name
    shutil.copytree(PACKS[name], copied)
    adapter_path = copied / "natural_adapter.py"
    source = adapter_path.read_text(encoding="utf-8")
    assert source.count('return bin(value).count("1")') == 1
    adapter_path.write_text(
        source.replace('return bin(value).count("1")', "return 0", 1), encoding="utf-8"
    )
    builder = _load(copied / "build_natural_profile.py", f"semantic_drift_{name}_builder")
    binding_names = (
        "natural-profile-material.json",
        "natural-adapter-config.json",
        "natural-conformance-record.json",
        "natural-capability.json",
    )
    original = {item: (copied / item).read_bytes() for item in binding_names}

    with pytest.raises(ValueError, match="semantic fixture outputs changed"):
        builder.refresh_bindings(copied)

    assert {item: (copied / item).read_bytes() for item in binding_names} == original
    assert not list(copied.glob(".natural-profile-refresh-*"))


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_profile_binding_refresh_rolls_back_interrupted_publication(
    name, tmp_path, monkeypatch
):
    copied = tmp_path / name
    shutil.copytree(PACKS[name], copied)
    adapter_path = copied / "natural_adapter.py"
    adapter_path.write_text(
        adapter_path.read_text(encoding="utf-8") + "\n# Behavior-preserving maintenance edit.\n",
        encoding="utf-8",
    )
    builder = _load(copied / "build_natural_profile.py", f"interrupted_{name}_builder")
    binding_names = (
        "natural-profile-material.json",
        "natural-adapter-config.json",
        "natural-conformance-record.json",
        "natural-capability.json",
    )
    original = {item: (copied / item).read_bytes() for item in binding_names}
    replace = builder.os.replace
    calls = 0

    def fail_second(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture publication failure")
        replace(source, destination)

    monkeypatch.setattr(builder.os, "replace", fail_second)
    with pytest.raises(OSError, match="fixture publication failure"):
        builder.refresh_bindings(copied)

    assert {item: (copied / item).read_bytes() for item in binding_names} == original
    assert not list(copied.glob(".natural-profile-refresh-*"))


def _operator_configuration(adapter: Any, name: str) -> dict[str, Any]:
    files = {"tokenizer.json": "1" * 64}
    configuration = {
        "byteorder": sys.byteorder,
        "configuration_sha256": "",
        "identifier": f"operator-{name}",
        "key_id": "1234567890abcdef1234567890abcdef",
        "minimum_effective_tokens": 32,
        "p_value_method": "one_sided_standard_normal_survival",
        "platform_machine": platform.machine(),
        "platform_system": platform.system(),
        "python_version": platform.python_version(),
        "schema_version": "1.0",
        "scheme": f"{name}-fixture",
        "score_direction": "higher",
        "threshold_operator": ">",
        "threshold_evidence_sha256": "2" * 64,
        "tokenizer_files": files,
        "tokenizer_revision": "fixture-revision",
        "tokenizer_snapshot_sha256": adapter._sha256(adapter._canonical(files)),
        "tokenizer_type": "transformers_local_files_v1",
        "tokenizers_version": "1.0.0",
        "torch_version": "1.0.0",
        "transformers_version": "1.0.0",
        "upstream_file_sha256": adapter.UPSTREAM_FILE_SHA256,
        "upstream_revision": adapter.UPSTREAM_REVISION,
        "vocab_size": 256,
    }
    if name == "kgw":
        configuration.update(
            {
                "bos_handling": "strip_if_present",
                "delta": 2.0,
                "gamma": 0.25,
                "ignore_repeated_bigrams": True,
                "nltk_version": "1.0.0",
                "normalizers": [],
                "scipy_version": "1.0.0",
                "seeding_scheme": "simple_1",
                "select_green_tokens": True,
                "threshold": 4.0,
                "upstream_repository": "https://github.com/jwkirchenbauer/lm-watermarking",
            }
        )
    else:
        configuration.update(
            {
                "alpha": 0.01,
                "dynamic_threshold_method": "finite_population_unique_tokens",
                "fraction": 0.5,
                "numpy_version": "1.0.0",
                "reported_z_score": "finite_population_adjusted",
                "scipy_version": "1.0.0",
                "strength": 2.0,
                "threshold": 2.3263478740408408,
                "upstream_repository": "https://github.com/XuandongZhao/Unigram-Watermark",
            }
        )
    public = {key: value for key, value in configuration.items() if key != "configuration_sha256"}
    configuration["configuration_sha256"] = adapter._sha256(adapter._canonical(public))
    return configuration


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_profiles_are_content_addressed_and_explicitly_unvalidated(name):
    directory = PACKS[name]
    configuration = json.loads(
        (directory / "natural-adapter-config.json").read_text(encoding="utf-8")
    )
    declared = configuration.pop("configuration_sha256")
    canonical = json.dumps(
        configuration, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert hashlib.sha256(canonical).hexdigest() == declared
    assert set(configuration) >= {
        "key_id",
        "profile_manifest_sha256",
        "threshold_evidence_sha256",
        "tokenizer_sha256",
        "upstream_file_sha256",
        "upstream_revision",
    }
    assert "key" not in configuration
    assert len(configuration["key_id"]) == 32
    assert "key_fingerprint" not in configuration
    assert configuration["threshold_operator"] == ">"

    capability = json.loads((directory / "natural-capability.json").read_text(encoding="utf-8"))
    assert capability["calibrated"] is False
    assert capability["independent"] is True
    assert capability["network_required"] is False
    assert capability["model_download_possible"] is False
    assert capability["requires_secret"] is False
    assert capability["metadata"]["production_detection"] is False
    assert capability["metadata"]["vendor_equivalent"] is False
    assert capability["metadata"]["upstream_equivalent_for_reference_configuration"] is True
    assert capability["metadata"]["calibration"] == ("analytical_only_not_empirically_calibrated")

    material_path = directory / "natural-profile-material.json"
    assert (
        hashlib.sha256(material_path.read_bytes()).hexdigest()
        == configuration["profile_manifest_sha256"]
    )
    material = json.loads(material_path.read_text(encoding="utf-8"))
    assert material["attestation"]["standalone_signature"] is False
    for relative, digest in material["files"].items():
        if relative.startswith("upstream/"):
            assert digest == configuration["upstream_file_sha256"]
        else:
            assert hashlib.sha256((directory / relative).read_bytes()).hexdigest() == digest

    evidence = directory / "natural-threshold-evidence.json"
    assert (
        hashlib.sha256(evidence.read_bytes()).hexdigest()
        == configuration["threshold_evidence_sha256"]
    )
    threshold_evidence = json.loads(evidence.read_text(encoding="utf-8"))
    assert threshold_evidence["empirical_calibration"] is False
    assert threshold_evidence["threshold_operator"] == ">"


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_profiles_match_fluent_golden_vectors_and_fail_closed(name):
    directory = PACKS[name]
    adapter = _load(directory / "natural_adapter.py", f"natural_{name}_adapter")
    configuration = adapter._load_configuration(directory / "natural-adapter-config.json")
    vectors = json.loads((directory / "natural-fixture-cases.json").read_text(encoding="utf-8"))[
        "vectors"
    ]
    assert {item["name"] for item in vectors} == {
        "natural-reference-positive",
        "natural-length-control",
        "readable-positive-variant",
        "natural-short-abstention",
    }
    variant = next(item for item in vectors if item["name"] == "readable-positive-variant")
    assert variant["expected_status"] == "detected"
    assert "." in variant["text"]
    assert len(variant["text"].split()) >= 40

    for vector in vectors:
        kwargs = {
            "configuration": configuration,
            "tokenizer_path": directory / "natural-tokenizer.json",
        }
        if name == "kgw":
            kwargs["transitions_path"] = directory / "green-transitions-v1.json"
        else:
            kwargs["mask_path"] = directory / "green-mask-v1.json"
        response = adapter.handle(_request(configuration, vector["text"]), **kwargs)
        assert response["status"] == vector["expected_status"]
        assert response["effective_tokens"] == vector["expected_effective_tokens"]
        for field in ("score", "p_value", "z_score"):
            expected = vector.get(f"expected_{field}")
            actual = response.get(field)
            if expected is None:
                assert actual is None
            else:
                assert math.isclose(float(actual), float(expected), rel_tol=0, abs_tol=1e-12)

    kwargs = {
        "configuration": configuration,
        "tokenizer_path": directory / "natural-tokenizer.json",
    }
    if name == "kgw":
        kwargs["transitions_path"] = directory / "green-transitions-v1.json"
    else:
        kwargs["mask_path"] = directory / "green-mask-v1.json"
    unsupported = adapter.handle(
        _request(configuration, "This lexemeisdeliberatelyunknown to the closed vocabulary."),
        **kwargs,
    )
    assert unsupported["status"] == "unsupported"
    assert unsupported["reason_code"] == "tokenizer_unknown_token"
    invalid_policy = _request(configuration, vectors[0]["text"])
    invalid_policy["policy"] = {"allow_model_download": 0, "allow_network": False}
    assert adapter.handle(invalid_policy, **kwargs)["status"] == "detector_error"


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_natural_command_detector_exposes_only_validated_numeric_evidence(name):
    directory = PACKS[name]
    capability_value = json.loads(
        (directory / "natural-capability.json").read_text(encoding="utf-8")
    )
    factory = CommandDetectorFactory(
        (sys.executable, str(directory / "natural_adapter.py")),
        _capability(capability_value),
    )
    positive = json.loads((directory / "natural-fixture-cases.json").read_text(encoding="utf-8"))[
        "vectors"
    ][0]
    evidence = factory().detect(positive["text"])
    assert evidence.status == "detected"
    assert (
        evidence.details["configuration_sha256"]
        == capability_value["metadata"]["configuration_sha256"]
    )
    assert evidence.details["effective_tokens"] >= 32
    assert 0 <= evidence.details["p_value"] <= 1
    assert math.isfinite(evidence.details["z_score"])
    assert evidence.details["score_direction"] == "higher"
    assert evidence.details["threshold_operator"] == ">"


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_checked_conformance_reports_are_content_free_and_replay(name):
    directory = PACKS[name]
    runner = _load(directory / "natural_conformance.py", f"natural_{name}_conformance")
    report = runner.run(directory)
    assert report["passed"] is True
    assert all(case["passed"] for case in report["cases"])
    serialized = json.dumps(report, sort_keys=True)
    vectors = json.loads((directory / "natural-fixture-cases.json").read_text(encoding="utf-8"))[
        "vectors"
    ]
    assert all(vector["text"] not in serialized for vector in vectors)
    checked = json.loads(
        (directory / "natural-conformance-record.json").read_text(encoding="utf-8")
    )
    assert checked["passed"] is True
    assert (
        checked["vectors_sha256"]
        == hashlib.sha256((directory / "natural-fixture-cases.json").read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_key_loader_requires_structured_identity_and_permissions(name, tmp_path):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_adapter")
    path = tmp_path / "operator.key"
    key_id = "1234567890abcdef1234567890abcdef"
    path.write_text(
        json.dumps({"key": 123456789, "key_id": key_id, "schema_version": "1.0"}),
        encoding="ascii",
    )
    path.chmod(0o600)
    arguments = (path, key_id, 256) if name == "kgw" else (path, key_id)
    if os.name != "posix":
        with pytest.raises(ValueError, match="key_permissions_unverifiable"):
            adapter._load_key(*arguments)
        return
    assert adapter._load_key(*arguments) == 123456789
    assert key_id != hashlib.sha256(path.read_bytes()).hexdigest()[:32]
    with pytest.raises(ValueError):
        adapter._load_key(path, "0" * 32, *(() if name == "unigram" else (256,)))
    if os.name == "posix":
        link = tmp_path / "operator-link.key"
        link.symlink_to(path)
        with pytest.raises(ValueError):
            link_args = (link, key_id, 256) if name == "kgw" else (link, key_id)
            adapter._load_key(*link_args)
        path.chmod(0o640)
        with pytest.raises(ValueError):
            adapter._load_key(*arguments)
        assert stat.S_IMODE(path.stat().st_mode) == 0o640


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_key_loader_fails_closed_without_posix_permission_metadata(
    name, tmp_path, monkeypatch
):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"nonposix_{name}_adapter")
    path = tmp_path / "operator.key"
    key_id = "1234567890abcdef1234567890abcdef"
    path.write_text(
        json.dumps({"key": 123456789, "key_id": key_id, "schema_version": "1.0"}),
        encoding="ascii",
    )
    arguments = (path, key_id, 256) if name == "kgw" else (path, key_id)
    with monkeypatch.context() as isolated:
        isolated.setattr(adapter.os, "name", "nt")
        with pytest.raises(ValueError, match="key_permissions_unverifiable"):
            adapter._load_key(*arguments)


def test_unigram_operator_rejects_keys_above_upstream_32_bit_seed_ceiling(tmp_path):
    adapter = _load(PACKS["unigram"] / "operator_adapter.py", "operator_unigram_key_ceiling")
    path = tmp_path / "operator.key"
    path.write_text(
        json.dumps(
            {
                "key": 1 << 32,
                "key_id": "1234567890abcdef1234567890abcdef",
                "schema_version": "1.0",
            }
        ),
        encoding="ascii",
    )
    path.chmod(0o600)
    reason = "key_unavailable" if os.name == "posix" else "key_permissions_unverifiable"
    with pytest.raises(ValueError, match=reason):
        adapter._load_key(path, "1234567890abcdef1234567890abcdef")


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_key_record_rejects_duplicate_json_fields(name, tmp_path):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_duplicate_key")
    path = tmp_path / "operator.key"
    path.write_text(
        '{"schema_version":"1.0","key_id":"1234567890abcdef1234567890abcdef","key":7,"key":8}',
        encoding="ascii",
    )
    path.chmod(0o600)
    reason = "key_unavailable" if os.name == "posix" else "key_permissions_unverifiable"
    with pytest.raises(ValueError, match=reason):
        adapter._read_key_record(path)


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_snapshot_caps_total_bytes_and_rejects_sensitive_paths(
    name, tmp_path, monkeypatch
):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_snapshot")
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    (tokenizer / "tokenizer.json").write_bytes(b"1234")
    monkeypatch.setattr(adapter, "MAX_TOKENIZER_TOTAL_BYTES", 3)
    with pytest.raises(ValueError, match="tokenizer_unavailable"):
        adapter._tokenizer_snapshot(tokenizer)
    monkeypatch.setattr(adapter, "MAX_TOKENIZER_TOTAL_BYTES", 1024)
    sensitive = tokenizer / ".env"
    sensitive.mkdir()
    (sensitive / "tokenizer.json").write_bytes(b"public-looking")
    with pytest.raises(ValueError, match="tokenizer_contains_sensitive_file"):
        adapter._tokenizer_snapshot(tokenizer)


@pytest.mark.parametrize("name", ["kgw", "unigram"])
@pytest.mark.parametrize(
    ("filename", "payload", "private_value"),
    [
        (
            "tokenizer.json",
            b'{"api_key":"low-entropy-private-credential"}',
            "low-entropy-private-credential",
        ),
        (
            "tokenizer.model",
            b'{"api_key":"low-entropy-private-credential"}',
            "low-entropy-private-credential",
        ),
        (
            "tokenizer.json",
            b'{"revision":"sk-live-PRIVATECREDENTIAL123456789"}',
            "sk-live-PRIVATECREDENTIAL123456789",
        ),
        (
            "tokenizer.json",
            b'{"source":"https://user:password@example.test/tokenizer"}',
            "https://user:password@example.test/tokenizer",
        ),
        (
            "tokenizer.json",
            b'{"source":"/workspace/customer/tokenizer.json"}',
            "/workspace/customer/tokenizer.json",
        ),
        (
            "tokenizer.json",
            b'{"source":"C:\\\\Users\\\\alice\\\\tokenizer.json"}',
            r"C:\Users\alice\tokenizer.json",
        ),
        (
            "merges.txt",
            b'authorization="Bearer PRIVATECREDENTIAL123456789"',
            "PRIVATECREDENTIAL123456789",
        ),
    ],
)
def test_operator_snapshot_rejects_private_content_before_hashing(
    name, filename, payload, private_value, tmp_path, monkeypatch
):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_private_snapshot")
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    (tokenizer / filename).write_bytes(payload)
    hashed: list[bytes] = []
    original_sha256 = adapter._sha256

    def record_hash(raw):
        hashed.append(raw)
        return original_sha256(raw)

    monkeypatch.setattr(adapter, "_sha256", record_hash)
    with pytest.raises(ValueError, match="^tokenizer_contains_unsafe_content$") as captured:
        adapter._tokenizer_snapshot(tokenizer)
    assert private_value not in str(captured.value)
    assert hashed == []


@pytest.mark.parametrize("name", ["kgw", "unigram"])
@pytest.mark.parametrize(
    "payload",
    [
        b'{"model":',
        b'{"model":1,"model":2}',
        b'{"model":NaN}',
        rb'{"model":"unsafe\u0000content"}',
        b'\xff{"model":1}',
    ],
)
def test_operator_snapshot_rejects_malformed_json_before_hashing(
    name, payload, tmp_path, monkeypatch
):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_unsafe_json")
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    (tokenizer / "tokenizer.json").write_bytes(payload)
    hashed: list[bytes] = []
    monkeypatch.setattr(adapter, "_sha256", lambda raw: hashed.append(raw) or "0" * 64)
    with pytest.raises(ValueError, match="^tokenizer_contains_unsafe_content$"):
        adapter._tokenizer_snapshot(tokenizer)
    assert hashed == []


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_snapshot_accepts_tokenizer_vocabulary_and_binary_model(name, tmp_path):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_safe_snapshot")
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    json_payload = json.dumps(
        {
            "added_tokens": [{"content": "private token", "id": 4}],
            "chat_template": "These are basic instructions for a tokenizer.",
            "model": {"vocab": {"/": 3, "private": 0, "secret": 1, "token": 2}},
            "token": "ordinary-special-token",
            "unk_token": "<unk>",
        },
        sort_keys=True,
    ).encode("utf-8")
    binary_payload = b"\x00\xff\xfe\x10sentencepiece-model\x80"
    (tokenizer / "tokenizer.json").write_bytes(json_payload)
    (tokenizer / "tokenizer.model").write_bytes(binary_payload)
    snapshot = adapter._tokenizer_snapshot(tokenizer)
    assert snapshot == {
        "tokenizer.json": hashlib.sha256(json_payload).hexdigest(),
        "tokenizer.model": hashlib.sha256(binary_payload).hexdigest(),
    }


def test_operator_snapshot_privacy_policy_stays_aligned_between_packs():
    kgw = _load(PACKS["kgw"] / "operator_adapter.py", "operator_kgw_privacy_alignment")
    unigram = _load(PACKS["unigram"] / "operator_adapter.py", "operator_unigram_privacy_alignment")
    assert kgw._CREDENTIAL_JSON_KEYS == unigram._CREDENTIAL_JSON_KEYS
    assert kgw._CREDENTIAL_JSON_KEY_SUFFIXES == unigram._CREDENTIAL_JSON_KEY_SUFFIXES
    assert kgw._CREDENTIAL_JSON_FRAGMENT.pattern == unigram._CREDENTIAL_JSON_FRAGMENT.pattern
    assert kgw._PRIVATE_ABSOLUTE_PATH.pattern == unigram._PRIVATE_ABSOLUTE_PATH.pattern
    assert [pattern.pattern for pattern in kgw._SECRET_VALUE_PATTERNS] == [
        pattern.pattern for pattern in unigram._SECRET_VALUE_PATTERNS
    ]
    for function_name in (
        "_credential_json_key",
        "_normal_json_key",
        "_reject_json_constant",
        "_tokenizer_snapshot",
        "_unsafe_tokenizer_fragment",
        "_unsafe_tokenizer_string",
        "_validate_tokenizer_content",
        "_validate_tokenizer_json",
    ):
        assert inspect.getsource(getattr(kgw, function_name)) == inspect.getsource(
            getattr(unigram, function_name)
        )


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_configuration_validation_is_complete_and_rejects_private_identifiers(name):
    adapter = _load(PACKS[name] / "operator_adapter.py", f"operator_{name}_configuration")
    configuration = _operator_configuration(adapter, name)
    assert adapter._validate_configuration(configuration) == configuration
    assert not adapter._valid_public_identifier("private-token")
    assert not adapter._valid_public_identifier("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")

    invalid = dict(configuration)
    invalid["tokenizer_revision"] = "https://private-token@example.test/revision"
    public = {key: value for key, value in invalid.items() if key != "configuration_sha256"}
    invalid["configuration_sha256"] = adapter._sha256(adapter._canonical(public))
    with pytest.raises(ValueError, match="configuration_unsupported"):
        adapter._validate_configuration(invalid)


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_sealer_validates_before_atomic_publication(name):
    source = (PACKS[name] / "seal_operator.py").read_text(encoding="utf-8")
    assert source.index("runtime._validate_configuration(configuration)") < source.index(
        "_publish_pair(output, configuration, capability"
    )
    assert '"requires_secret": True' in source
    assert '"secret_binding": "operator_managed_file"' in source


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_sealer_rejects_arbitrary_threshold_evidence(name):
    sealer = _load(PACKS[name] / "seal_operator.py", f"seal_{name}_evidence")
    common = {
        "empirical_calibration": False,
        "evidence_id": "abcdef0123456789abcdef0123456789",
        "minimum_effective_tokens": 32,
        "schema_version": "1.0",
        "threshold_operator": ">",
    }
    if name == "kgw":
        args = SimpleNamespace(gamma=0.25, minimum_effective_tokens=32, threshold=4.0)
        evidence = {**common, "gamma": 0.25, "score": "z_score", "threshold": 4.0}
    else:
        args = SimpleNamespace(alpha=0.01, fraction=0.5, minimum_effective_tokens=32)
        evidence = {
            **common,
            "alpha": 0.01,
            "fraction": 0.5,
            "score": "finite_population_adjusted_z_score",
            "threshold": 2.3263478740408408,
        }
    assert sealer._validate_threshold_evidence(evidence, args) is None
    with pytest.raises(ValueError, match="threshold evidence is invalid"):
        sealer._validate_threshold_evidence({**evidence, "secret": "do-not-hash"}, args)


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_operator_sealer_publishes_configuration_and_capability_as_one_directory(
    name, tmp_path, monkeypatch
):
    sealer = _load(PACKS[name] / "seal_operator.py", f"seal_{name}_transaction")
    output = tmp_path / "published"
    original = sealer._write_new
    calls = 0

    def fail_second(path, value):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture failure")
        original(path, value)

    monkeypatch.setattr(sealer, "_write_new", fail_second)
    with pytest.raises(OSError, match="fixture failure"):
        sealer._publish_pair(output, {"configuration": True}, {"capability": True}, 1024)
    assert not output.exists()
    assert not list(tmp_path.glob(".dewatermark-operator-*"))


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_checked_conformance_rejects_resealed_loose_tolerances(name, tmp_path):
    source = PACKS[name]
    copied = tmp_path / name
    shutil.copytree(source, copied)
    record_path = copied / "natural-conformance-record.json"
    capability_path = copied / "natural-capability.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["numeric_absolute_tolerance"] = 1e-3
    record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="ascii")
    capability = json.loads(capability_path.read_text(encoding="utf-8"))
    capability["metadata"]["cross_implementation_conformance"]["record_sha256"] = hashlib.sha256(
        record_path.read_bytes()
    ).hexdigest()
    capability_path.write_text(
        json.dumps(capability, sort_keys=True, indent=2) + "\n", encoding="ascii"
    )
    runner = _load(copied / "natural_conformance.py", f"tampered_{name}_conformance")
    with pytest.raises(ValueError, match="checked conformance binding mismatch"):
        runner.run(copied)


@pytest.mark.parametrize("name", ["kgw", "unigram"])
def test_conformance_numeric_comparison_is_relative_and_log_scale(name):
    runner = _load(PACKS[name] / "natural_conformance.py", f"numeric_{name}_conformance")
    assert runner._numeric_matches("score", 1_000_000_000_000.5, 1_000_000_000_000.0)
    assert not runner._numeric_matches("score", 1_000_000_002_000.0, 1_000_000_000_000.0)
    assert runner._numeric_matches("p_value", 1.00000000005e-40, 1e-40)
    assert not runner._numeric_matches("p_value", 1e-13, 1e-40)
    assert not runner._numeric_matches("p_value", 0.0, 1e-40)


def test_operator_adapters_force_cached_tokenizers_and_disable_remote_code():
    for directory in PACKS.values():
        source = (directory / "operator_adapter.py").read_text(encoding="utf-8")
        assert "local_files_only=True" in source
        assert "trust_remote_code=False" in source
        assert "from_pretrained(" in source
        assert 'str(torch.__version__) != configuration["torch_version"]' in source
        assert '.split("+", 1)' not in source
        assert "requests" not in source
        assert "import socket" not in source
