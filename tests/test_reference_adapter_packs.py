from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from dewatermark.adapter_packs import (
    adapter_pack_manifest,
    list_adapter_packs,
    materialize_adapter_pack,
)
from dewatermark.command_detector import CommandDetectorFactory
from dewatermark.models import CapabilityManifest

ROOT = Path(__file__).resolve().parents[1]
KGW = ROOT / "adapters" / "kgw"


def _load_adapter():
    spec = importlib.util.spec_from_file_location("kgw_adapter_fixture", KGW / "adapter.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_kgw_adapter_configuration_and_capability_are_content_addressed():
    configuration = json.loads((KGW / "adapter-config.json").read_text(encoding="utf-8"))
    declared = configuration.pop("configuration_sha256")
    canonical = json.dumps(
        configuration, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    assert hashlib.sha256(canonical).hexdigest() == declared

    capability = json.loads((KGW / "capability.json").read_text(encoding="utf-8"))
    assert capability["metadata"]["configuration_sha256"] == declared
    assert capability["metadata"]["source_revision"] == ("82922516930c02f8aa322765defdb5863d07a00e")
    assert capability["independent"] is True
    assert capability["calibrated"] is False
    assert capability["metadata"]["production_detection"] is False
    assert capability["metadata"]["vendor_equivalent"] is False
    assert capability["metadata"]["golden_conformance"]["passed"] is True
    vector_sha256 = hashlib.sha256((KGW / "fixture-cases.json").read_bytes()).hexdigest()
    assert capability["metadata"]["golden_conformance"]["vectors_sha256"] == vector_sha256

    static = CapabilityManifest(
        identifier=capability["identifier"],
        kind="detector",
        version=capability["version"],
        schemes=tuple(capability["schemes"]),
        description=capability["description"],
        network_required=capability["network_required"],
        model_download_possible=capability["model_download_possible"],
        requires_secret=capability["requires_secret"],
        minimum_characters=capability["minimum_characters"],
        calibrated=capability["calibrated"],
        independent=capability["independent"],
        metadata=capability["metadata"],
    )
    factory = CommandDetectorFactory(
        (
            sys.executable,
            str(KGW / "adapter.py"),
            "--upstream-dir",
            str(ROOT / "operator-pinned-upstream"),
        ),
        static,
    )
    assert factory.capability.independent is True
    assert factory.capability.calibrated is False


def test_kgw_adapter_invokes_injected_upstream_detector_without_copied_algorithm(monkeypatch):
    adapter = _load_adapter()
    configuration = adapter._load_configuration(KGW / "adapter-config.json")

    class FakeDetector:
        def __init__(self, **kwargs):
            assert kwargs["normalizers"] == []
            assert kwargs["ignore_repeated_bigrams"] is True

        def detect(self, *, tokenized_text, return_prediction):
            assert return_prediction is False
            return {
                "z_score": 5.5,
                "p_value": 0.0001,
                "num_tokens_scored": len(tokenized_text) - 1,
            }

    fake = SimpleNamespace(
        WatermarkDetector=FakeDetector,
        torch=SimpleNamespace(
            __version__="2.4.1",
            device=lambda value: value,
            long="long",
            tensor=lambda values, dtype: values,
        ),
    )
    monkeypatch.setattr(adapter, "_load_upstream", lambda *_args: fake)
    text = " ".join(f"t{index}" for index in range(40))
    response = adapter.handle(
        {
            "protocol_version": "1.0",
            "action": "detect",
            "detector": configuration["identifier"],
            "configuration_sha256": configuration["configuration_sha256"],
            "policy": {"allow_network": False, "allow_model_download": False},
            "text": text,
        },
        configuration=configuration,
        upstream_dir=Path("unused"),
    )
    assert response["status"] == "detected"
    assert response["score"] == 5.5
    assert response["effective_tokens"] == 39


def test_kgw_adapter_abstains_on_natural_text_without_loading_upstream(monkeypatch):
    adapter = _load_adapter()
    configuration = adapter._load_configuration(KGW / "adapter-config.json")
    monkeypatch.setattr(
        adapter,
        "_load_upstream",
        lambda *_args: pytest.fail("unsupported text must not import upstream code"),
    )
    response = adapter.handle(
        {
            "protocol_version": "1.0",
            "action": "detect",
            "detector": configuration["identifier"],
            "configuration_sha256": configuration["configuration_sha256"],
            "policy": {"allow_network": False, "allow_model_download": False},
            "text": "ordinary natural language",
        },
        configuration=configuration,
        upstream_dir=Path("unused"),
    )
    assert response["status"] == "unsupported"
    assert response["reason_code"] == "token_fixture_only"


def test_synthid_pack_is_explicitly_an_incomplete_nonproduction_template():
    manifest = json.loads(
        (ROOT / "adapters" / "synthid" / "adapter-manifest.template.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["repository_revision"] == "addb4a158143c7c6851a1308f78b89fceed59683"
    assert manifest["status"] == "template_pending_conformance"
    assert manifest["golden_conformance"]["passed"] is False
    assert manifest["independent"] is False
    assert manifest["production_keys_available"] is False
    assert manifest["production_detection"] is False
    assert manifest["vendor_equivalent"] is False


def test_pack_api_lists_reads_and_materializes_without_overwrite(tmp_path):
    listed = {item["name"]: item for item in list_adapter_packs()}
    assert listed["kgw"]["production_detection"] is False
    assert listed["synthid"]["calibrated"] is False
    assert adapter_pack_manifest("kgw")["metadata"]["source_revision"]

    destination = tmp_path / "kgw-pack"
    created = materialize_adapter_pack("kgw", destination)
    assert {path.name for path in created} >= {"adapter.py", "capability.json"}
    with pytest.raises(FileExistsError):
        materialize_adapter_pack("kgw", destination)
