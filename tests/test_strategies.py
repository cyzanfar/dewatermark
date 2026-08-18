from __future__ import annotations

from dataclasses import replace

import pytest

from dewatermark.config import DewatermarkConfig
from dewatermark.models import CapabilityManifest
from dewatermark.providers import register_provider, unregister_provider
from dewatermark.strategies import registered_strategy

OFFLINE = DewatermarkConfig(local_lm_enabled=False)


def test_registered_strategy_is_lazy_and_strips_generic_credentials():
    constructed: list[bool] = []

    class Provider:
        capability = CapabilityManifest(identifier="search-provider", kind="transformer")

        def __init__(self, config):
            constructed.append(True)
            assert config.fireworks_api_key is None
            assert config.llm_api_key is None

        def available(self):
            return True

        def rewrite(self, text, **_options):
            return text.replace("large", "broad"), {"private": "discarded"}

    register_provider("search-provider", Provider)
    try:
        strategy = registered_strategy(
            "search-provider",
            replace(OFFLINE, fireworks_api_key="private", llm_api_key="private"),
        )
        assert not constructed
        assert strategy.available() is True
        assert constructed == [True]
        assert strategy.generate("a large test", context=object()) == ("a broad test",)
        assert "search-provider" not in repr(strategy)
    finally:
        unregister_provider("search-provider")


def test_registered_strategy_accepts_native_candidate_generation():
    class Provider:
        capability = CapabilityManifest(identifier="multi-provider", kind="transformer")

        def __init__(self, _config):
            pass

        def available(self):
            return True

        def generate(self, text, *, context, **_options):
            assert context == "feedback"
            return [text.upper(), text.lower()]

    register_provider("multi-provider", Provider)
    try:
        strategy = registered_strategy("multi-provider", OFFLINE)
        assert strategy.generate("Mixed", context="feedback") == ["MIXED", "mixed"]
    finally:
        unregister_provider("multi-provider")


def test_registered_strategy_rejects_instance_manifest_mismatch():
    class Provider:
        capability = CapabilityManifest(identifier="declared-provider", kind="transformer")

        def __init__(self, _config):
            self.capability = CapabilityManifest(
                identifier="different-provider", kind="transformer"
            )

    register_provider("mismatched-search-provider", Provider)
    try:
        strategy = registered_strategy("mismatched-search-provider", OFFLINE)
        with pytest.raises(TypeError, match="capability"):
            strategy.available()
    finally:
        unregister_provider("mismatched-search-provider")
