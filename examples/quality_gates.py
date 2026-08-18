"""Offline task-contract gate with a content-free evidence receipt."""

from __future__ import annotations

import json

import dewatermark
from dewatermark.config import DewatermarkConfig
from dewatermark.models import CapabilityManifest
from dewatermark.providers import register_provider, unregister_provider
from dewatermark.quality import QualityGateBinding
from dewatermark.quality_gates import PairwiseAssessment, TaskContractGate


class Rewrite:
    capability = CapabilityManifest(identifier="example-rewrite", kind="transformer")

    def __init__(self, _config):
        pass

    def available(self) -> bool:
        return True

    def rewrite(self, _text: str, **_options):
        return '{"enabled": true, "retries": 3}', {"strategy": "example"}


class JSONContract:
    capability = CapabilityManifest(
        identifier="example-json-contract",
        kind="quality_gate",
        metadata={"resource_accounting": "none"},
    )

    def available(self) -> bool:
        return True

    def assess(self, source: str, candidate: str) -> PairwiseAssessment:
        before = json.loads(source)
        after = json.loads(candidate)
        checks = (
            set(before) == set(after),
            all(type(before[key]) is type(after[key]) for key in before),
            before == after,
        )
        return PairwiseAssessment(
            score=sum(checks) / len(checks),
            checked_items=len(checks),
        )


register_provider("example-quality-rewrite", Rewrite)
try:
    config = DewatermarkConfig(
        local_lm_enabled=False,
        rewriter_provider="example-quality-rewrite",
        quality_gates=(QualityGateBinding(TaskContractGate(JSONContract(), threshold=1.0)),),
    )
    result = dewatermark.remove(
        '{"enabled": true, "retries": 3}',
        mode="full",
        config=config,
    )
    print(json.dumps(result.receipt.to_dict(), indent=2, sort_keys=True))
finally:
    unregister_provider("example-quality-rewrite")
