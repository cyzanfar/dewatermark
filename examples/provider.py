"""Minimal third-party rewriter provider."""

from dewatermark import CapabilityManifest, DewatermarkConfig, register_provider, remove


class ExampleRewriter:
    capability = CapabilityManifest(
        identifier="example-rewriter",
        kind="transformer",
        version="1.0.0",
        schemes=("example",),
    )

    def __init__(self, _config):
        pass

    def available(self):
        return True

    def rewrite(self, text, **_options):
        return text.replace("utilize", "use"), {"strategy": "example"}


register_provider("example", ExampleRewriter)
config = DewatermarkConfig(local_lm_enabled=False, rewriter_provider="example")
print(remove("Agents utilize tools.", config=config).to_dict())
