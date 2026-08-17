"""Deterministic use with no network or model downloads."""

from dewatermark import DewatermarkConfig, remove, sanitize

config = DewatermarkConfig(local_lm_enabled=False)
print(sanitize("he\u200bllo"))
print(remove("he\u200bllo", mode="sanitize", config=config).to_dict())
