"""Safe public projection of detector capability manifests."""

from __future__ import annotations

from typing import Any

from .models import CapabilityManifest


def public_detector_capability(capability: CapabilityManifest) -> dict[str, Any]:
    """Project one capability without reinterpreting legacy extension fields.

    Command protocol 1.0/1.1 metadata was deliberately open.  Names introduced
    by 1.2 may therefore already exist as unrelated legacy extensions.  Only a
    complete 1.2 attribution contract is safe to expose as attribution metadata.
    """
    value = capability.to_dict()
    metadata = dict(value["metadata"])
    attribution_bound = (
        metadata.get("command_protocol_version") == "1.2"
        and metadata.get("attribution_kind") == "token_character_spans"
        and type(metadata.get("maximum_attributions")) is int
        and 1 <= metadata["maximum_attributions"] <= 4096
    )
    if not attribution_bound:
        metadata.pop("attribution_kind", None)
        metadata.pop("maximum_attributions", None)
    value["metadata"] = metadata
    return value
