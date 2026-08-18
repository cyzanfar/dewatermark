"""Cross-platform, privacy-safe resource telemetry for benchmark runs."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ResourceSnapshot:
    wall_seconds: float
    process_cpu_seconds: float
    peak_rss_bytes: int | None


def _peak_rss_bytes() -> int | None:
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return None
    # macOS reports bytes; Linux and the BSDs exposed by CI report KiB.
    if sys.platform == "darwin":
        return value
    return value * 1024


def resource_snapshot() -> ResourceSnapshot:
    return ResourceSnapshot(
        wall_seconds=time.perf_counter(),
        process_cpu_seconds=time.process_time(),
        peak_rss_bytes=_peak_rss_bytes(),
    )


def telemetry_value(
    value: int | float | None,
    unit: str,
    *,
    state: str | None = None,
) -> dict[str, Any]:
    selected = state or ("measured" if value is not None else "not_available")
    if selected not in {"measured", "declared", "not_available", "not_applicable"}:
        raise ValueError("invalid telemetry state")
    if value is not None and (isinstance(value, bool) or value < 0):
        raise ValueError("telemetry values must be non-negative numbers")
    return {"state": selected, "value": value, "unit": unit}


def model_size_bytes(model: Any) -> int | None:
    """Best-effort in-memory parameter plus buffer size without serialization."""
    try:
        values = list(model.parameters()) + list(model.buffers())
        return sum(int(value.numel()) * int(value.element_size()) for value in values)
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None


def resource_telemetry(
    started: ResourceSnapshot,
    *,
    finished: ResourceSnapshot | None = None,
    model_bytes: int | None = None,
    remote_queries: int | None = None,
    generated_tokens: int | None = None,
    estimated_cost_usd: float | None = None,
    operations: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Build schema-compatible telemetry; unknown facts stay explicitly unknown."""
    ended = finished or resource_snapshot()
    peak = ended.peak_rss_bytes
    values: dict[str, Any] = {
        "wall_time": telemetry_value(
            max(0.0, ended.wall_seconds - started.wall_seconds), "seconds"
        ),
        "process_cpu_time": telemetry_value(
            max(0.0, ended.process_cpu_seconds - started.process_cpu_seconds), "seconds"
        ),
        "peak_rss": telemetry_value(peak, "bytes"),
        "model_size": telemetry_value(model_bytes, "bytes"),
        "remote_queries": telemetry_value(remote_queries, "queries"),
        "generated_tokens": telemetry_value(generated_tokens, "tokens"),
        "estimated_cost": telemetry_value(estimated_cost_usd, "USD"),
    }
    for name, count in sorted((operations or {}).items()):
        if not name or not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("operation counters require a name and non-negative integer")
        values[f"operation.{name}"] = telemetry_value(count, "calls", state="measured")
    return values


def zero_network_telemetry(*, operations: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Deterministic declaration for an offline conformance artifact."""
    values = {
        "wall_time": telemetry_value(None, "seconds", state="not_applicable"),
        "process_cpu_time": telemetry_value(None, "seconds", state="not_applicable"),
        "peak_rss": telemetry_value(None, "bytes", state="not_applicable"),
        "model_size": telemetry_value(None, "bytes", state="not_applicable"),
        "remote_queries": telemetry_value(0, "queries", state="declared"),
        "generated_tokens": telemetry_value(0, "tokens", state="declared"),
        "estimated_cost": telemetry_value(0.0, "USD", state="declared"),
    }
    for name, count in sorted((operations or {}).items()):
        values[f"operation.{name}"] = telemetry_value(count, "calls", state="declared")
    return values


def scrubbed_subprocess_environment() -> dict[str, str]:
    """Minimal replay environment that excludes ambient credentials."""
    allowed = {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.setdefault("PATH", os.defpath)
    environment.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
    )
    return environment
