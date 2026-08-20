"""Side-effect-free detector inventory, diagnostics, and reference conformance."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Optional, Sequence

from .capability_projection import public_detector_capability
from .models import CapabilityManifest
from .providers import detector_errors, detector_manifest, list_detectors
from .reference_detectors import (
    ReferenceConformanceReport,
    ReferenceScheme,
    run_reference_conformance,
)

InventoryStatus = Literal[
    "ready",
    "research_fixture_only",
    "unsupported",
    "entry_point_not_loaded",
]
CheckSeverity = Literal["pass", "warning", "error"]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNPINNED = {"", "0", "dev", "latest", "main", "master", "unknown", "unresolved"}


@dataclass(frozen=True, repr=False)
class DetectorInventoryEntry:
    identifier: str
    aliases: tuple[str, ...]
    status: InventoryStatus
    capability: Optional[CapabilityManifest] = None

    def __repr__(self) -> str:
        return "<detector inventory entry; representation redacted>"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "identifier": self.identifier,
            "aliases": list(self.aliases),
            "status": self.status,
        }
        if self.capability is not None:
            value["capability"] = public_detector_capability(self.capability)
        return value


@dataclass(frozen=True, repr=False)
class DetectorDoctorCheck:
    detector: str
    check: str
    severity: CheckSeverity
    reason_code: str

    def __repr__(self) -> str:
        return "<detector doctor check; representation redacted>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "check": self.check,
            "severity": self.severity,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, repr=False)
class DetectorDoctorReport:
    inventory: tuple[DetectorInventoryEntry, ...]
    checks: tuple[DetectorDoctorCheck, ...]
    registry_errors: dict[str, str]

    def __repr__(self) -> str:
        return "<detector doctor report; representation redacted>"

    @property
    def passed(self) -> bool:
        return not any(check.severity == "error" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "side_effect_free": True,
            "scope": "static manifests only; executables, models, sockets, and plugins were not run",
            "inventory": [entry.to_dict() for entry in self.inventory],
            "checks": [check.to_dict() for check in self.checks],
            "registry_errors": dict(sorted(self.registry_errors.items())),
        }


def _inventory_status(capability: CapabilityManifest) -> InventoryStatus:
    declared = capability.metadata.get("status")
    if isinstance(declared, str) and declared.startswith("unsupported"):
        return "unsupported"
    if declared == "research_fixture_only":
        return "research_fixture_only"
    return "ready"


def discover_detector_capabilities() -> tuple[DetectorInventoryEntry, ...]:
    """List static capabilities without importing entry-point plugin code."""
    grouped: dict[str, tuple[CapabilityManifest, list[str]]] = {}
    unloaded: list[str] = []
    for name in list_detectors():
        manifest = detector_manifest(name)
        if manifest is None:
            unloaded.append(name)
            continue
        existing = grouped.get(manifest.identifier)
        if existing is None:
            grouped[manifest.identifier] = (manifest, [name])
        else:
            existing[1].append(name)
    entries = [
        DetectorInventoryEntry(
            identifier=identifier,
            aliases=tuple(sorted(aliases)),
            status=_inventory_status(capability),
            capability=capability,
        )
        for identifier, (capability, aliases) in grouped.items()
    ]
    entries.extend(
        DetectorInventoryEntry(
            identifier=name,
            aliases=(name,),
            status="entry_point_not_loaded",
        )
        for name in unloaded
    )
    return tuple(sorted(entries, key=lambda entry: (entry.identifier, entry.aliases)))


def _check(
    checks: list[DetectorDoctorCheck],
    detector: str,
    name: str,
    condition: bool,
    *,
    failed_code: str,
    failed_severity: CheckSeverity = "error",
) -> None:
    checks.append(
        DetectorDoctorCheck(
            detector=detector,
            check=name,
            severity="pass" if condition else failed_severity,
            reason_code="ok" if condition else failed_code,
        )
    )


def doctor_detectors() -> DetectorDoctorReport:
    """Audit static claims and pins without constructing any detector."""
    inventory = discover_detector_capabilities()
    checks: list[DetectorDoctorCheck] = []
    for entry in inventory:
        capability = entry.capability
        if capability is None:
            checks.append(
                DetectorDoctorCheck(
                    detector=entry.identifier,
                    check="static_manifest",
                    severity="warning",
                    reason_code="entry_point_not_loaded",
                )
            )
            continue
        _check(
            checks,
            entry.identifier,
            "schemes_declared",
            bool(capability.schemes and all(item.strip() for item in capability.schemes)),
            failed_code="missing_scheme",
        )
        _check(
            checks,
            entry.identifier,
            "version_pinned",
            capability.version.strip().lower() not in _UNPINNED,
            failed_code="unresolved_version",
        )
        if entry.status == "unsupported":
            _check(
                checks,
                entry.identifier,
                "explicit_abstention",
                capability.calibrated is False and capability.independent is False,
                failed_code="unsupported_capability_overclaims",
            )
        if entry.status == "research_fixture_only":
            metadata = capability.metadata
            _check(
                checks,
                entry.identifier,
                "fixture_claim_boundary",
                metadata.get("vendor_equivalent") is False
                and metadata.get("production_detection") is False
                and capability.calibrated is False
                and capability.independent is False,
                failed_code="reference_fixture_overclaims",
            )
            fingerprint = metadata.get("configuration_sha256")
            _check(
                checks,
                entry.identifier,
                "configuration_pinned",
                isinstance(fingerprint, str) and bool(_SHA256.fullmatch(fingerprint)),
                failed_code="missing_configuration_fingerprint",
            )
        command_version = capability.metadata.get("command_protocol_version")
        if command_version is not None:
            metadata = capability.metadata
            _check(
                checks,
                entry.identifier,
                "command_contract_pinned",
                isinstance(command_version, str)
                and isinstance(metadata.get("configuration_sha256"), str)
                and bool(_SHA256.fullmatch(str(metadata.get("configuration_sha256"))))
                and metadata.get("score_direction") in ("higher", "lower")
                and isinstance(metadata.get("minimum_effective_tokens"), int),
                failed_code="incomplete_command_contract",
            )
        if capability.independent:
            metadata = capability.metadata
            has_revision = any(
                isinstance(metadata.get(field), str)
                and str(metadata.get(field)).strip().lower() not in _UNPINNED
                for field in ("implementation_revision", "source_revision", "commit")
            )
            _check(
                checks,
                entry.identifier,
                "independent_implementation_revision",
                has_revision,
                failed_code="independent_revision_not_declared",
                failed_severity="warning",
            )
    return DetectorDoctorReport(
        inventory=inventory,
        checks=tuple(checks),
        registry_errors=detector_errors(),
    )


def conform_reference_detectors(
    schemes: Optional[Sequence[ReferenceScheme]] = None,
) -> ReferenceConformanceReport:
    """Execute only the dependency-free built-in research fixtures."""
    return run_reference_conformance(schemes)


__all__ = [
    "CheckSeverity",
    "DetectorDoctorCheck",
    "DetectorDoctorReport",
    "DetectorInventoryEntry",
    "InventoryStatus",
    "conform_reference_detectors",
    "discover_detector_capabilities",
    "doctor_detectors",
]
