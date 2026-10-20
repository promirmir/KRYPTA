"""KRYPTA hardware *diagnostics*, not an authorization or key-release mechanism.

Untrusted device inventory / JSON cannot establish PIN anti-hammering. This module
always reports such protection as UNVERIFIED, even with a healthy TPM and Secure Boot.
No secrets are accepted; no keys, partitions or policy settings are modified.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class HardwareReadiness:
    provider_available: bool
    tpm_ready: bool
    secure_boot_confirmed: bool
    device_key_prototype_possible: bool
    pin_anti_hammering_verified: bool
    boot_integrity_binding_verified: bool
    evidence: str
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_available": self.provider_available,
            "tpm_ready": self.tpm_ready,
            "secure_boot_confirmed": self.secure_boot_confirmed,
            "device_key_prototype_possible": self.device_key_prototype_possible,
            "pin_anti_hammering_verified": self.pin_anti_hammering_verified,
            "boot_integrity_binding_verified": self.boot_integrity_binding_verified,
            "evidence": self.evidence,
            "notes": list(self.notes),
        }


def assess_windows_readiness(report: Mapping[str, Any]) -> HardwareReadiness:
    """Evaluate a *read-only*, untrusted Windows readiness report.

    Strict typing avoids treating strings like 'false' as evidence. Neither this
    function nor the report is an authorization source. Never feed this decision
    directly into decryption, key release or hardware PIN-rate-limit claims.
    """
    if not isinstance(report, Mapping) or report.get("schema") != "KRYPTA-TPM-READINESS/1":
        raise ValueError("Unsupported readiness report")
    tpm = report.get("tpm")
    crypto = report.get("platform_crypto_provider")
    boot = report.get("secure_boot")
    if not all(isinstance(x, Mapping) for x in (tpm, crypto, boot)):
        raise ValueError("Readiness report lacks required sections")

    # Missing/unknown status is never treated as a positive capability.
    available = crypto.get("can_open") is True
    ready = tpm.get("present") is True and tpm.get("ready") is True
    unlocked = tpm.get("locked_out") is False
    boot_ok = boot.get("enabled") is True
    can_prototype = available and ready and unlocked
    notes = ["Advisory inventory only; no TPM key created or used.",
             "A 4-digit PIN alone never resists offline dictionary attacks.",
             "Hardware PIN anti-hammering and PCR binding require independent device tests."]
    if not ready:
        notes.append("TPM is unavailable, not ready, or status cannot be determined.")
    if not available:
        notes.append("Microsoft Platform Crypto Provider was not confirmed available.")
    if tpm.get("locked_out") is True:
        notes.append("TPM is locked out: do not attempt more authorizations.")
    if not boot_ok:
        notes.append("Secure Boot could not be confirmed enabled.")
    return HardwareReadiness(
        provider_available=available,
        tpm_ready=ready,
        secure_boot_confirmed=boot_ok,
        device_key_prototype_possible=can_prototype,
        pin_anti_hammering_verified=False,
        boot_integrity_binding_verified=False,
        evidence="read_only_untrusted_inventory",
        notes=tuple(notes),
    )