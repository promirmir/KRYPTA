"""Read-only, best-effort inspection of OS-managed transparent volume encryption.

This module never enables encryption or alters devices. It does NOT prove physical
TPM pin rate limits, or confidentiality while the volume is already unlocked.
Missing/ambiguous evidence always maps to UNKNOWN, not PROTECTED.
"""
from __future__ import annotations

import json
import platform
import subprocess
from typing import Any, Callable

Run = Callable[..., Any]

_WINDOWS = r"""
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
  Write-Output '{"available":false,"volumes":[]}'
  exit 0
}
$items = @(
  Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
    [ordered]@{
      mount_point = [string]$_.MountPoint
      kind = [string]$_.VolumeType
      encryption = [string]$_.EncryptionMethod
      volume_status = [string]$_.VolumeStatus
      protection = [string]$_.ProtectionStatus
      lock_status = [string]$_.LockStatus
      percentage = $_.EncryptionPercentage
    }
  }
)
Write-Output (ConvertTo-Json -InputObject @{
  available = $true
  volumes = @($items)
} -Compress -Depth 5)
"""

def _result(os_name: str, backend: str, status: str, volumes: list[dict],
            warnings: list[str] | None = None) -> dict:
    return {
        "schema": "KRYPTA-VOLUME-STATUS/1",
        "platform": os_name, "backend": backend, "status": status,
        "read_only": True, "transparent_encryption": True,
        "krypta_managed_encryption": False,
        "hardware_pin_rate_limit_verified": False,
        "volumes": volumes, "warnings": list(warnings or []),
    }


def parse_windows(payload: str) -> dict:
    """Map BitLocker states conservatively: suspended != protected."""
    data = json.loads(payload)
    if not isinstance(data, dict) or data.get("available") is not True:
        return _result("windows", "BitLocker", "unavailable", [],
                       ["BitLocker module unavailable or access denied."])
    entries = data.get("volumes")
    if not isinstance(entries, list):
        return _result("windows", "BitLocker", "unknown", [],
                       ["Malformed BitLocker inventory."])
    items = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        method = str(entry.get("encryption", "")).lower()
        state = str(entry.get("volume_status", "")).lower()
        protection = str(entry.get("protection", "")).lower()
        try:
            pct = float(entry.get("percentage", -1))
        except (ValueError, TypeError):
            pct = -1
        verdict = "unknown"
        if state == "fullydecrypted" and pct == 0:
            verdict = "not_encrypted"
        elif state in ("encryptioninprogress", "decryptioninprogress", "encryptionpaused", "decryptionpaused"):
            verdict = "transition"
        elif state == "fullyencrypted" and pct >= 100 and method not in ("", "none", "unknown"):
            if protection == "on":
                verdict = "protected_at_rest"
            elif protection == "off":
                verdict = "protection_suspended"
        items.append({
            "mount_point": str(entry.get("mount_point", ""))[:256],
            "kind": str(entry.get("kind", "unknown"))[:32],
            "method": str(entry.get("encryption", "unknown"))[:48],
            "status": verdict,
            "volume_status": str(entry.get("volume_status", "unknown"))[:48],
            "protection": str(entry.get("protection", "unknown"))[:32],
        })
    return _result("windows", "BitLocker", "inspected", items)


def parse_linux(payload: str) -> dict:
    """Recognize active LUKS descendants; other layouts remain unknown."""
    data = json.loads(payload)
    if not isinstance(data, dict) or not isinstance(data.get("blockdevices"), list):
        return _result("linux", "lsblk/dm-crypt", "unknown", [],
                       ["Missing Linux block device tree."])
    items = []
    def visit(node: Any, luks_parent: bool = False, crypt_parent: bool = False) -> None:
        if not isinstance(node, dict):
            return
        fstype = str(node.get("fstype") or "").lower()
        devtype = str(node.get("type") or "").lower()
        luks_here = fstype in ("crypto_luks", "crypto_luks2", "crypto_luks1")
        crypt_here = devtype == "crypt"
        inherited_luks = luks_parent or luks_here
        inherited_crypt = crypt_parent or crypt_here
        mounts = node.get("mountpoints")
        if isinstance(mounts, str):
            mounts = [mounts]
        if not isinstance(mounts, list):
            mounts = []
        mounts = [m[:256] for m in mounts if isinstance(m, str) and m]
        if mounts and devtype not in ("loop", "rom"):
            verdict = ("active_luks_mapping" if luks_parent and inherited_crypt
                       else "unknown_encryption")
            items.append({
                "device": str(node.get("name", ""))[:256],
                "mount_points": mounts, "type": devtype[:48],
                "filesystem": fstype[:48], "status": verdict,
            })
        children = node.get("children", [])
        if isinstance(children, list):
            for child in children:
                visit(child, inherited_luks, inherited_crypt)
    for root in data["blockdevices"]:
        visit(root)
    return _result("linux", "lsblk/dm-crypt", "inspected", items,
                   ["Unrecognized layouts are UNKNOWN, not evidence of no encryption."])


def inspect_volumes(os_name: str | None = None, runner: Run = subprocess.run) -> dict:
    system = (os_name or platform.system()).lower()
    if system.startswith("win"):
        cmd = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
               "-Command", _WINDOWS]
        parser = parse_windows
        normalized = "windows"
        backend = "BitLocker"
    elif system == "linux":
        cmd = ["lsblk", "--json", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINTS"]
        parser = parse_linux
        normalized = "linux"
        backend = "lsblk/dm-crypt"
    else:
        return _result(system[:32], "native", "unsupported", [],
                       ["No supported read-only volume inspection backend."])
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=20,
                      check=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            raise ValueError("Command failed or returned empty output")
        return parser(proc.stdout)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return _result(normalized, backend, "unknown", [],
                       ["Unable to establish the volume protection state; no disk changes performed."])
