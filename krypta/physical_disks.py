"""Metadata-only physical-drive discovery: never opens or writes a device.

The scanner NEVER approves any physical drive for formatting or encryption.
Real-disk encryption requires its own independently tested backend and gates.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess

LINUX_CMD = ("lsblk", "--json", "--bytes", "--tree",
             "--output", "NAME,PATH,SIZE,TYPE,TRAN,RM,RO,MODEL,MOUNTPOINTS")
WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$items = @(Get-Disk | ForEach-Object {
    $d = $_
    $parts = @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        number = [int]$d.Number
        size_bytes = [long]$d.Size
        model = [string]$d.FriendlyName
        bus_type = [string]$d.BusType
        is_system = [bool]$d.IsSystem
        is_boot = [bool]$d.IsBoot
        is_read_only = [bool]$d.IsReadOnly
        is_offline = [bool]$d.IsOffline
        partition_count = [int]$d.NumberOfPartitions
        inspected_partitions = [int]$parts.Count
        mounted = [bool](@($parts | Where-Object {
            $_.DriveLetter -or @($_.AccessPaths).Count -gt 0
        }).Count -gt 0)
    }
})
ConvertTo-Json -InputObject $items -Compress -Depth 5
"""


class DeviceInspectionError(RuntimeError):
    """The OS inventory is missing, corrupt, or insufficient for display."""


def _decode(raw: str):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 1_000_000:
        raise DeviceInspectionError("Empty or oversized device inventory")
    try:
        return json.loads(raw.lstrip("\ufeff"))
    except ValueError as exc:
        raise DeviceInspectionError("Invalid OS device metadata JSON") from exc


def _number(value, name: str, *, zero: bool = False) -> int:
    if type(value) is int:
        result = value
    elif type(value) is str and re.fullmatch(r"[0-9]{1,20}", value):
        result = int(value)
    else:
        raise DeviceInspectionError(f"Invalid {name}")
    if result < (0 if zero else 1) or result >= 2**64:
        raise DeviceInspectionError(f"Invalid {name}")
    return result


def _bool(value, name: str) -> bool:
    if type(value) is bool:
        return value
    if value in (0, "0"):
        return False
    if value in (1, "1"):
        return True
    raise DeviceInspectionError(f"Invalid {name}")


def _text(value) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 256 or any(
        ord(ch) < 32 for ch in value
    ):
        raise DeviceInspectionError("Invalid device metadata string")
    return value.strip()


def _tree_mounts(node: dict, depth: int = 0) -> tuple[bool, bool, bool]:
    if not isinstance(node, dict) or depth > 16:
        raise DeviceInspectionError("Invalid device tree depth")
    mounts = node.get("mountpoints")
    if mounts is None:
        mounts = []
    if not isinstance(mounts, list):
        raise DeviceInspectionError("Invalid Linux mountpoint list")
    values = [_text(m) for m in mounts]
    mounted = any(values)
    system = any(v in {"/", "/boot", "/boot/efi", "/usr", "/var"}
                 for v in values)
    children = node.get("children", [])
    if not isinstance(children, list) or len(children) > 128:
        raise DeviceInspectionError("Invalid nested devices")
    partitions = False
    for child in children:
        if not isinstance(child, dict) or not isinstance(child.get("type"), str):
            raise DeviceInspectionError("Invalid child block device")
        partitions |= child["type"] == "part"
        child_mounted, child_system, child_partitions = _tree_mounts(child, depth + 1)
        mounted |= child_mounted
        system |= child_system
        partitions |= child_partitions
    return mounted, system, partitions


def parse_linux_inventory(raw: str) -> list[dict]:
    document = _decode(raw)
    if not isinstance(document, dict) or not isinstance(document.get("blockdevices"), list):
        raise DeviceInspectionError("Linux disk inventory missing")
    devices, seen = [], set()
    for disk in document["blockdevices"]:
        if not isinstance(disk, dict):
            raise DeviceInspectionError("Invalid Linux device entry")
        if disk.get("type") != "disk":
            continue
        path = disk.get("path")
        if (not isinstance(path, str) or
                not re.fullmatch(r"/dev/[a-zA-Z0-9._+\-]+", path) or path in seen):
            raise DeviceInspectionError("Invalid or duplicate disk identity")
        seen.add(path)
        mounted, system, partitions = _tree_mounts(disk)
        devices.append({
            "device": path, "bytes": _number(disk.get("size"), "disk size"),
            "model": _text(disk.get("model")), "bus": _text(disk.get("tran")),
            "removable_hint": _bool(disk.get("rm"), "removable flag"),
            "read_only": _bool(disk.get("ro"), "read-only flag"),
            "mounted": mounted, "system_or_boot": system,
            "has_partitions": partitions, "inspection_complete": True,
            "write_authorized": False,
        })
    return sorted(devices, key=lambda device: device["device"])


def parse_windows_inventory(raw: str) -> list[dict]:
    document = _decode(raw)
    if isinstance(document, dict):
        document = [document]
    if not isinstance(document, list):
        raise DeviceInspectionError("Invalid Windows inventory")
    devices, seen = [], set()
    for disk in document:
        if not isinstance(disk, dict):
            raise DeviceInspectionError("Invalid Windows disk metadata")
        number = _number(disk.get("number"), "disk number", zero=True)
        if number in seen:
            raise DeviceInspectionError("Duplicate physical drive identity")
        seen.add(number)
        parts = _number(disk.get("partition_count"), "partition count", zero=True)
        inspected = _number(disk.get("inspected_partitions"),
                            "inspected partition count", zero=True)
        if inspected > parts:
            raise DeviceInspectionError("Partition inventory mismatch")
        devices.append({
            "device": f"PhysicalDrive{number}",
            "bytes": _number(disk.get("size_bytes"), "disk size"),
            "model": _text(disk.get("model")), "bus": _text(disk.get("bus_type")),
            "removable_hint": None,
            "read_only": _bool(disk.get("is_read_only"), "read-only flag"),
            "offline": _bool(disk.get("is_offline"), "offline flag"),
            "mounted": _bool(disk.get("mounted"), "mount flag")
                       if inspected == parts else None,
            "system_or_boot": _bool(disk.get("is_system"), "system flag")
                              or _bool(disk.get("is_boot"), "boot flag"),
            "has_partitions": parts > 0,
            "inspection_complete": inspected == parts,
            "write_authorized": False,
        })
    return sorted(devices, key=lambda device: device["device"])


def inspect_physical_disks(*, system: str | None = None, runner=None) -> dict:
    """Execute a static OS metadata query, never direct block I/O."""
    system = platform.system() if system is None else system
    if system == "Linux":
        argv, parser = list(LINUX_CMD), parse_linux_inventory
    elif system == "Windows":
        argv = ["powershell.exe", "-NoProfile", "-NonInteractive",
                "-Command", WINDOWS_SCRIPT]
        parser = parse_windows_inventory
    else:
        raise DeviceInspectionError("Only Windows/Linux drive inventory is supported")
    runner = subprocess.run if runner is None else runner
    try:
        result = runner(argv, capture_output=True, text=True, timeout=18,
                        check=False)
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise DeviceInspectionError("OS device query failed") from exc
    if result.returncode != 0:
        raise DeviceInspectionError("OS device query unavailable")
    disks = parser(result.stdout)
    return {
        "operation": "PHYSICAL DISKS / READ-ONLY METADATA ONLY",
        "platform": system, "devices": disks, "device_count": len(disks),
        "physical_disk_encryption_enabled": False,
        "warning": "No formatting, mounting, raw writes or device encryption. "
                   "The inventory cannot authorize writes to ANY disk.",
    }


def main() -> int:
    try:
        print(json.dumps(inspect_physical_disks(), ensure_ascii=False, indent=2))
        return 0
    except DeviceInspectionError as exc:
        print("KRYPTA / physical disk inventory failed:", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
