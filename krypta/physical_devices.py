"""Read-only physical disk inventory for KRYPTA's future native volume adapter.

No raw device is opened. No encryption, partitioning, formatting, or device
writes can be authorized by this module. The "candidate" labels are only for
operator identification, NEVER an approval to modify a disk.
"""
from __future__ import annotations

import json
import platform
import subprocess
from typing import Any, Callable

Run = Callable[..., Any]
SCHEMA = "KRYPTA-PHYSICAL-INVENTORY/1"

_WINDOWS = r"""
$ErrorActionPreference = 'Stop'
$items = @(
  Get-Disk -ErrorAction Stop | ForEach-Object {
    [ordered]@{
      number = $_.Number
      path = [string]$_.Path
      name = [string]$_.FriendlyName
      bus = [string]$_.BusType
      size = $_.Size
      boot = $_.IsBoot
      system = $_.IsSystem
      offline = $_.IsOffline
      read_only = $_.IsReadOnly
      partition_style = [string]$_.PartitionStyle
    }
  }
)
[ordered]@{ disks = @($items) } | ConvertTo-Json -Compress -Depth 5
"""


def _report(system: str, status: str, devices: list[dict],
            warnings: list[str] | None = None) -> dict:
    return {
        "schema": SCHEMA,
        "platform": system,
        "status": status,
        "read_only": True,
        "physical_disk_encryption_available": False,
        "any_device_authorized_for_writes": False,
        "devices": devices,
        "warnings": list(warnings or []),
    }


def _size(value: Any) -> int | None:
    if type(value) is int and 0 < value < 2**64:
        return value
    # Powershell sometimes serializes a 64-bit integer as a decimal string.
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        number = int(value)
        if 0 < number < 2**64:
            return number
    return None


def _flag(value: Any) -> bool | None:
    """Never let truthy strings such as 'False' masquerade as a boolean."""
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    return None


def _label(*, system: bool | None, mounted: bool | None,
           removable: bool | None, offline: bool | None = False) -> str:
    if system is True:
        return "system_or_boot_disk"
    if mounted is True:
        return "disk_with_mounted_filesystems"
    if (system is None or mounted is None or removable is None
            or offline is None):
        return "unknown_requires_independent_review"
    if offline is True:
        return "offline_disk"
    if removable is True:
        return "external_candidate_inspection_only"
    return "fixed_disk_requires_independent_review"


def parse_windows_physical(payload: str) -> dict:
    data = json.loads(payload)
    if not isinstance(data, dict) or not isinstance(data.get("disks"), list):
        return _report("windows", "unknown", [],
                       ["Unrecognized disk inventory output."])
    devices = []
    for item in data["disks"]:
        if not isinstance(item, dict):
            continue
        number = item.get("number")
        boot, system = _flag(item.get("boot")), _flag(item.get("system"))
        offline, ro = _flag(item.get("offline")), _flag(item.get("read_only"))
        size = _size(item.get("size"))
        bus = str(item.get("bus") or "unknown")[:32]
        # Get-Disk lacks enough information about *all* active mount paths
        # and descendant operating-system volumes. Mounted state therefore
        # stays UNKNOWN, prohibiting an automated destructive decision.
        mounted = None
        system_disk = None if boot is None or system is None else boot or system
        removable = bus.lower() == "usb" if bus.lower() in (
            "usb", "sata", "nvme", "sas", "scsi", "raid", "ata", "sd", "mmc"
        ) else None
        if size is None or type(number) is not int or number < 0 or ro is None:
            system_disk = None
        status = _label(system=system_disk, mounted=mounted,
                        removable=removable, offline=offline)
        devices.append({
            "device": f"PhysicalDrive{number}" if type(number) is int and number >= 0
                      else "unidentified",
            "name": str(item.get("name") or "unknown")[:128],
            "bus": bus,
            "size_bytes": size,
            "system_or_boot": system_disk,
            "read_only_flag": ro,
            "status": status,
            "write_authorized": False,
        })
    return _report("windows", "inspected", devices,
                   ["Windows mount/volume dependencies are not fully resolved; "
                    "device identification never authorizes encryption."])


def parse_linux_physical(payload: str) -> dict:
    data = json.loads(payload)
    if not isinstance(data, dict) or not isinstance(data.get("blockdevices"), list):
        return _report("linux", "unknown", [],
                       ["Unrecognized lsblk device tree."])

    devices = []
    for root in data["blockdevices"]:
        if not isinstance(root, dict) or root.get("type") != "disk":
            continue
        size = _size(root.get("size"))
        path = root.get("path")
        ro, removable, hotplug = (_flag(root.get("ro")),
                                   _flag(root.get("rm")),
                                   _flag(root.get("hotplug")))
        # The lsblk tree may contain partitions, dm-crypt and LVM descendants.
        # Any mounted descendant is a real data-loss hazard. A missing or
        # malformed descendant tree produces UNKNOWN, never "safe".
        mounted = False
        system_disk = False
        known_tree = True
        nodes = [root]
        while nodes:
            node = nodes.pop()
            if not isinstance(node, dict):
                known_tree = False
                continue
            mountpoints = node.get("mountpoints")
            if not isinstance(mountpoints, list):
                known_tree = False
            else:
                for mount in mountpoints:
                    if isinstance(mount, str) and mount:
                        mounted = True
                        if mount in ("/", "/boot", "/boot/efi", "/usr", "/var"):
                            system_disk = True
                    elif mount is not None:
                        known_tree = False
            children = node.get("children", [])
            if not isinstance(children, list):
                known_tree = False
            else:
                nodes.extend(children)
            # Swap can be active without a standard mount point.
            if str(node.get("fstype") or "").lower() == "swap":
                mounted = True
        if not known_tree:
            mounted = None
            system_disk = None
        if size is None or ro is None or not isinstance(path, str) or not path.startswith("/dev/"):
            system_disk = None
        is_external = None if removable is None or hotplug is None else removable or hotplug
        status = _label(system=system_disk, mounted=mounted,
                        removable=is_external, offline=False)
        devices.append({
            "device": path[:256] if isinstance(path, str) else "unidentified",
            "size_bytes": size,
            "transport": str(root.get("tran") or "unknown")[:32],
            "system_or_boot": system_disk,
            "has_mounted_filesystems": mounted,
            "read_only_flag": ro,
            "status": status,
            "write_authorized": False,
        })
    return _report("linux", "inspected", devices,
                   ["Device-mapper/RAID ancestry, live kernel handles and external "
                    "device identity must be verified before any future write."])


def inspect_physical_disks(
    os_name: str | None = None, runner: Run = subprocess.run,
) -> dict:
    """Inventory devices through OS metadata tools only, with a hard timeout."""
    os_platform = (os_name or platform.system()).lower()
    if os_platform.startswith("win"):
        command = ["powershell.exe", "-NoLogo", "-NoProfile",
                   "-NonInteractive", "-Command", _WINDOWS]
        parser = parse_windows_physical
        system = "windows"
    elif os_platform == "linux":
        command = ["lsblk", "--json", "--bytes", "--paths", "--output",
                   "PATH,TYPE,SIZE,TRAN,RM,HOTPLUG,RO,MOUNTPOINTS,FSTYPE"]
        parser = parse_linux_physical
        system = "linux"
    else:
        return _report(os_platform[:32], "unsupported", [],
                       ["No read-only physical inventory backend for this OS."])
    try:
        result = runner(command, capture_output=True, text=True,
                        timeout=20, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            raise ValueError("Empty/failed OS disk inventory")
        return parser(result.stdout)
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return _report(system, "unknown", [],
                       ["Inventory failed; no device opened or modified."])
