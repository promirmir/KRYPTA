"""Strict, side-effect-free fixture tests for OS-managed transparent encryption."""
import json
from types import SimpleNamespace
import pytest
from krypta.volume_status import inspect_volumes, parse_linux, parse_windows


def test_windows_confirmed_bitlocker_requires_key_protection_on():
    data = {"available": True, "volumes": [
        {"mount_point": "C:", "kind": "OperatingSystem", "encryption": "XtsAes256",
         "volume_status": "FullyEncrypted", "protection": "On", "percentage": 100},
        {"mount_point": "D:", "kind": "Data", "encryption": "XtsAes256",
         "volume_status": "FullyEncrypted", "protection": "Off", "percentage": 100},
        {"mount_point": "E:", "kind": "Data", "encryption": "None",
         "volume_status": "FullyDecrypted", "protection": "Off", "percentage": 0},
    ]}
    result = parse_windows(json.dumps(data))
    assert [i["status"] for i in result["volumes"]] == [
        "protected_at_rest", "protection_suspended", "not_encrypted"]
    assert not result["hardware_pin_rate_limit_verified"]
    assert not result["krypta_managed_encryption"]


def test_windows_never_certifies_partial_or_unknown():
    result = parse_windows(json.dumps({"available": True, "volumes": [
        {"encryption": "XtsAes256", "volume_status": "FullyEncrypted",
         "protection": "Unknown", "percentage": 100},
        {"encryption": "XtsAes256", "volume_status": "FullyEncrypted",
         "protection": "On", "percentage": 79},
        {"encryption": "XtsAes256", "volume_status": "EncryptionInProgress",
         "protection": "On", "percentage": 79},
    ]}))
    assert [i["status"] for i in result["volumes"]] == [
        "unknown", "unknown", "transition"]


def test_windows_missing_module_is_not_reported_as_protected():
    assert parse_windows('{"available":false,"volumes":[]}')["status"] == "unavailable"


def test_linux_luks_mapped_mount_confirmed_but_plain_unknown():
    payload = {"blockdevices": [
        {"name": "/dev/nvme0n1", "type": "disk", "children": [
            {"name": "/dev/nvme0n1p2", "type": "part", "fstype": "crypto_LUKS",
             "children": [{"name": "/dev/mapper/secure", "type": "crypt", "fstype": "ext4",
                            "mountpoints": ["/"]}]},
            {"name": "/dev/nvme0n1p3", "type": "part", "fstype": "ext4",
             "mountpoints": ["/data"]},
        ]}
    ]}
    result = parse_linux(json.dumps(payload))
    observed = {i["mount_points"][0]: i["status"] for i in result["volumes"]}
    assert observed["/"] == "active_luks_mapping"
    assert observed["/data"] == "unknown_encryption"
    assert result["read_only"]


def test_linux_or_windows_malformed_data_never_claims_secure():
    assert parse_windows('{"available":true,"volumes":{}}')["status"] == "unknown"
    assert parse_linux('{"blockdevices":{}}')["status"] == "unknown"


def test_windows_inspection_invokes_only_read_only_command():
    seen = []
    def runner(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"available":true,"volumes":[]}')
    result = inspect_volumes(os_name="Windows", runner=runner)
    assert result["status"] == "inspected"
    assert "Get-BitLockerVolume" in seen[0][0][-1]
    assert "Enable-BitLocker" not in seen[0][0][-1]
    assert seen[0][1]["timeout"] == 20
    assert seen[0][1]["check"] is False


def test_linux_inspection_is_read_only():
    def runner(argv, **kwargs):
        assert argv == ["lsblk", "--json", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINTS"]
        return SimpleNamespace(returncode=0, stdout='{"blockdevices":[]}')
    assert inspect_volumes("Linux", runner=runner)["status"] == "inspected"


@pytest.mark.parametrize("error", [OSError("no executable"), subprocess_timeout := TimeoutError("slow")])
def test_fails_closed_on_os_errors(error):
    def runner(*args, **kwargs):
        raise error
    # TimeoutError is a subclass of OSError and should fail closed.
    assert inspect_volumes("Linux", runner=runner)["status"] == "unknown"


def test_unknown_platform_does_not_run_commands():
    def runner(*args, **kwargs):
        raise AssertionError("unexpected call")
    assert inspect_volumes("Android", runner=runner)["status"] == "unsupported"


def test_failed_command_or_invalid_json_fails_closed():
    for result in (SimpleNamespace(returncode=1, stdout=""),
                   SimpleNamespace(returncode=0, stdout="not-json")):
        def runner(*args, **kwargs):
            return result
        assert inspect_volumes("Windows", runner=runner)["status"] == "unknown"
