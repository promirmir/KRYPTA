"""Safe argument validation for the opt-in Windows read-only mount entrypoint."""
import os

import pytest

from tools.windows_mount_readonly import (
    _arguments, _drive_letter, _drive_is_free, main,
)


VALID_RECEIPT = "a" * 64


def args(*extra):
    return [
        "--image", "temporary.kpv", "--envelope", "temporary.pvkey",
        "--expected-receipt", VALID_RECEIPT, "--drive", "Z:",
        "--acknowledge-test-only", *extra,
    ]


@pytest.mark.parametrize("invalid", ["C:", "a:", "Z:\\", "Z:\\Windows", "Z:foo",
                                     "\\\\.\\PhysicalDrive0", "", "AA:", "3:"])
def test_mount_refuses_disks_paths_and_invalid_letters(invalid):
    with pytest.raises(ValueError):
        _drive_letter(invalid)


def test_mount_accepts_unused_upper_or_lower_disposable_letter():
    assert _drive_letter("z:") == "Z:"
    assert _drive_is_free("Z:", 1 << (ord("C") - ord("A")))
    assert not _drive_is_free("Z:", 1 << (ord("Z") - ord("A")))


def test_mount_requires_explicit_experimental_acknowledgment():
    with pytest.raises(SystemExit):
        _arguments(args()[:-1])


def test_mount_requires_exact_externally_supplied_receipt():
    with pytest.raises(SystemExit):
        _arguments([
            "--image", "temporary.kpv", "--envelope", "temporary.pvkey",
            "--expected-receipt", "incorrect", "--drive", "Z:",
            "--acknowledge-test-only",
        ])


def test_mount_accepts_only_separate_recovery_file_not_key_on_command_line():
    parsed = _arguments(args("--recovery", "offline-recovery.key"))
    assert parsed.drive == "Z:"
    assert parsed.recovery == "offline-recovery.key"
    with pytest.raises(SystemExit):
        _arguments(args("--password", "not-allowed"))


@pytest.mark.skipif(os.name == "nt", reason="Windows native operation covered in WinFsp CI")
def test_non_windows_platform_never_attempts_native_mount():
    with pytest.raises(RuntimeError, match="requires Windows"):
        main(args())
