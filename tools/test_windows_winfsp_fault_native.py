"""CI-only native WinFsp lost-commit-ACK fault injection.

A deliberately corrupted acknowledgment AFTER a successful PFS/2 commit must
quarantine the mounted view immediately. This NEVER mounts physical media.
Do not expose this driver/entrypoint through user releases.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from tools.test_windows_winfsp_staged_native import _unused_test_drive


def main():
    if os.name != "nt":
        raise RuntimeError("Native lost-ACK test requires Windows")

    import win32api
    import win32con
    import win32security
    import winfspy
    from winfspy.plumbing.security_descriptor import SecurityDescriptor

    from research.paged_volume import PagedResearchVolume, PagedVolumeError
    from research.paged_fs2 import PagedFS2
    from research.receipt_anchor import pin_trusted_image
    from research.windows_file_ops import WindowsFileOperations
    from research.windows_winfsp_staged_test import make_one_shot_test_winfsp_operations

    drive = _unused_test_drive(win32api)
    mount_path = Path(drive + "\\")
    if mount_path.exists():
        raise AssertionError("Will never mount over an occupied drive")

    with (
        tempfile.TemporaryDirectory(prefix="krypta-winfsp-ack-") as work,
        tempfile.TemporaryDirectory(prefix="krypta-winfsp-seal-") as seal_root,
    ):
        root = Path(work)
        image = root / "fault-injected.kpv"
        pin = Path(seal_root) / "trusted.kpin"
        key = os.urandom(32)
        old_content = b"ORIGINAL"
        new_content = b"CHANGED!"
        with PagedResearchVolume(image, key, create=True) as volume:
            fs = PagedFS2.format(volume)
            fs.write_file("sample.txt", old_content)
            old_receipt = fs.receipt
        sealed = pin_trusted_image(image, key, old_receipt, pin)
        pin_before = pin.read_bytes()

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            sid = win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            )
        finally:
            token.Close()
        descriptor = SecurityDescriptor.from_string(
            f"O:{sid}G:{sid}D:P(A;;FA;;;SY)(A;;FA;;;{sid})"
        )

        with PagedResearchVolume(image, key, expected_receipt=old_receipt) as volume:
            fs = PagedFS2(volume)
            callbacks = make_one_shot_test_winfsp_operations(
                WindowsFileOperations(fs), winfspy, test_root=root,
                trusted_pin_path=pin,
                independently_trusted_seal=sealed["seal_sha256"],
                security_descriptor=descriptor,
            )
            real_commit = volume._commit

            def lost_ack(*args, **kwargs):
                real_commit(*args, **kwargs)
                raise OSError("TEST injected ACK loss after PFS/2 final root")

            volume._commit = lost_ack
            native = winfspy.FileSystem(
                drive, callbacks,
                sector_size=512, sectors_per_allocation_unit=1,
                read_only_volume=False, persistent_acls=True,
                case_sensitive_search=True, case_preserved_names=True,
                unicode_on_disk=True, um_file_context_is_user_context2=True,
                file_info_timeout=1000, post_cleanup_when_modified_only=True,
                reject_irp_prior_to_transact0=False, file_system_name=drive,
            )
            started = False
            try:
                native.start()
                started = True
                target = mount_path / "sample.txt"
                if target.read_bytes() != old_content:
                    raise AssertionError("Failed to establish known original state")
                with open(target, "r+b", buffering=0) as handle:
                    if handle.write(new_content) != len(new_content):
                        raise AssertionError("Native staged write failed before flush")
                    try:
                        os.fsync(handle.fileno())
                    except OSError:
                        pass  # Commit acknowledgment was intentionally lost.
                    else:
                        raise AssertionError("WinFsp acknowledged uncertain commit")
                if callbacks._uncertain is not True:
                    raise AssertionError("Lost acknowledgment did not lock mounted state")
                if callbacks.observed_receipt_UNTRUSTED is not None:
                    raise AssertionError("Unverified receipt was falsely published")
                for operation in (
                    lambda: target.read_bytes(),
                    lambda: (mount_path / "sample.txt").stat(),
                    lambda: open(target, "r+b", buffering=0),
                ):
                    try:
                        operation()
                    except OSError:
                        pass
                    else:
                        raise AssertionError("Uncertain mounted view accepted IO")
                print("PASS: native WinFsp lost ACK quarantines data/metadata/writes")
            finally:
                if started or native.started:
                    native.stop()
        if pin.read_bytes() != pin_before:
            raise AssertionError("Uncertain native commit modified trusted pin")
        with __import__("contextlib").suppress(PagedVolumeError):
            with PagedResearchVolume(
                image, key, expected_receipt=old_receipt, read_only=True,
            ) as recovered:
                raise AssertionError(
                    "Old trusted receipt unexpectedly reopened newer committed state"
                )
        if mount_path.exists():
            raise AssertionError("Fault test left native drive mounted")
    print("PASS: disposable lost-ACK native WinFsp fault test")


if __name__ == "__main__":
    main()
