"""Real Windows WinFsp one-shot write test over a THROWAWAY PFS/2 image.

This is CI-only. No physical disk is opened, no existing drive is mounted,
and there is deliberately NO public writable mount CLI or release executable.
All plaintext is synthetic. A separately pinned test receipt must match.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile


def _unused_test_drive(win32api):
    mask = win32api.GetLogicalDrives()
    for letter in "ZYXWVUTSRQP":
        if not (mask & (1 << (ord(letter) - ord("A")))):
            drive = letter + ":"
            if not Path(drive + "\\").exists():
                return drive
    raise RuntimeError("No free high drive letter for disposable native test")


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("Native WinFsp writing must be tested on Windows")

    import win32api
    import win32con
    import win32security
    import winfspy
    from winfspy.plumbing.security_descriptor import SecurityDescriptor

    from research.paged_fs2 import PagedFS2
    from research.paged_volume import PagedResearchVolume, PagedVolumeError
    from research.receipt_anchor import (
        pin_trusted_image, verify_image_with_sealed_pin,
    )
    from research.windows_file_ops import WindowsFileOperations
    from research.windows_winfsp_staged_test import (
        make_one_shot_test_winfsp_operations,
    )

    drive = _unused_test_drive(win32api)
    mountpoint = Path(drive + "\\")
    if mountpoint.exists():
        raise RuntimeError("Existing drive path must never be reused")
    key = os.urandom(32)
    # Each directory is isolated directly underneath the system temp folder.
    # The writable image and its test pin must NOT share a directory.
    with (
        tempfile.TemporaryDirectory(prefix="krypta-native-write-") as workspace,
        tempfile.TemporaryDirectory(prefix="krypta-native-pin-") as pinspace,
    ):
        base, pin_dir = Path(workspace), Path(pinspace)
        image = base / "disposable.kpv"
        pin_path = pin_dir / "baseline.kpin"
        before_data = b"KRYPTA00"
        after_data = b"UPDATED!"
        with PagedResearchVolume(image, key, create=True) as volume:
            fs = PagedFS2.format(volume)
            fs.write_file("sample.txt", before_data)
            baseline_receipt, start_sequence = fs.receipt, fs.sequence

        # The seal is trusted solely because this controlled test just created
        # the baseline. A real product MUST obtain it from external storage.
        sealed = pin_trusted_image(image, key, baseline_receipt, pin_path)
        if sealed["trust_promoted"] is not False:
            raise AssertionError("Synthetic baseline was auto-enrolled as trusted")
        original_pin_bytes = pin_path.read_bytes()

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            user_sid = win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(
                    token, win32security.TokenUser
                )[0]
            )
        finally:
            token.Close()
        # User/SYSTEM only, no Everyone or Authenticated Users grant.
        # Even with this test DACL, file creation/deletion/rename callbacks
        # fail closed. The public mounts use read-only ACLs instead.
        descriptor = SecurityDescriptor.from_string(
            f"O:{user_sid}G:{user_sid}D:P(A;;FA;;;SY)(A;;FA;;;{user_sid})"
        )

        with PagedResearchVolume(
            image, key, expected_receipt=baseline_receipt
        ) as writer:
            fs = PagedFS2(writer)
            callbacks = make_one_shot_test_winfsp_operations(
                WindowsFileOperations(fs), winfspy, test_root=base,
                trusted_pin_path=pin_path,
                independently_trusted_seal=sealed["seal_sha256"],
                security_descriptor=descriptor,
            )
            # Diagnostic native I/O trace: metadata only, no secrets or
            # plaintext. It is essential to distinguish Win32 failures from
            # failures in our higher-level staged callbacks.
            for method_name in (
                "get_security_by_name", "open", "get_file_info", "write",
                "flush", "cleanup", "close", "set_file_size", "overwrite",
            ):
                original = getattr(callbacks, method_name)
                def trace(*args, _name=method_name, _fn=original, **kwargs):
                    markers = ""
                    if _name == "open" and len(args) >= 3:
                        markers = f" access={args[2]!r}"
                    elif _name == "cleanup" and len(args) >= 3:
                        markers = f" flags={args[2]!r}"
                    elif _name == "write" and len(args) >= 5:
                        markers = (
                            f" size={len(args[1])} offset={args[2]!r}"
                            f" offset_type={type(args[2]).__name__}"
                            f" append={args[3]!r} constrained={args[4]!r}"
                            f" has_stage={getattr(args[0], 'stage', None) is not None}"
                        )
                    print(f"WINFSP_STAGE {_name} begin{markers}", flush=True)
                    try:
                        result = _fn(*args, **kwargs)
                    except Exception as exc:
                        print(f"WINFSP_STAGE {_name} denied {type(exc).__name__}", flush=True)
                        raise
                    if _name == "open" and getattr(result, "stage", None) is not None:
                        stage = result.stage
                        original_write = stage.write
                        def trace_stage_write(offset, payload):
                            print(
                                f"STAGE_INPUT offset={offset!r} "
                                f"offset_type={type(offset).__name__} "
                                f"payload_type={type(payload).__name__} "
                                f"payload_length={len(payload)}",
                                flush=True,
                            )
                            try:
                                return original_write(offset, payload)
                            except Exception as error:
                                print(
                                    f"STAGE_FAIL {type(error).__name__}: {error}",
                                    flush=True,
                                )
                                raise
                        stage.write = trace_stage_write
                    print(f"WINFSP_STAGE {_name} success", flush=True)
                    return result
                setattr(callbacks, method_name, trace)
            native = winfspy.FileSystem(
                drive, callbacks, sector_size=512,
                sectors_per_allocation_unit=1,
                read_only_volume=False,
                persistent_acls=True, case_sensitive_search=True,
                case_preserved_names=True, unicode_on_disk=True,
                um_file_context_is_user_context2=True, file_info_timeout=1000,
                post_cleanup_when_modified_only=True,
                reject_irp_prior_to_transact0=False,
                file_system_name=drive,
            )
            started = False
            try:
                native.start()
                started = True
                target = mountpoint / "sample.txt"
                if target.read_bytes() != before_data:
                    raise AssertionError("Native baseline read incorrect")

                # Real Win32 filesystem write and FlushFileBuffers via fsync.
                # The image MUST NOT change before explicit flush.
                with open(target, "r+b", buffering=0) as handle:
                    result = handle.write(after_data)
                    if result != len(after_data):
                        raise AssertionError("Native Windows wrote partial bytes")
                    if fs.receipt != baseline_receipt:
                        raise AssertionError("Native write bypassed staging")
                    os.fsync(handle.fileno())
                if fs.read_file("sample.txt") != after_data:
                    raise AssertionError("Native flush failed to encrypt new bytes")
                if fs.sequence != start_sequence + 1:
                    raise AssertionError("Expected exactly ONE authenticated commit")
                untrusted_new_receipt = callbacks.observed_receipt_UNTRUSTED
                if untrusted_new_receipt != fs.receipt:
                    raise AssertionError("Committed receipt not reported as UNTRUSTED")
                if untrusted_new_receipt == baseline_receipt:
                    raise AssertionError("Flush failed to advance receipt")

                # Every further writer attempt MUST fail, including same name.
                try:
                    with open(target, "r+b", buffering=0) as again:
                        again.write(b"OTHER!!!")
                        os.fsync(again.fileno())
                except OSError:
                    pass
                else:
                    raise AssertionError("Native WinFsp accepted second writer")
                if fs.read_file("sample.txt") != after_data:
                    raise AssertionError("Denied second write changed authenticated data")
                if (mountpoint / "new.txt").exists():
                    raise AssertionError("Unexpected file creation")
                print("PASS: Windows real WinFsp write + fsync => 1 COW commit")
            finally:
                if started or native.started:
                    native.stop()
                    print("Native staged WinFsp mount stopped")

        # Old pinned state MUST reject newer ciphertext. A mere observation
        # from the mounted callback cannot silently promote trust.
        try:
            verify_image_with_sealed_pin(
                image, key, pin_path, sealed["seal_sha256"]
            )
        except PagedVolumeError:
            pass
        else:
            raise AssertionError("Stale seal accepted an untrusted descendant")
        if pin_path.read_bytes() != original_pin_bytes:
            raise AssertionError("Driver changed immutable external receipt pin")
        try:
            with PagedResearchVolume(
                image, key, expected_receipt=baseline_receipt, read_only=True
            ):
                pass
        except PagedVolumeError:
            pass
        else:
            raise AssertionError("Old receipt opened a different sequence")
        # Read-back with observed receipt is *forensic*, not trust promotion.
        with PagedResearchVolume(
            image, key, expected_receipt=untrusted_new_receipt, read_only=True
        ) as readback:
            if PagedFS2(readback).read_file("sample.txt") != after_data:
                raise AssertionError("Native committed ciphertext cannot be recovered")
        if mountpoint.exists():
            raise AssertionError("Native write test left a drive mounted")
    print("PASS: isolated synthetic one-shot native WinFsp staged write")


if __name__ == "__main__":
    main()
