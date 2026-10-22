"""Native WinFsp mount/unmount lifecycle smoke test, disposable images only.

No host disks are formatted or opened. This intentionally denies Windows ACL
discovery, so the filesystem must never be advertised as user-accessible.
A successful lifecycle does NOT demonstrate read/write Explorer compatibility.
"""
from __future__ import annotations

import os
import tempfile
import sys
import faulthandler
from pathlib import Path


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("Native mount test requires Windows")
    import winfspy
    import win32api
    import win32con
    import win32security
    from winfspy.plumbing.security_descriptor import SecurityDescriptor

    from research.paged_volume import PagedResearchVolume
    from research.paged_fs2 import PagedFS2
    from research.windows_file_ops import WindowsFileOperations
    from research.windows_winfsp_readonly import make_readonly_winfsp_operations

    # Only fresh ordinary test files under the temporary CI directory.
    with tempfile.TemporaryDirectory(prefix="krypta-winfsp-") as folder:
        base = Path(folder)
        image = base / "temporary.kpv"
        mountpoint = base / "empty-mount"
        # WinFsp creates the junction/mountpoint itself. An existing directory
        # can produce STATUS_OBJECT_NAME_COLLISION on the native backend.
        assert not mountpoint.exists()
        with PagedResearchVolume(image, os.urandom(32), create=True) as volume:
            fs = PagedFS2.format(volume)
            ops = WindowsFileOperations(fs)
            ops.create(r"\probe.txt")
            ops.write(r"\probe.txt", 0, b"KRYPTA")
            ops.create(r"\second.txt")
            ops.write(r"\second.txt", 0, b"SECOND")
            receipt = fs.receipt
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                sid = win32security.ConvertSidToStringSid(
                    win32security.GetTokenInformation(token, win32security.TokenUser)[0]
                )
            finally:
                token.Close()
            descriptor = SecurityDescriptor.from_string(
                f"O:{sid}G:{sid}D:P(A;;FRFX;;;SY)(A;;FRFX;;;{sid})"
            )
            callbacks = make_readonly_winfsp_operations(
                ops, winfspy, security_descriptor=descriptor
            )
            # CI-only diagnostics: record which native security/open callback
            # rejected the request without broadening the volume DACL.
            for method_name in ("get_security_by_name", "get_security",
                                "open", "read", "read_directory"):
                original = getattr(callbacks, method_name)
                def trace(*args, _original=original, _name=method_name, **kwargs):
                    print(f"WINFSP_TRACE {_name}: called marker={args[1]!r}" if _name == "read_directory" and len(args) > 1 else f"WINFSP_TRACE {_name}: called", flush=True)
                    try:
                        value = _original(*args, **kwargs)
                    except Exception as exc:
                        print(f"WINFSP_TRACE {_name}: denied {type(exc).__name__}: {exc}", flush=True)
                        raise
                    print(f"WINFSP_TRACE {_name}: ok", flush=True)
                    return value
                setattr(callbacks, method_name, trace)
            # Diagnostics only: capture driver response status and actual
            # directory bytes. A successful high-level callback does not
            # establish successful low-level buffer termination.
            from winfspy.plumbing import ffi
            original_ll = callbacks.ll_read_directory
            def traced_ll(*args, **kwargs):
                print(f"WINFSP_LL_DIR: request buffer_size={args[4]}", flush=True)
                result = original_ll(*args, **kwargs)
                print(f"WINFSP_LL_DIR: status={result} bytes={args[5][0]}", flush=True)
                return result
            callbacks.ll_read_directory = traced_ll
            native = winfspy.FileSystem(str(mountpoint), callbacks,
                                        # Match explicit native disk geometry from
                                        # winfspy's working memory filesystem,
                                        # with 4-KiB allocation units.
                                        sector_size=512,
                                        sectors_per_allocation_unit=8,
                                        read_only_volume=True,
                                        # Each open returns a distinct Context object; WinFsp
                                        # must interpret it as a per-open file descriptor,
                                        # not the shared file node (its default mode).
                                        um_file_context_is_user_context2=True,
                                        persistent_acls=False,
                                        case_sensitive_search=True,
                                        case_preserved_names=True,
                                        unicode_on_disk=True,
                                        file_system_name="KRYPTA-TEST")
            started = False
            try:
                native.start()
                started = True
                print("Native WinFsp dispatcher started on ephemeral directory")
                actual = (mountpoint / "probe.txt").read_bytes()
                if actual != b"KRYPTA":
                    raise AssertionError("Native read returned incorrect plaintext")
                print("PASS: actual native Windows read of KRYPTA file")
                print("WINFSP_DIAG: entering native directory enumeration", flush=True)
                faulthandler.dump_traceback_later(12, file=sys.stderr)
                try:
                    names = {p.name for p in mountpoint.iterdir()}
                finally:
                    faulthandler.cancel_dump_traceback_later()
                print(f"WINFSP_DIAG: listed names={sorted(names)}", flush=True)
                if names != {"probe.txt", "second.txt"}:
                    raise AssertionError(f"Native Windows directory listing wrong: {names!r}")
                if (mountpoint / "second.txt").read_bytes() != b"SECOND":
                    raise AssertionError("Second file not readable through native mount")
                try:
                    (mountpoint / "missing.txt").read_bytes()
                except FileNotFoundError:
                    pass
                else:
                    raise AssertionError("Nonexistent native file was readable")
                print("PASS: native Windows directory listing, second-file read, missing-file rejection")
                # Exercise actual Windows handles, not just mocked callbacks.
                # All mutation attempts must fail and retain authenticated content.
                mutation_attempts = (
                    ("overwrite", lambda: (mountpoint / "probe.txt").write_bytes(b"CHANGED")),
                    ("create", lambda: (mountpoint / "new.txt").write_bytes(b"NEW")),
                    ("delete", lambda: (mountpoint / "probe.txt").unlink()),
                    ("rename", lambda: (mountpoint / "probe.txt").rename(mountpoint / "renamed.txt")),
                )
                for action, attempt in mutation_attempts:
                    try:
                        attempt()
                    except OSError:
                        print(f"PASS: native Windows {action} rejected")
                    else:
                        raise AssertionError(f"Read-only mounted volume allowed {action}")
                if (mountpoint / "probe.txt").read_bytes() != b"KRYPTA":
                    raise AssertionError("Data changed after rejected mutation")
                if (mountpoint / "new.txt").exists() or (mountpoint / "renamed.txt").exists():
                    raise AssertionError("Rejected mutation left a visible file")
            finally:
                # Always close the driver mount before image/temporary-dir exit.
                if started or native.started:
                    native.stop()
                    print("Native WinFsp dispatcher stopped")
                else:
                    print("Native mount did not start; no mounted device to stop")
            if fs.receipt != receipt:
                raise AssertionError("Native mount lifecycle unexpectedly changed ciphertext")
    print("PASS: owner-only WinFsp native read and unmount on disposable image")


if __name__ == "__main__":
    main()
