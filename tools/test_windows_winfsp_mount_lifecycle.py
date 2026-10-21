"""Native WinFsp mount/unmount lifecycle smoke test, disposable images only.

No host disks are formatted or opened. This intentionally denies Windows ACL
discovery, so the filesystem must never be advertised as user-accessible.
A successful lifecycle does NOT demonstrate read/write Explorer compatibility.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("Native mount test requires Windows")
    import winfspy

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
            receipt = fs.receipt
            callbacks = make_readonly_winfsp_operations(ops, winfspy)
            native = winfspy.FileSystem(str(mountpoint), callbacks,
                                        read_only_volume=True,
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
            finally:
                # Always close the driver mount before image/temporary-dir exit.
                if started or native.started:
                    native.stop()
                    print("Native WinFsp dispatcher stopped")
                else:
                    print("Native mount did not start; no mounted device to stop")
            if fs.receipt != receipt:
                raise AssertionError("Native mount lifecycle unexpectedly changed ciphertext")
    print("PASS: native WinFsp ephemeral start/stop (NOT user-accessible filesystem)")


if __name__ == "__main__":
    main()
