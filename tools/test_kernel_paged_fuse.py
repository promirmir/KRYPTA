"""Actual Linux kernel FUSE smoke for KRYPTA-PFS/1 disposable .kpv images.

Exit 77 when the runner has no usable FUSE device; distinguish SKIP from
PASS. Never touch physical disks, user secrets, root or boot partitions.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from research.paged_fs import PagedFileSystem, MAX_FILE_BYTES
from research.paged_volume import PagedResearchVolume

SKIP = 77


def main() -> int:
    if sys.platform != "linux" or os.geteuid() == 0:
        print("SKIP: Linux nonroot FUSE required")
        return SKIP
    unmount = shutil.which("fusermount3") or shutil.which("fusermount")
    if not Path("/dev/fuse").exists() or not unmount:
        print("SKIP: /dev/fuse or user unmount utility unavailable")
        return SKIP
    try:
        from research import linux_fuse
        if linux_fuse.FUSE is None:
            print("SKIP: libfuse/fusepy not available")
            return SKIP
    except (ImportError, OSError):
        print("SKIP: optional FUSE dependency unavailable")
        return SKIP

    with tempfile.TemporaryDirectory(prefix="krypta-paged-fuse-") as temp:
        base = Path(temp)
        image, folder = base / "only-test-image.kpv", base / "mount"
        folder.mkdir(mode=0o700)
        key = secrets.token_bytes(32)
        marker = secrets.token_bytes(610 * 1024)  # larger than entire legacy VIMG capacity
        assert len(marker) < MAX_FILE_BYTES
        with PagedResearchVolume(image, key, create=True) as vol:
            fs = PagedFileSystem.format(vol)
            receipt = fs.receipt

        read_fd, write_fd = os.pipe()
        proc = None
        mounted = False
        try:
            proc = subprocess.Popen(
                [
                    sys.executable, "-m", "research.linux_mount_paged",
                    "--image", str(image), "--mountpoint", str(folder),
                    "--key-fd", str(read_fd), "--expected-receipt", receipt,
                    "--accept-development-risk",
                ],
                pass_fds=(read_fd,), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            os.close(read_fd)
            read_fd = -1
            os.write(write_fd, key)
            os.close(write_fd)
            write_fd = -1
            limit = time.monotonic() + 30
            while time.monotonic() < limit:
                if proc.poll() is not None:
                    raise RuntimeError("Paged FUSE process exited before mounting")
                if os.path.ismount(folder):
                    mounted = True
                    break
                time.sleep(0.2)
            if not mounted:
                raise TimeoutError("Paged FUSE mount timed out")

            first = folder / "larger-than-old-engine.bin"
            first.write_bytes(marker)
            if first.read_bytes() != marker:
                raise AssertionError("Large encrypted file read/write mismatch")
            if b"larger-than-old-engine.bin" in image.read_bytes() or marker[:96] in image.read_bytes():
                raise AssertionError("Plaintext/name appears in encrypted image")
            renamed = folder / "renamed-encrypted.bin"
            first.rename(renamed)
            if renamed.read_bytes() != marker:
                raise AssertionError("Renamed encrypted data mismatch")
            with renamed.open("ab") as file:
                file.write(b"AFTER-RENAME")
            if renamed.stat().st_size != len(marker) + len(b"AFTER-RENAME"):
                raise AssertionError("Append size mismatch")
            if renamed.read_bytes() != marker + b"AFTER-RENAME":
                raise AssertionError("Appended encrypted data mismatch")
            renamed.unlink()
            if list(folder.iterdir()):
                raise AssertionError("Unlink failed to update the encrypted catalogue")
        finally:
            for fd in (read_fd, write_fd):
                if fd >= 0:
                    os.close(fd)
            if mounted:
                try:
                    subprocess.run([unmount, "-u", str(folder)],
                                   check=False, capture_output=True, timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if proc is not None:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)

        with PagedResearchVolume(image, key) as vol:
            fs = PagedFileSystem(vol)
            assert fs.list_files() == []
            assert vol.sequence > 1
            assert fs.verify_all()["files_verified"] == 0
    print("PASS: genuine PVIMG-PFS Linux kernel FUSE mount, 610-KiB write/read, rename, append, unlink, unmount and authenticated reopen")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: PFS kernel FUSE smoke: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        raise SystemExit(1) from None
