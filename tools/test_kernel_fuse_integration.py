"""Optional disposable Linux FUSE kernel-level integration smoke test.

No real disks, partitions, boot volumes, secrets, or production data are used.
Only runs when /dev/fuse and user-mode FUSE are available. On unsupported
hosts exits 77 (SKIPPED), never counts as an actual mount validation.
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

from research.fs_image import ResearchFileSystem
from research.volume_image import ResearchVolume

SKIP = 77


def main() -> int:
    if sys.platform != "linux" or os.geteuid() == 0:
        print("SKIPPED: Linux non-root user required for FUSE research smoke")
        return SKIP
    unmount = shutil.which("fusermount3") or shutil.which("fusermount")
    if not Path("/dev/fuse").exists() or unmount is None:
        print("SKIPPED: /dev/fuse or fusermount is not available")
        return SKIP
    try:
        from research import linux_fuse
        if linux_fuse.FUSE is None:
            print("SKIPPED: fusepy/libfuse binding is unavailable")
            return SKIP
    except (ImportError, OSError):
        print("SKIPPED: FUSE Python dependency unavailable")
        return SKIP

    with tempfile.TemporaryDirectory(prefix="krypta-kernel-fuse-test-") as temp:
        base = Path(temp)
        image = base / "strictly-disposable.kvi"
        mountpoint = base / "mount"
        mountpoint.mkdir(mode=0o700)
        key = secrets.token_bytes(32)
        marker = b"SYNTHETIC-KRYPTA-FUSE-CI-PROBE-ONLY" * 8
        with ResearchVolume(image, key, create=True) as volume:
            ResearchFileSystem.format(volume)
        input_fd, output_fd = os.pipe()
        proc = None
        mounted = False
        try:
            cmd = [
                sys.executable, "-m", "research.linux_mount",
                "--image", str(image),
                "--mountpoint", str(mountpoint),
                "--key-fd", str(input_fd),
                "--accept-research-risk",
            ]
            proc = subprocess.Popen(
                cmd, pass_fds=(input_fd,), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            os.close(input_fd)
            input_fd = -1
            os.write(output_fd, key)
            os.close(output_fd)
            output_fd = -1
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    # If running a runner which exposes /dev/fuse but refuses
                    # user mounts, keep the outcome explicit and non-green.
                    raise RuntimeError("FUSE process ended without a mount")
                if os.path.ismount(mountpoint):
                    mounted = True
                    break
                time.sleep(0.2)
            if not mounted:
                raise TimeoutError("FUSE did not mount within 25 seconds")

            one = mountpoint / "proof.txt"
            one.write_bytes(marker)
            if one.read_bytes() != marker:
                raise AssertionError("Kernel FUSE read/write mismatch")
            if marker in image.read_bytes() or b"proof.txt" in image.read_bytes():
                raise AssertionError("Research ciphertext contains raw test file contents/name")
            renamed = mountpoint / "renamed.txt"
            one.rename(renamed)
            if renamed.read_bytes() != marker:
                raise AssertionError("Kernel FUSE rename failed")
            renamed.write_bytes(b"revised-" + marker)
            if renamed.read_bytes() != b"revised-" + marker:
                raise AssertionError("Kernel FUSE replacement write failed")
            renamed.unlink()
            if any(mountpoint.iterdir()):
                raise AssertionError("Kernel FUSE unlink did not update directory")
        finally:
            if input_fd >= 0:
                os.close(input_fd)
            if output_fd >= 0:
                os.close(output_fd)
            if mounted:
                try:
                    subprocess.run([unmount, "-u", str(mountpoint)],
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
        with ResearchVolume(image, key) as volume:
            fs = ResearchFileSystem(volume)
            if fs.list_files():
                raise AssertionError("Unmount/reopen mismatch")
            if volume.sequence <= 1:
                raise AssertionError("No encrypted commits after FUSE operations")
    print("PASS: genuine disposable Linux kernel FUSE mount/write/read/rename/unlink/unmount/reopen")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: Linux research FUSE integration: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        raise SystemExit(1) from None
