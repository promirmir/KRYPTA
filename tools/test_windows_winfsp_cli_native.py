"""Native Windows smoke of the actual experimental CLI on a disposable PFS/2 image."""
from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path


class TerminalEnter(io.StringIO):
    """Permit an immediate Enter to stop the native mount in CI."""
    def isatty(self):
        return True


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows-only native mount smoke")
    import win32api
    from krypta.volume_lab import create_image
    from research.paged_keys import unlock_recovery
    from research.paged_volume import PagedResearchVolume
    from tools.windows_mount_readonly import main as mount_cli

    used = win32api.GetLogicalDrives()
    available = next(
        (chr(ord("A") + n) + ":" for n in range(25, 2, -1)
         if not (used & (1 << n))),
        None,
    )
    if not available:
        raise RuntimeError("No disposable free drive letter")
    with tempfile.TemporaryDirectory(prefix="krypta-cli-native-") as tmp:
        base = Path(tmp)
        image = base / "cli.kpv"
        envelope = base / "cli.pvkey"
        recovery = base / "cli.recovery"
        phrase = "Disposable-Only-Long-Password-Not-For-Real-Data"
        report = create_image(image, envelope, recovery, phrase, phrase)
        actual_key, actual_id = unlock_recovery(envelope, recovery)
        with PagedResearchVolume(
            image, actual_key,
            expected_receipt=report["receipt"], read_only=True,
        ) as verified:
            assert verified.id == actual_id
        previous_stdin = sys.stdin
        try:
            sys.stdin = TerminalEnter("\n")
            rc = mount_cli([
                "--image", str(image), "--envelope", str(envelope),
                "--expected-receipt", report["receipt"],
                "--drive", available, "--recovery", str(recovery),
                "--acknowledge-test-only",
            ])
            if rc != 0:
                raise AssertionError("Native Windows CLI did not complete")
        finally:
            sys.stdin = previous_stdin
        if Path(available + "\\").exists():
            raise AssertionError("Experimental CLI left Windows mount active")
        with PagedResearchVolume(
            image, actual_key, expected_receipt=report["receipt"],
            read_only=True,
        ) as verified:
            if verified.id != actual_id:
                raise AssertionError("CLI changed authenticated image identity")
    print("PASS: native Windows source-only CLI unlocked, mounted and unmounted disposable image")


if __name__ == "__main__":
    main()
