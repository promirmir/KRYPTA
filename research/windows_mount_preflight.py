"""Windows mount prerequisites for disposable KRYPTA test images.

This is a NON-MOUNTING, fail-closed preflight, not a WinFsp adapter.
Never formats disks, installs drivers, opens raw devices or accepts a volume
without a separately maintained trusted receipt. For isolated research only.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


class WindowsMountPreflightError(ValueError):
    """The requested disposable mount setup is not safe or supported."""


def validate_windows_mount_request(image: str | os.PathLike[str],
                                   mount_dir: str | os.PathLike[str],
                                   expected_receipt: str) -> tuple[Path, Path]:
    """Check an existing image and empty mount folder without changing either.

    This deliberately does not claim protection against concurrent path swaps;
    the future native mount adapter MUST pin kernel handles and recheck file
    identities before giving filesystem callbacks access to the container.
    """
    if os.name != "nt":
        raise WindowsMountPreflightError("Windows preflight requires Windows")
    if not isinstance(expected_receipt, str) or len(expected_receipt) != 64 or any(
            c not in "0123456789abcdef" for c in expected_receipt):
        raise WindowsMountPreflightError("A trusted current SHA-256 receipt is required")
    image, mount_dir = Path(image), Path(mount_dir)
    if image.suffix.lower() != ".kpv" or image.is_symlink():
        raise WindowsMountPreflightError("Only existing disposable .kpv files are allowed")
    if not image.is_file() or not stat.S_ISREG(image.stat().st_mode):
        raise WindowsMountPreflightError("The encrypted image must be a regular file")
    if mount_dir.is_symlink() or not mount_dir.is_dir():
        raise WindowsMountPreflightError("An existing ordinary mount directory is required")
    if image.resolve() == mount_dir.resolve():
        raise WindowsMountPreflightError("Image and mount directory cannot be the same")
    if any(mount_dir.iterdir()):
        raise WindowsMountPreflightError("Mount directory must be empty")
    # This module never performs the mount, even when validation succeeds.
    return image, mount_dir
