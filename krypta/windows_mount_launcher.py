"""Fail-closed Windows GUI hand-off to the isolated read-only WinFsp test tool.

The GUI never collects a mount password. The child console uses getpass and
owns the mount lifetime, even if the desktop UI is closed. No shell or PATH
search is used to locate the helper. This is NOT full-device encryption.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

HELPER_NAME = "KRYPTA-Windows-ReadOnly-Mount-TEST.exe"


def _regular_input(value: str, extension: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("A regular input file is required")
    path = Path(value)
    if path.suffix.lower() != extension or path.is_symlink() or not path.is_file():
        raise ValueError("Input must be an existing, non-symlink regular file")
    return path.resolve(strict=True)


def build_mount_command(
    image: str, envelope: str, receipt: str, drive: str,
    recovery: str = "", *,
    packaged: bool | None = None,
    app_executable: str | Path | None = None,
    source_root: str | Path | None = None,
) -> tuple[list[str], Path]:
    """Validate inputs and locate an exact executable without starting it.

    Extra keyword parameters are for deterministic tests; the UI uses defaults.
    All arguments other than paths and the NON-SECRET receipt are public.
    """
    if type(receipt) is not str or re.fullmatch(r"[0-9a-f]{64}", receipt) is None:
        raise ValueError("An independently trusted current 64-hex receipt is required")
    if type(drive) is not str or re.fullmatch(r"[D-Zd-z]:", drive) is None:
        raise ValueError("Use an unused drive letter D: through Z:")
    image_path = _regular_input(image, ".kpv")
    key_path = _regular_input(envelope, ".pvkey")
    recovery_path = None
    if recovery:
        # No extension is mandated for recovery secrets.
        p = Path(recovery)
        if p.is_symlink() or not p.is_file():
            raise ValueError("Recovery secret must be an existing regular file")
        recovery_path = p.resolve(strict=True)
    paths = [image_path, key_path] + ([recovery_path] if recovery_path else [])
    if len(set(paths)) != len(paths):
        raise ValueError("Image, envelope and recovery secret must be different files")
    for i, first in enumerate(paths):
        for second in paths[i + 1:]:
            if first.samefile(second):
                raise ValueError("Hardlink aliases are not supported")
    if packaged is None:
        packaged = bool(getattr(sys, "frozen", False))
    current = Path(app_executable or sys.executable).resolve(strict=True)
    if packaged:
        helper = current.with_name(HELPER_NAME)
        if helper.is_symlink() or not helper.is_file():
            raise RuntimeError("Place the separately tested read-only mount EXE next to KRYPTA.exe")
        command = [str(helper)]
        cwd = helper.parent
    else:
        # No pythonw.exe: the password must be entered into a child console.
        if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?\.exe", current.name.lower()) is None:
            raise RuntimeError("Source mount requires a console-capable Python.exe on Windows")
        cwd = Path(source_root or Path(__file__).resolve().parent.parent).resolve(strict=True)
        if not (cwd / "tools" / "windows_mount_readonly.py").is_file():
            raise RuntimeError("Source WinFsp mount entrypoint not found")
        command = [str(current), "-m", "tools.windows_mount_readonly"]
    command += [
        "--image", str(image_path), "--envelope", str(key_path),
        "--expected-receipt", receipt, "--drive", drive.upper(),
        "--acknowledge-test-only",
    ]
    if recovery_path is not None:
        command += ["--recovery", str(recovery_path)]
    return command, cwd


def launch_readonly_mount(
    image: str, envelope: str, receipt: str, drive: str, recovery: str = ""
) -> subprocess.Popen:
    if os.name != "nt":
        raise RuntimeError("Windows with WinFsp is required for this test mount")
    command, cwd = build_mount_command(image, envelope, receipt, drive, recovery)
    # Do not use shell=True or redirect standard input: the mount helper must
    # have its own interactive console for password entry and unmount control.
    return subprocess.Popen(
        command, cwd=str(cwd), shell=False, close_fds=True,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
