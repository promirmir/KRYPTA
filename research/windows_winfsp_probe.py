"""Fail-closed WinFsp dependency readiness probe for KRYPTA development.

No driver installation, mounting, formatting, or physical disk access.
A successful probe is NOT evidence of a secure working filesystem.
"""
from __future__ import annotations

import importlib
import os
from dataclasses import dataclass


class WinFspUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class WinFspCapabilities:
    available: bool
    backend: str
    reason: str


def probe_winfsp(*, platform: str | None = None, loader=None) -> WinFspCapabilities:
    system = os.name if platform is None else platform
    if system != "nt":
        return WinFspCapabilities(False, "winfspy", "WinFsp requires Windows")
    load = importlib.import_module if loader is None else loader
    try:
        api = load("winfspy")
    except (ImportError, OSError) as exc:
        return WinFspCapabilities(False, "winfspy", f"WinFsp bindings unavailable: {type(exc).__name__}")
    required = ("FileSystem", "BaseFileSystemOperations", "NTStatusAccessDenied")
    missing = [name for name in required if not hasattr(api, name)]
    if missing:
        return WinFspCapabilities(False, "winfspy", "Missing required bindings: " + ", ".join(missing))
    # WinFsp installation, permissions and actual mounting MUST be checked by
    # a separate native smoke test before enabling even read-only mounts.
    return WinFspCapabilities(True, "winfspy", "Python binding surface present; native mount unverified")


def require_winfsp(*, platform: str | None = None, loader=None):
    status = probe_winfsp(platform=platform, loader=loader)
    if not status.available:
        raise WinFspUnavailable(status.reason)
    return status
