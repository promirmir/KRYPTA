"""Fail-closed callback contract for a future Windows WinFsp adapter.

This module has no dependency on WinFsp and NEVER mounts a volume. It offers
only an explicit, audited subset of requests; all other requests fail closed.
A real native adapter still needs pinned handles, sharing, ACL enforcement,
case-insensitive lookups, reparse defenses and authenticated image unlock.
"""
from __future__ import annotations

from .windows_file_ops import WindowsFileOperations


class UnsupportedWindowsRequest(OSError):
    """Request semantics cannot be safely implemented by this research layer."""


class WindowsCallbackContract:
    def __init__(self, operations: WindowsFileOperations):
        if not isinstance(operations, WindowsFileOperations):
            raise TypeError("Expected authenticated PFS/2-backed operations")
        self._ops = operations

    def dispatch(self, operation: str, **kwargs):
        """Execute only precisely supported callbacks; refuse everything else."""
        allowed = {
            "list_directory": (self._ops.list_directory, frozenset()),
            "stat": (self._ops.stat, frozenset({"path"})),
            "read": (self._ops.read, frozenset({"path", "offset", "length"})),
        }
        entry = allowed.get(operation) if isinstance(operation, str) else None
        if entry is None:
            raise UnsupportedWindowsRequest("Unsupported or potentially mutating callback")
        callback, required = entry
        if frozenset(kwargs) != required:
            raise UnsupportedWindowsRequest("Invalid callback argument set")
        return callback(**kwargs)
