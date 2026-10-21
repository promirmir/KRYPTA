"""Read-only WinFsp callback implementation over an authenticated PFS/2 image.

No filesystem is mounted by this module; native mount lifecycle, NTFS
security/ACLs, and WinFsp installation require separate end-to-end validation.
Only use disposable .kpv images. All mutations are denied.
"""
from __future__ import annotations

from dataclasses import dataclass

from .windows_file_ops import WindowsFileOperations


def make_readonly_winfsp_operations(ops: WindowsFileOperations, api, *, security_descriptor=None):
    """Build WinFsp callbacks using explicit injectable winfspy bindings."""
    if not isinstance(ops, WindowsFileOperations):
        raise TypeError("Authenticated PFS/2 operations required")
    for field in ("BaseFileSystemOperations", "FILE_ATTRIBUTE",
                  "NTStatusObjectNameNotFound", "NTStatusAccessDenied",
                  "NTStatusMediaWriteProtected", "NTStatusEndOfFile"):
        if not hasattr(api, field):
            raise RuntimeError("Missing WinFsp binding: " + field)
    from threading import RLock
    from datetime import datetime, timezone

    @dataclass(frozen=True)
    class Context:
        path: str
        directory: bool

    class ReadOnlyOperations(api.BaseFileSystemOperations):
        def __init__(self):
            super().__init__()
            self._lock = RLock()
            self._time = 0  # never claim real persistent timestamps

        def _resolve(self, file_name):
            if file_name in ("\\", "/"):
                return Context("\\", True)
            if not isinstance(file_name, str):
                raise api.NTStatusObjectNameNotFound()
            try:
                candidate = ops._filename(file_name)
            except (ValueError, TypeError):
                raise api.NTStatusObjectNameNotFound()
            with self._lock:
                # Exactly matching names only; no ambiguous Windows aliases.
                try:
                    ops.stat(file_name)
                except (FileNotFoundError, KeyError, ValueError):
                    raise api.NTStatusObjectNameNotFound() from None
                return Context("\\" + candidate, False)

        def _info(self, ctx):
            length = 0 if ctx.directory else ops.stat(ctx.path)["size"]
            return {
                "file_attributes": (api.FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY
                                    if ctx.directory else api.FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE),
                "allocation_size": ((length + 4095) // 4096) * 4096,
                "file_size": length,
                "creation_time": self._time,
                "last_access_time": self._time,
                "last_write_time": self._time,
                "change_time": self._time,
                "index_number": 0,
            }

        def get_volume_info(self):
            # Report conservative capacity, not the sparse 1-GiB logical ceiling.
            return {"total_size": 512 * 1024 * 1024, "free_size": 0,
                    "volume_label": "KRYPTA-TEST"}

        def get_security_by_name(self, file_name):
            if security_descriptor is None:
                raise api.NTStatusAccessDenied()
            context = self._resolve(file_name)
            attributes = self._info(context)["file_attributes"]
            return attributes, security_descriptor.handle, security_descriptor.size

        def get_security(self, file_context):
            if security_descriptor is None:
                raise api.NTStatusAccessDenied()
            return security_descriptor

        def open(self, file_name, create_options, granted_access):
            return self._resolve(file_name)

        def close(self, file_context):
            return None

        def get_file_info(self, file_context):
            return self._info(file_context)

        def read_directory(self, file_context, marker):
            if not file_context.directory:
                raise api.NTStatusAccessDenied()
            with self._lock:
                names = sorted(ops.list_directory(), key=lambda n: (n.casefold(), n))
                entries = [{"file_name": n, **self._info(Context("\\" + n, False))}
                           for n in names]
            if marker is None:
                return entries
            return [e for e in entries if (e["file_name"].casefold(), e["file_name"]) >
                    (marker.casefold(), marker)]

        def read(self, file_context, offset, length):
            if file_context.directory:
                raise api.NTStatusAccessDenied()
            if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
                raise api.NTStatusAccessDenied()
            with self._lock:
                info = self._info(file_context)
                if offset >= info["file_size"]:
                    raise api.NTStatusEndOfFile()
                return ops.read(file_context.path, offset, length)

        # Other methods inherit the base adapter's unsupported defaults.
        def create(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def write(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def rename(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def set_file_size(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

    return ReadOnlyOperations()
