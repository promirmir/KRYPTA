"""ONE-SHOT, TEST-ONLY native WinFsp staged file-write callbacks.

NOT registered by desktop, mounted CLI, or any downloadable release.
Only an isolated disposable .kpv underneath a fresh temporary test directory
is accepted. Exactly one existing file may receive one explicit flush commit.
A receipt from the flush is an UNTRUSTED observation until independently
recorded: never silently permit another write from this same mounted image.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import tempfile
from threading import RLock

from .windows_file_ops import WindowsFileOperations
from .windows_staged_write import StagedWindowsFileWrite, UncertainStagedCommit, MAX_STAGED_FILE_BYTES
from .windows_winfsp_readonly import make_readonly_winfsp_operations
from .receipt_anchor import load_sealed_pin, ReceiptPinError


def make_one_shot_test_winfsp_operations(
    ops: WindowsFileOperations, api, *, test_root: str | Path,
    trusted_pin_path: str | Path, independently_trusted_seal: str,
    security_descriptor=None,
):
    """Build a disposable native callback adapter; no public mount entrypoint.

    The input PFS/2 image MUST be under a private, dedicated temporary
    directory with a separate trusted pin and externally retained seal.
    Until explicit flush, all edits remain in one bounded RAM staging buffer.
    Close without flush discards edits; after flush, the mounted instance is
    write-locked even if verification fails or the acknowledgment is lost.
    """
    if not isinstance(ops, WindowsFileOperations):
        raise TypeError("Expected authenticated Windows file operations")
    fs = ops._fs
    vol = fs._volume
    vol._check()
    if vol.read_only:
        raise ReceiptPinError("Test writer requires write-open disposable volume")
    if Path(vol.path).suffix.lower() != ".kpv":
        raise ReceiptPinError("Only disposable .kpv images are accepted")
    try:
        root = Path(test_root).resolve(strict=True)
        image = Path(vol.path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ReceiptPinError("Write adapter requires a dedicated temp child image") from exc
    temp_base = Path(tempfile.gettempdir()).resolve(strict=True)
    # Avoid temp base itself: must be one new private test directory
    if (root == temp_base or root.parent != temp_base or image.parent != root
            or root.is_symlink() or Path(vol.path).is_symlink()
            or not image.is_file()):
        raise ReceiptPinError("Write adapter requires a dedicated temp child image")
    pin = load_sealed_pin(trusted_pin_path, independently_trusted_seal)
    if (pin["image_id"] != vol.id.hex()
            or pin["sequence"] != vol.sequence
            or not hmac.compare_digest(pin["receipt"], vol.receipt)):
        raise ReceiptPinError("Independent receipt pin does not match test image")
    fs.verify_all()
    readonly = make_readonly_winfsp_operations(
        ops, api, security_descriptor=security_descriptor
    )

    class OneShotOperations(type(readonly)):
        def __init__(self):
            super().__init__()
            self._txn_guard = RLock()
            self._writer_context = None
            self._ever_committed = False
            self._uncertain = False
            self.observed_receipt_UNTRUSTED = None
            self._test_root = root

        class _Handle:
            __slots__ = ("path", "directory", "stage", "closed", "had_writer")
            def __init__(self, original, stage=None):
                self.path = original.path
                self.directory = original.directory
                self.stage = stage
                self.had_writer = stage is not None
                self.closed = False

        def open(self, file_name, create_options, granted_access):
            # The native kernel enforces ACLs; callback additionally refuses
            # operations after an uncertain or completed commit.
            with self._txn_guard:
                if not isinstance(granted_access, int):
                    raise api.NTStatusAccessDenied()
                # FILE_WRITE_DATA and FILE_APPEND_DATA (Win32 access bits).
                wants_write = bool(granted_access & 0x0006)
                # Never consult potentially poisoned PFS/2 metadata after an
                # uncertain flush merely to decide whether a writer is denied.
                if wants_write and (self._ever_committed or self._uncertain):
                    raise api.NTStatusMediaWriteProtected()
                ctx = self._resolve(file_name)
                if wants_write:
                    if (ctx.directory or self._ever_committed or self._uncertain
                            or self._writer_context is not None):
                        raise api.NTStatusMediaWriteProtected()
                    try:
                        stage = StagedWindowsFileWrite(ops, ctx.path, pin["receipt"])
                    except Exception:
                        raise api.NTStatusAccessDenied() from None
                    handle = self._Handle(ctx, stage=stage)
                    self._writer_context = handle
                    return handle
                return self._Handle(ctx)

        def _active(self, ctx):
            if not isinstance(ctx, self._Handle) or ctx.closed:
                raise api.NTStatusAccessDenied()

        def read(self, file_context, offset, length):
            with self._txn_guard:
                self._active(file_context)
                if file_context.stage is None:
                    return super().read(file_context, offset, length)
                if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
                    raise api.NTStatusAccessDenied()
                data = file_context.stage.read(offset, length)
                if not data and length:
                    raise api.NTStatusEndOfFile()
                return data

        def write(self, file_context, buffer, offset, write_to_end_of_file, constrained_io):
            with self._txn_guard:
                self._active(file_context)
                if (file_context.stage is None or self._ever_committed
                        or self._uncertain):
                    raise api.NTStatusMediaWriteProtected()
                stage = file_context.stage
                try:
                    # winfspy's native low-level binding supplies a CFFI
                    # buffer, not necessarily a bytes/bytearray/memoryview.
                    # Accept only objects with Python's buffer protocol and
                    # bound allocation BEFORE materializing plaintext bytes.
                    try:
                        view = memoryview(buffer)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("Invalid native WinFsp buffer") from exc
                    if (view.ndim != 1 or view.itemsize != 1
                            or view.nbytes > MAX_STAGED_FILE_BYTES):
                        raise ValueError("Invalid or oversized native write")
                    payload = view.tobytes()
                    if constrained_io:
                        size = len(stage._buffer)
                        if type(offset) is not int or offset < 0:
                            raise ValueError("Invalid constrained offset")
                        if offset >= size:
                            return 0
                        payload = payload[:size - offset]
                    elif write_to_end_of_file:
                        offset = len(stage._buffer)
                    return stage.write(offset, payload)
                except (ValueError, OverflowError, TypeError):
                    raise api.NTStatusAccessDenied() from None

        def set_file_size(self, file_context, new_size, set_allocation_size):
            with self._txn_guard:
                self._active(file_context)
                if (file_context.stage is None or self._ever_committed
                        or self._uncertain):
                    raise api.NTStatusMediaWriteProtected()
                if set_allocation_size:
                    # Physical allocation hints are not PFS/2 logical resizes.
                    raise api.NTStatusMediaWriteProtected()
                try:
                    file_context.stage.truncate(new_size)
                except (ValueError, TypeError):
                    raise api.NTStatusAccessDenied() from None

        def get_file_info(self, file_context):
            with self._txn_guard:
                self._active(file_context)
                info = super().get_file_info(file_context)
                if file_context.stage is not None and not self._ever_committed:
                    size = len(file_context.stage._buffer)
                    info["file_size"] = size
                    info["allocation_size"] = (size + 4095) // 4096 * 4096
                return info

        def flush(self, file_context):
            with self._txn_guard:
                if file_context is None:
                    if self._writer_context is not None:
                        raise api.NTStatusMediaWriteProtected()
                    return None
                self._active(file_context)
                if file_context.stage is None:
                    if file_context.had_writer:
                        raise api.NTStatusMediaWriteProtected()
                    return None
                if self._ever_committed or self._uncertain:
                    raise api.NTStatusMediaWriteProtected()
                # Fail-closed even if the final commit succeeded but its
                # acknowledgment or subsequent authentication was lost.
                self._uncertain = True
                try:
                    report = file_context.stage.commit()
                except Exception:
                    raise api.NTStatusAccessDenied() from None
                finally:
                    file_context.stage = None
                    self._ever_committed = True
                self.observed_receipt_UNTRUSTED = report["receipt"]
                self._uncertain = False
                return None

        def cleanup(self, file_context, file_name, flags):
            with self._txn_guard:
                self._active(file_context)
                # Native WinFsp sends normal cleanup with metadata hints
                # (0x10 archive; 0x20 last-access; 0x40 last-write;
                # 0x80 change-time), even after a successful explicit flush.
                # Cleanup is a VOID callback: Windows cannot observe errors.
                # Ignore ONLY these optional timestamp/archive hints in this
                # synthetic, non-production filesystem, never invent
                # persisted NTFS metadata or mutate authenticated ciphertext.
                # Deletion (0x01), allocation-size (0x02) and unknown flags
                # remain forbidden. CanDelete/SetDelete are denied separately.
                if type(flags) is not int or flags & ~0xF0:
                    raise api.NTStatusMediaWriteProtected()
                return None

        def close(self, file_context):
            with self._txn_guard:
                if not isinstance(file_context, self._Handle) or file_context.closed:
                    return None
                if file_context.stage is not None:
                    file_context.stage.abort()
                    file_context.stage = None
                if file_context is self._writer_context:
                    self._writer_context = None
                file_context.closed = True

        def create(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def rename(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def can_delete(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def overwrite(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def set_basic_info(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

        def set_security(self, *args, **kwargs):
            raise api.NTStatusMediaWriteProtected()

    return OneShotOperations()
