"""One-shot PFS/2 Linux FUSE write bridge for disposable test images only.

An explicit, sealed external receipt is required. Edits stay in bounded RAM
until flush/fsync; at most one authenticated COW root commit can be attempted.
After a commit (including uncertain ACK), all reads/writes are quarantined
until a NEW independently trusted pin is established after unmount.

No real disks, production data, background trust promotion or device drivers.
"""
from __future__ import annotations

import errno
import hmac
import os
from pathlib import Path
import stat
import tempfile

from .linux_fuse import KryptaFuseOps, FuseOSError
from .paged_fs2 import PagedFS2
from .receipt_anchor import load_sealed_pin, ReceiptPinError

MAX_STAGED_BYTES = 4 * 1024 * 1024


class OneShotStagedFuseOps(KryptaFuseOps):
    """One writer, one file, one flush. PFS2 never sees unflushed data."""

    def __init__(self, fs: PagedFS2, *, test_root: str | Path,
                 trusted_pin_path: str | Path, independently_trusted_seal: str):
        if not isinstance(fs, PagedFS2):
            raise TypeError("One-shot Linux staged writer requires PFS/2")
        fs._check()
        volume = fs._volume
        if volume.read_only:
            raise ReceiptPinError("Staged writer needs a writable test image")
        path = Path(volume.path)
        if path.suffix.lower() != ".kpv" or path.is_symlink():
            raise ReceiptPinError("Only private .kpv regular images are accepted")
        try:
            if Path(test_root).is_symlink():
                raise ReceiptPinError("Symlink test root is forbidden")
            root = Path(test_root).resolve(strict=True)
            image = path.resolve(strict=True)
            tempbase = Path(tempfile.gettempdir()).resolve(strict=True)
            image_info = image.stat()
            root_info = root.stat()
        except OSError as exc:
            raise ReceiptPinError("Missing dedicated disposable test directory") from exc
        if (root == tempbase or root.parent != tempbase or
                image.parent != root or not stat.S_ISREG(image_info.st_mode) or
                root.is_symlink() or not stat.S_ISDIR(root_info.st_mode) or
                image_info.st_nlink != 1):
            raise ReceiptPinError("Only a private temp child .kpv is accepted")
        if os.name == "posix" and (
                os.getuid() == 0 or root_info.st_uid != os.getuid()
                or root_info.st_mode & 0o077):
            raise ReceiptPinError("Non-root, owned 0700 test directory required")
        if (root == Path(trusted_pin_path).resolve(strict=False).parent or
                root in Path(trusted_pin_path).resolve(strict=False).parents):
            raise ReceiptPinError("External receipt pin must be outside test image directory")
        pin = load_sealed_pin(trusted_pin_path, independently_trusted_seal)
        if (pin["image_id"] != volume.id.hex()
                or pin["sequence"] != volume.sequence
                or not hmac.compare_digest(pin["receipt"], volume.receipt)):
            raise ReceiptPinError("Externally sealed receipt does not match image")
        fs.verify_all()
        super().__init__(fs, read_only=False)
        self._trusted_receipt = pin["receipt"]
        self._writer = None
        self._stage: bytearray | None = None
        self._dirty = False
        self._ever_attempted = False
        self._quarantine = False
        self.observed_receipt_UNTRUSTED: str | None = None

    def _safe(self):
        if self._quarantine:
            raise FuseOSError(errno.EIO)

    def _guard_mutation(self):
        self._safe()
        if self._ever_attempted:
            raise FuseOSError(errno.EROFS)

    def _writer_handle(self, path, fh):
        name, mode, append = self._fh(fh, path)
        if mode == os.O_RDONLY or self._writer != fh or self._stage is None:
            raise FuseOSError(errno.EBADF)
        return name, append

    def getattr(self, path, fh=None):
        with self._lock:
            self._safe()
            result = super().getattr(path, fh)
            if fh is not None and fh == self._writer and self._stage is not None:
                self._fh(fh, path)
                result["st_size"] = len(self._stage)
                result["st_blocks"] = (len(self._stage) + 511) // 512
            return result

    def readdir(self, path, fh):
        with self._lock:
            self._safe()
            return super().readdir(path, fh)

    def open(self, path, flags):
        with self._lock:
            self._safe()
            if type(flags) is not int or flags < 0:
                raise FuseOSError(errno.EINVAL)
            mode = flags & 0o3
            if mode not in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
                raise FuseOSError(errno.EINVAL)
            if any(flags & getattr(os, name, 0) for name in (
                    "O_PATH", "O_TMPFILE", "O_DIRECTORY")):
                raise FuseOSError(errno.EOPNOTSUPP)
            if flags & os.O_CREAT or flags & os.O_EXCL:
                raise FuseOSError(errno.EROFS)
            name = self._file_exists(path)
            if mode != os.O_RDONLY or flags & os.O_TRUNC:
                self._guard_mutation()
                if mode == os.O_RDONLY:
                    raise FuseOSError(errno.EACCES)
                if self._writer is not None:
                    raise FuseOSError(errno.EBUSY)
                # Reject ambiguous POSIX names under Windows portability
                # constraints, rather than creating incompatible state.
                if sum(n.casefold() == name.casefold()
                       for n in self._fs.list_files()) != 1:
                    raise FuseOSError(errno.EINVAL)
                old = self._fs.read_file(name)
                if len(old) > MAX_STAGED_BYTES:
                    raise FuseOSError(errno.EFBIG)
                stage = bytearray() if flags & os.O_TRUNC else bytearray(old)
                fh = self._alloc(name, mode, bool(flags & os.O_APPEND))
                self._writer = fh
                self._stage = stage
                self._dirty = bool(flags & os.O_TRUNC and old)
                return fh
            return self._alloc(name, mode, False)

    def read(self, path, size, offset, fh):
        with self._lock:
            self._safe()
            name, mode, _ = self._fh(fh, path)
            if mode == os.O_WRONLY:
                raise FuseOSError(errno.EBADF)
            if (type(size) is not int or type(offset) is not int
                    or size < 0 or offset < 0):
                raise FuseOSError(errno.EINVAL)
            if fh == self._writer and self._stage is not None:
                return bytes(self._stage[offset:offset + size])
            return super().read(path, size, offset, fh)

    def write(self, path, data, offset, fh):
        with self._lock:
            self._guard_mutation()
            _, append = self._writer_handle(path, fh)
            if type(data) is not bytes or type(offset) is not int or offset < 0:
                raise FuseOSError(errno.EINVAL)
            assert self._stage is not None
            if append:
                offset = len(self._stage)
            end = offset + len(data)
            if end > MAX_STAGED_BYTES:
                raise FuseOSError(errno.EFBIG)
            if not data:
                return 0
            if offset > len(self._stage):
                self._stage.extend(bytes(offset - len(self._stage)))
            if end > len(self._stage):
                self._stage.extend(bytes(end - len(self._stage)))
            self._stage[offset:end] = data
            self._dirty = True
            return len(data)

    def truncate(self, path, length, fh=None):
        with self._lock:
            self._guard_mutation()
            if fh is None:
                raise FuseOSError(errno.EROFS)
            self._writer_handle(path, fh)
            if type(length) is not int or not 0 <= length <= MAX_STAGED_BYTES:
                raise FuseOSError(errno.EFBIG)
            assert self._stage is not None
            if length != len(self._stage):
                if length < len(self._stage):
                    del self._stage[length:]
                else:
                    self._stage.extend(bytes(length - len(self._stage)))
                self._dirty = True
            return 0

    def flush(self, path, fh):
        with self._lock:
            self._fh(fh, path)
            self._safe()
            if fh != self._writer:
                return 0
            if self._ever_attempted or self._stage is None:
                raise FuseOSError(errno.EROFS)
            if not self._dirty:
                return 0
            # This can be an acknowledgment-loss boundary. Quarantine before
            # touching on-disk ciphertext and do not automatically trust the
            # receipt even when the operation returns success.
            self._ever_attempted = True
            self._quarantine = True
            try:
                if not hmac.compare_digest(self._fs.receipt, self._trusted_receipt):
                    raise RuntimeError("Stale external trusted receipt")
                candidate_data = bytes(self._stage)
                name = self._fh(fh, path)[0]
                self._fs.write_file(name, candidate_data, replace=True)
                observed = self._fs.receipt
                self._fs.verify_all()
                if self._fs.read_file(name) != candidate_data:
                    raise RuntimeError("Authenticated staged readback mismatch")
                self.observed_receipt_UNTRUSTED = observed
                return 0
            except BaseException as exc:
                # Preserve prior external pin, and never retry in this mount.
                raise FuseOSError(errno.EIO) from exc
            finally:
                self._stage[:] = bytes(len(self._stage))
                self._stage = None

    def fsync(self, path, datasync, fh):
        return self.flush(path, fh)

    def release(self, path, fh):
        with self._lock:
            self._fh(fh, path)
            if fh == self._writer:
                if self._stage is not None:
                    self._stage[:] = bytes(len(self._stage))
                    self._stage = None
                self._writer = None
                self._dirty = False
            del self._handles[fh]
            return 0

    def statfs(self, path):
        with self._lock:
            self._safe()
            result = super().statfs(path)
            if self._ever_attempted:
                result["f_bavail"] = 0
                result["f_bfree"] = 0
            return result

    def create(self, *args):
        raise FuseOSError(errno.EROFS)

    def unlink(self, *args):
        raise FuseOSError(errno.EROFS)

    def rename(self, *args):
        raise FuseOSError(errno.EROFS)
