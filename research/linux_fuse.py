"""Research-only Linux FUSE interface to KRYPTA's OWN encrypted filesystem.

Supports a small, flat, disposable .kvi volume. FUSE is only the kernel I/O
adapter: authenticated encryption/storage are implemented by KRYPTA-FS/VIMG.
Never mount on an important host or store unique data. No system disk access.
"""
from __future__ import annotations

import errno
import functools
import os
import stat
import threading
import time

from .fs_image import (
    CATALOGUE_SECTORS, MAX_FILE_BYTES, MAX_FILES,
    ResearchFSError, ResearchFileSystem,
)
from .volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume, VolumeImageError

# Optional package: pytest can exercise the adapter on Windows/Linux even if
# the machine does not have libfuse or the 'fusepy' Python distribution.
try:
    from fuse import FUSE, FuseOSError, Operations
except (ImportError, OSError):
    FUSE = None

    class Operations:
        pass

    class FuseOSError(OSError):
        def __init__(self, code):
            super().__init__(code, os.strerror(code))


def _api(func):
    @functools.wraps(func)
    def call(self, *args, **kwargs):
        with self._lock:
            try:
                self._fs._check()
                return func(self, *args, **kwargs)
            except FuseOSError:
                raise
            except FileNotFoundError as exc:
                raise FuseOSError(errno.ENOENT) from exc
            except FileExistsError as exc:
                raise FuseOSError(errno.EEXIST) from exc
            except PermissionError as exc:
                raise FuseOSError(errno.EACCES) from exc
            except ResearchFSError as exc:
                desc = str(exc).lower()
                code = (errno.ENOSPC if any(w in desc for w in ("not enough", "quota", "maximum", "count"))
                        else errno.EFBIG if "fit" in desc or "size" in desc
                        else errno.EINVAL)
                raise FuseOSError(code) from exc
            except (VolumeImageError, OSError) as exc:
                raise FuseOSError(errno.EIO) from exc
            except (TypeError, ValueError) as exc:
                raise FuseOSError(errno.EINVAL) from exc
    return call


class KryptaFuseOps(Operations):
    """Flat-directory filesystem; serializes every request through one lock.

    The process and the mount remain trusted. This is NOT protection against
    malware with root privileges, untrusted FUSE peers or a compromised host.
    """

    def __init__(self, fs: ResearchFileSystem):
        if not isinstance(fs, ResearchFileSystem):
            raise TypeError("Expected KRYPTA ResearchFileSystem")
        fs._check()
        self._fs = fs
        self._lock = threading.RLock()
        self._handles = {}  # fh: (filename, access mode, append flag)
        self._next_handle = 1
        self._mounted_at = time.time()

    @staticmethod
    def _filename(path: str) -> str:
        if not isinstance(path, str) or not path.startswith("/") or path == "/":
            raise FuseOSError(errno.EISDIR if path == "/" else errno.EINVAL)
        if path.count("/") != 1:
            raise FuseOSError(errno.ENOENT)
        return path[1:]

    def _file_exists(self, path: str) -> str:
        name = self._filename(path)
        self._fs.stat(name)
        return name

    def _fh(self, fh: int):
        if type(fh) is not int or fh not in self._handles:
            raise FuseOSError(errno.EBADF)
        return self._handles[fh]

    def _alloc(self, name, mode, append):
        fh = self._next_handle
        self._next_handle += 1
        self._handles[fh] = (name, mode, append)
        return fh

    @_api
    def getattr(self, path, fh=None):
        common = {
            "st_uid": getattr(os, "getuid", lambda: 0)(),
            "st_gid": getattr(os, "getgid", lambda: 0)(),
            "st_atime": self._mounted_at, "st_mtime": self._mounted_at,
            "st_ctime": self._mounted_at,
        }
        if path == "/":
            return {**common, "st_mode": stat.S_IFDIR | 0o700, "st_nlink": 2,
                    "st_size": 0}
        name = self._file_exists(path)
        size = self._fs.stat(name)["size"]
        return {**common, "st_mode": stat.S_IFREG | 0o600, "st_nlink": 1,
                "st_size": size, "st_blocks": (size + 511) // 512}

    @_api
    def readdir(self, path, fh):
        if path != "/":
            raise FuseOSError(errno.ENOTDIR)
        return [".", "..", *self._fs.list_files()]

    @_api
    def open(self, path, flags):
        name = self._file_exists(path)
        # POSIX access-mode mask uses low two bits. Python for Windows does
        # not export os.O_ACCMODE, but test the mapping on both platforms.
        mode = flags & 0o3
        if mode not in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
            raise FuseOSError(errno.EINVAL)
        if flags & os.O_TRUNC:
            if mode == os.O_RDONLY:
                raise FuseOSError(errno.EACCES)
            self._fs.write_file(name, b"", replace=True)
        return self._alloc(name, mode, bool(flags & os.O_APPEND))

    @_api
    def create(self, path, mode, fi=None):
        if not stat.S_ISREG(stat.S_IFREG | mode):
            raise FuseOSError(errno.EINVAL)
        name = self._filename(path)
        self._fs.write_file(name, b"", replace=False)
        return self._alloc(name, os.O_RDWR, False)

    @_api
    def read(self, path, size, offset, fh):
        name, mode, _ = self._fh(fh)
        if mode == os.O_WRONLY:
            raise FuseOSError(errno.EBADF)
        if type(size) is not int or type(offset) is not int or offset < 0 or size < 0:
            raise FuseOSError(errno.EINVAL)
        if size > MAX_FILE_BYTES:
            raise FuseOSError(errno.EFBIG)
        return self._fs.read_file(name)[offset:offset + size]

    @_api
    def write(self, path, data, offset, fh):
        name, mode, append = self._fh(fh)
        if mode == os.O_RDONLY:
            raise FuseOSError(errno.EBADF)
        if type(offset) is not int or offset < 0 or not isinstance(data, bytes):
            raise FuseOSError(errno.EINVAL)
        previous = self._fs.read_file(name)
        if append:
            offset = len(previous)
        if offset + len(data) > MAX_FILE_BYTES:
            raise FuseOSError(errno.EFBIG)
        # A single filesystem transaction is committed for each FUSE write.
        new_value = (previous[:offset] + bytes(max(0, offset - len(previous)))
                     + data + previous[offset + len(data):])
        if data:
            self._fs.write_file(name, new_value, replace=True)
        return len(data)

    @_api
    def truncate(self, path, length, fh=None):
        name = self._file_exists(path)
        if fh is not None:
            handle_name, mode, _ = self._fh(fh)
            if handle_name != name or mode == os.O_RDONLY:
                raise FuseOSError(errno.EACCES)
        if type(length) is not int or length < 0 or length > MAX_FILE_BYTES:
            raise FuseOSError(errno.EFBIG)
        old = self._fs.read_file(name)
        new = old[:length].ljust(length, b"\0")
        if old != new:
            self._fs.write_file(name, new, replace=True)
        return 0

    @_api
    def unlink(self, path):
        name = self._file_exists(path)
        if any(entry[0] == name for entry in self._handles.values()):
            # POSIX's unlink-while-open semantics are not implemented yet.
            raise FuseOSError(errno.EBUSY)
        self._fs.delete_file(name)
        return 0

    @_api
    def rename(self, old, new):
        name = self._file_exists(old)
        if any(entry[0] == name for entry in self._handles.values()):
            raise FuseOSError(errno.EBUSY)
        self._fs.rename_file(name, self._filename(new))
        return 0

    @_api
    def release(self, path, fh):
        self._fh(fh)
        del self._handles[fh]
        return 0

    @_api
    def flush(self, path, fh):
        self._fh(fh)
        # Underlying ResearchVolume performs a flush/fsync per commit.
        return 0

    @_api
    def fsync(self, path, datasync, fh):
        self._fh(fh)
        os.fsync(self._fs._volume._f.fileno())
        return 0

    @_api
    def statfs(self, path):
        if path != "/":
            raise FuseOSError(errno.ENOENT)
        used = sum((self._fs.stat(n)["size"] + BLOCK_BYTES - 1) // BLOCK_BYTES
                   for n in self._fs.list_files())
        total = MAX_BLOCKS - CATALOGUE_SECTORS
        available = max(0, total - used)
        return {"f_bsize": BLOCK_BYTES, "f_frsize": BLOCK_BYTES,
                "f_blocks": total, "f_bfree": available, "f_bavail": available,
                "f_files": MAX_FILES, "f_ffree": MAX_FILES - len(self._fs.list_files()),
                "f_namemax": 96}

    # The flat test FS cannot persist POSIX permissions, directories, xattrs,
    # hard links, symlinks or timestamps. Fail instead of claiming success.
    @_api
    def chmod(self, path, mode):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def chown(self, path, uid, gid):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def utimens(self, path, times=None):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def mkdir(self, path, mode):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def rmdir(self, path):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def symlink(self, target, source):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def link(self, target, source):
        raise FuseOSError(errno.EOPNOTSUPP)

    @_api
    def setxattr(self, path, name, value, options, position=0):
        raise FuseOSError(errno.EOPNOTSUPP)


def mount_research_image(volume: ResearchVolume, mountpoint: str):
    """Blocking Linux FUSE mount of one OPEN disposable image (explicit opt-in).

    No root, no allow_other, no background daemon. Actual availability of
    /dev/fuse, OS permissions and the optional fusepy dependency is unknown
    until exercised in a disposable Linux VM.
    """
    if os.name != "posix" or not hasattr(os, "getuid"):
        raise RuntimeError("Linux/POSIX FUSE research mount only")
    if FUSE is None:
        raise RuntimeError("Install optional fusepy/libfuse to test this adapter")
    if not isinstance(volume, ResearchVolume):
        raise TypeError("Expected existing KRYPTA research volume")
    folder = os.fspath(mountpoint)
    if os.getuid() == 0:
        raise PermissionError("Never run the KRYPTA research FUSE mount as root")
    if not os.path.isdir(folder) or os.path.islink(folder) or os.listdir(folder):
        raise ValueError("Mountpoint must be an existing, empty, non-symlink directory")
    mount_stat = os.stat(folder)
    if mount_stat.st_uid != os.getuid() or stat.S_IMODE(mount_stat.st_mode) & 0o077:
        raise PermissionError("Mountpoint must be user-owned and private (mode 0700)")
    if os.path.realpath(volume.path).startswith(os.path.realpath(folder) + os.sep):
        raise ValueError("Encrypted image must not reside beneath its mountpoint")
    fs = ResearchFileSystem(volume)
    return FUSE(KryptaFuseOps(fs), folder,
                foreground=True, nothreads=True, allow_other=False,
                default_permissions=True, fsname="KRYPTA-RESEARCH")
