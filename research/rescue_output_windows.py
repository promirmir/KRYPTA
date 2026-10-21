"""Windows local NTFS backend. Native relative opens, private DACL, pinned handles.

Unsupported filesystems, reparse points and ambiguous ACLs fail closed.
Native API contracts and threat-model limits: RESCUE_OUTPUT_SECURITY.md.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import msvcrt
import os
from pathlib import Path
import sys

import win32api
import win32con
import win32file
import win32security
import win32timezone  # noqa: F401 - PyTime conversion imports this dynamically in frozen builds.

from .rescue_output import RescueError, _leaf, _write_verify


class UNICODE_STRING(C.Structure):
    _fields_ = [("Length", W.USHORT), ("MaximumLength", W.USHORT),
                ("Buffer", W.LPWSTR)]


class OBJECT_ATTRIBUTES(C.Structure):
    _fields_ = [("Length", W.ULONG), ("RootDirectory", W.HANDLE),
                ("ObjectName", C.POINTER(UNICODE_STRING)),
                ("Attributes", W.ULONG), ("SecurityDescriptor", W.LPVOID),
                ("SecurityQualityOfService", W.LPVOID)]


class IO_STATUS_BLOCK(C.Structure):
    _fields_ = [("Status", C.c_void_p), ("Information", C.c_size_t)]


_ntdll = C.WinDLL("ntdll", use_last_error=True)
_kernel = C.WinDLL("kernel32", use_last_error=True)
_ntcreate = _ntdll.NtCreateFile
_ntcreate.argtypes = [C.POINTER(W.HANDLE), W.DWORD, C.POINTER(OBJECT_ATTRIBUTES),
                     C.POINTER(IO_STATUS_BLOCK), C.c_void_p, W.ULONG, W.ULONG,
                     W.ULONG, W.ULONG, C.c_void_p, W.ULONG]
_ntcreate.restype = C.c_long
_ntdll.RtlNtStatusToDosError.argtypes = [C.c_long]
_ntdll.RtlNtStatusToDosError.restype = W.ULONG
_kernel.CloseHandle.argtypes = [W.HANDLE]
_kernel.CloseHandle.restype = W.BOOL
_kernel.SetFileInformationByHandle.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD]
_kernel.SetFileInformationByHandle.restype = W.BOOL


def _relative_open(parent, name, *, create=False, directory=True, sd=None):
    _leaf(name)
    buffer = C.create_unicode_buffer(name)
    length = len(name.encode("utf-16-le"))
    if length > 65532:
        raise RescueError("Recovery filename is too long")
    text = UNICODE_STRING(length, length + 2, C.cast(buffer, W.LPWSTR))
    descriptor = C.create_string_buffer(bytes(sd)) if sd is not None else None
    attrs = OBJECT_ATTRIBUTES(C.sizeof(OBJECT_ATTRIBUTES), int(parent),
                              C.pointer(text), 0x40,  # OBJ_CASE_INSENSITIVE
                              C.cast(descriptor, W.LPVOID) if descriptor else None, None)
    iosb, handle = IO_STATUS_BLOCK(), W.HANDLE()
    # READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE on existing ancestry.
    access = 0x00120080
    if create:
        access = 0xC0110080  # GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE | attributes
        access |= 0x00020000  # READ_CONTROL for ACL validation
    options = 0x00200000 | 0x00000020  # OPEN_REPARSE_POINT | SYNCHRONOUS_IO_NONALERT
    options |= 0x00000001 if directory else 0x00000040
    status = _ntcreate(C.byref(handle), access, C.byref(attrs), C.byref(iosb),
                       None, 0x80, 1 if directory else 0,
                       2 if create else 1, options, None, 0)  # FILE_CREATE / FILE_OPEN
    if status < 0:
        raise C.WinError(_ntdll.RtlNtStatusToDosError(status))
    return handle.value


def _delete_handle(handle):
    delete = W.BOOL(True)
    if not _kernel.SetFileInformationByHandle(handle, 4, C.byref(delete), C.sizeof(delete)):
        raise C.WinError(C.get_last_error())


def _trusted_sids():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()
    current = win32security.ConvertSidToStringSid(sid)
    return current, {
        current, "S-1-5-18", "S-1-5-32-544",
        # Windows Modules Installer, owner of protected system directories.
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }


def _check_directory(handle, trusted):
    info = win32file.GetFileInformationByHandle(handle)
    if not info[0] & 0x10 or info[0] & 0x400:
        raise RescueError("Reparse points and non-directory recovery ancestors are forbidden")
    sd = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT,
                                      win32security.OWNER_SECURITY_INFORMATION
                                      | win32security.DACL_SECURITY_INFORMATION)
    if win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()) not in trusted:
        raise RescueError("Untrusted recovery directory owner")
    acl = sd.GetSecurityDescriptorDacl()
    if acl is None:
        raise RescueError("Unrestricted recovery directory ACL is forbidden")
    # Rights that can redirect, replace children or change this directory's
    # trust. Creating a new sibling alone is harmless: FILE_CREATE is exclusive.
    dangerous = 0x10000000 | 0x40000000 | 0x000C0000 | 0x00010000 | 0x40 | 0x100 | 0x10
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        kind, flags = ace[0]
        if flags & 0x08:  # INHERIT_ONLY_ACE does not apply to this directory.
            continue
        if kind == win32security.ACCESS_DENIED_ACE_TYPE:
            continue
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise RescueError("Unsupported recovery directory ACL entry")
        sid = win32security.ConvertSidToStringSid(ace[2])
        # OWNER RIGHTS refers to the owner validated above (Python 3.13's
        # private mkdir DACL uses this SID).
        if sid not in trusted and sid != "S-1-3-4" and ace[1] & dangerous:
            raise RescueError("Shared writable recovery hierarchy is forbidden")
    return info


class WindowsOutput:
    def __init__(self, path):
        raw = str(path)
        self.path = Path(path).absolute()
        if (raw.startswith(("\\\\", "//")) or len(self.path.drive) != 2
                or ":" in str(self.path)[2:]):
            raise RescueError("Recovery requires an ordinary local NTFS drive path")
        _leaf(self.path.name)
        self.chain, self.files = [], []
        self.handle = None

    def __enter__(self):
        try:
            root = self.path.anchor
            if (win32file.GetDriveType(root) != win32con.DRIVE_FIXED
                    or win32api.GetVolumeInformation(root)[4] != "NTFS"):
                raise RescueError("Secure Windows recovery requires a local fixed NTFS drive")
            current, self.trusted = _trusted_sids()
            # A protected DACL is installed AT creation, never chmod afterwards.
            self.sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                f"D:P(A;OICI;FA;;;{current})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1)
            handle = win32file.CreateFile(root, 0x00120080, win32con.FILE_SHARE_READ,
                                         None, win32con.OPEN_EXISTING,
                                         0x02000000 | 0x00200000, None)
            self.chain.append(handle)
            _check_directory(handle, self.trusted)
            for name in self.path.parent.parts[1:]:
                handle = _relative_open(self.chain[-1], name)
                self.chain.append(handle)
                _check_directory(handle, self.trusted)
            # The newly created directory and its handle are one operation.
            self.handle = _relative_open(self.chain[-1], self.path.name,
                                         create=True, sd=self.sd)
            self.check()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def check(self):
        for handle in self.chain:
            _check_directory(handle, self.trusted)
        _check_directory(self.handle, self.trusted)

    def write(self, name, data):
        self.check()
        handle = _relative_open(self.handle, name, create=True, directory=False, sd=self.sd)
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            try:
                _delete_handle(handle)
            finally:
                _kernel.CloseHandle(handle)
            raise
        self.files.append(fd)
        _write_verify(fd, data)
        self.check()

    def sync(self):
        self.check()
        # File data is flushed by _write_verify. Windows has no equivalent
        # supported directory fsync guarantee; see documented durability scope.

    def __exit__(self, exc_type, exc, tb):
        for fd in reversed(self.files):
            if exc_type is not None:
                try:
                    _delete_handle(msvcrt.get_osfhandle(fd))
                except OSError:
                    pass
            os.close(fd)
        if self.handle is not None:
            if exc_type is not None:
                try:
                    _delete_handle(self.handle)
                except OSError:
                    pass
            _kernel.CloseHandle(self.handle)
        for handle in reversed(self.chain):
            if isinstance(handle, int):
                _kernel.CloseHandle(handle)
            else:
                handle.Close()
