# Pinned rescue output — PR #25, issue #24

Implementation under review; this is not a production-security certification.
No release or stable-1.0 claim follows from these tests. An independent code
review and hardware recovery evidence remain required.

## Trust boundary

All encrypted contents are authenticated before creating output. Recovery
writes only to a newly created private directory. Recovered data is plaintext.
The OS, local filesystem implementation, administrator/root and current account
are trusted. A malicious process with the same account, kernel access, backup
privileges or administrator privileges is outside this boundary. This does not
isolate plaintext from such processes or erase memory/disk remnants.

Refuse output under an untrusted owner or a hierarchy whose ACL/mode permits
untrusted replacement, permission changes or directory redirection. Failures
do not fall back to the old path-based writer. An existing directory, symlink,
junction or collision is never overwritten. Do not weaken permissions to make
a refused location work: select a private local destination instead.

## Linux

Walk from `/` using `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, one component at a time,
keeping descriptors open. Each component must belong to root or the effective
UID and must not be group/other writable. Root-owned sticky ancestors (such as
`/tmp`) are permitted: sticky deletion rules plus trusted child ownership
protect the next component. ACL write grants are bounded by the mode mask.
Supported filesystem types are ext2/3/4, XFS, Btrfs, tmpfs and OverlayFS; other
types, including NFS/SMB/FUSE, fail closed. This list expresses required local
semantics, not a claim that each type has received hardware power-loss testing.

Create the output directory as 0700 relative to the pinned parent. The private
parent/sticky rules protect the mkdir/open interval from other users. Create
each output and the final manifest with `O_EXCL|O_NOFOLLOW` relative to the
output descriptor, mode 0600. Keep file descriptors open, write/fsync/read back
through the SAME descriptor, verify regular-file type, identity, length, digest
and single link. No plaintext path is reopened for verification.

Directory identity checks diagnose renames; they are not the mechanism that
prevents redirected writes. Cleanup uses the original dirfd, checks identity
and link count, and preserves unfamiliar entries. The stat/unlink cleanup pair
relies on private-directory permissions and the trusted-current-UID boundary;
Linux has no general unlink-by-open-file-descriptor primitive. It is not a
promise of protection against concurrent malicious code running as the owner.

## Windows

Only ordinary local fixed NTFS drive paths are supported. UNC, device paths,
alternate data streams, removable drives, unsupported ACL ACE types and other
filesystems fail closed. `pywin32` is required and included in Windows builds.

Open the volume root, then each component with native `NtCreateFile` relative
to its pinned parent and `FILE_OPEN_REPARSE_POINT`. Check directory attributes
and reject **all** reparse points, including junctions. Keep ancestors open
without sharing write/delete. Validate owner and DACL through each handle.
Trusted principals are the process account, SYSTEM, Administrators and (for
existing system ancestry) TrustedInstaller. OWNER RIGHTS applies only after
the actual owner is validated. Inherit-only ACEs do not apply to the current
directory; ambiguous ACE forms are refused rather than approximated.

Create the new directory with `FILE_CREATE`, obtaining the handle atomically.
Apply a protected DACL at creation granting full access only to the current
account, SYSTEM and Administrators. Create files with the same private DACL
and `FILE_CREATE`, relative to the pinned output handle, with no sharing.
The CRT descriptor owns the native file handle; write, flush and verify through
that descriptor, keeping it open until completion. Cleanup marks owned handles
with `FileDispositionInfo`; it never finds deletion targets by path. Sharing
locks prevent concurrent rename, replacement and writes while handles remain
open. Normal access resumes once recovery finishes.

API contracts:
- [NtCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile)
- [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)

## Completion, failure and verification

The manifest is created last and verified through its creation handle as well.
Linux syncs output and parent directory entries before/after the manifest.
Windows flushes each file but offers no equivalent directory-fsync guarantee
here. A crash/power loss can leave partial plaintext, an incomplete manifest or
inconsistent directory persistence. A manifest is unsigned and is not a
power-loss certificate. Independently verify every listed file hash and retain
the trusted external receipt separately.

Ordinary exceptions clean only known owned output. Cleanup errors or unknown
identities can leave partial data: inspect the destination after failure.
Neither backend recursively deletes a directory or touches encrypted inputs.

`tests/test_rescue_output.py` exercises native handles, junctions, ACL refusal,
directory replacement at the Linux check/create boundary, exclusive collisions,
hardlinks, descriptor readback, partial write failure and cleanup identity.
`tests/test_paged_rescue.py` verifies authenticated all-file recovery and manifest
ordering. The PR workflow runs the full suite on Windows/Linux Python 3.11/3.13,
then builds and executes real standalone rescue EXE/ELF self-tests on each.
Windows CI uses private profile ancestry rather than shared runner scratch
folders. Test success is scoped to that exact commit and those environments.

Remaining release gates: independent native/ACL code review; separate-machine
restore; physical power-loss and device-failure tests; broader filesystem and
platform qualification. Issue #24 stays open until its review gate is met.
