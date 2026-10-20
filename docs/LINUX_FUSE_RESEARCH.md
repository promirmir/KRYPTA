# KRYPTA-FS/0 — Linux FUSE research mount adapter

**Status: opt-in research adapter with one verified disposable Linux kernel FUSE
mount in GitHub Actions (2026-10-20). NOT a production filesystem, full-disk
encryption, boot protection or suitable storage for important files.**

The binding [Project Charter](PROJECT_CHARTER.md) requires an **independent**
KRYPTA encrypted-volume engine. Linux FUSE is solely a Linux kernel **I/O
transport** into that engine. It performs no encryption and is not a wrapper
around BitLocker, LUKS, VeraCrypt or other encrypted-disk products.

## Implemented in source

- \`research/linux_fuse.py\` — FUSE high-level operations bound to the existing
  **KRYPTA-FS/0 → KRYPTA-VIMG/0 → HORIZON/0** authenticated encryption stack.
- \`research/linux_mount.py\` — **explicit opt-in Linux-only** foreground mount
  entry point that never formats an image or opens a device node, and never
  accepts a raw key on the command line or in an environment variable.
- \`tests/test_linux_fuse.py\` — simulated FUSE callbacks against actual
  disposable encrypted images without mounting a real OS filesystem.
- \`tests/test_linux_mount_cli.py\` — required risk acknowledgment,
  anonymous pipe-only key loading, missing-image refusal, and mocked CLI mount.

Source supports:
- Owner-only simulated root directory (0700), existing files (0600);
  creation, full/partial reads and writes, appending, truncation, rename,
  unlink, directory listing, statfs and fsync.
- Regular Linux file-copy patterns using \`open/read/write/close\`, with
  **automatic authenticated encryption for every write reaching the adapter**.
- Per-process synchronous locking, and VIMG's existing cross-process lock.
- Explicit error mapping: an encrypted data-integrity or failed commit
  operation returns EIO, oversized file writes fail with EFBIG, and unsupported
  features fail with EOPNOTSUPP.

**Deliberate deviations from POSIX:** no directories, timestamps, symlinks,
hardlinks, chmod/chown, ACLs, xattrs, sparse extents, cross-user access, live
secure deletion or unlink/rename while a file is open. Unexpected operations
fail, instead of silently claiming to implement them. A file is at most 496
KiB and the entire volume is only 512 KiB logical size; VIMG append-only
encrypted history has a 64-MiB physical image limit.

## How to evaluate ONLY in a disposable Linux VM

**Do not run as root. The mountpoint must be owned by the caller and private (mode 0700).**

Before using FUSE you need Linux with \`/dev/fuse\`, \`fusermount3\` (or
\`fusermount\`), the optional \`fusepy\` Python binding and matching libfuse.
Actual Linux kernel mount, file operations, unmount and authenticated
reopen were exercised on a disposable Ubuntu 22.04 GitHub-hosted runner in
[successful integration CI run 39460873238](https://github.com/promirmir/KRYPTA/actions/runs/39460873238).
The job log explicitly reports **PASS: genuine disposable Linux kernel FUSE
mount/write/read/rename/unlink/unmount/reopen**. This is a **single environment
smoke test**, not verified support for all distributions, power loss, recovery,
full POSIX operations or system disks. Do not test on a host storing unique data.

Example creates an image in a temporary directory, generates an **ephemeral
32-byte random key in RAM**, then starts the foreground mount. When the mount
finishes, the disposable directory is deleted. The key is deliberately not
saved. **Anything written into that test mount may become irrecoverable.**

\`\`\`python
# Run explicitly in a disposable Linux VM after installing dependencies.
import os
import tempfile
from pathlib import Path

from research.volume_image import ResearchVolume
from research.fs_image import ResearchFileSystem
from research.linux_fuse import mount_research_image

with tempfile.TemporaryDirectory(prefix="krypta-only-test-") as directory:
    root = Path(directory)
    image = root / "disposable.kvi"
    mountpoint = root / "empty-mount"
    mountpoint.mkdir(mode=0o700)
    key = os.urandom(32)  # DEMONSTRATION ONLY — no recovery copy
    with ResearchVolume(image, key, create=True) as volume:
        ResearchFileSystem.format(volume)
        mount_research_image(volume, str(mountpoint))  # blocking foreground FUSE
        # In a separate VM terminal, unmount using fusermount3 -u <mountpoint>
\`\`\`

Alternatively \`python -m research.linux_mount --image EXISTING.kvi
--mountpoint EMPTY_DIRECTORY --key-fd FD --accept-research-risk\` accepts only
an existing test image. \`FD\` must be an **anonymous pipe/socket** containing
32 opaque bytes; interactive terminal, regular file and CLI hexadecimal keys
are refused. No automatic image creation, auto-start or privileged mounting.

## Automated disposable kernel-mount gate

`.github/workflows/fuse-integration.yml` now runs a **separate** hosted-Linux
FUSE integration experiment. `tools/test_kernel_fuse_integration.py` creates
only a new `.kvi` test image, generates a RAM-only random key, attempts a
foreground kernel mount via `/dev/fuse`, exercises ordinary file write/read,
rename, overwrite, unlink, unmount and authentication on reopen. The original
KRYPTA-HORIZON/VIMG/FS engine is the encryption backend.

The test distinguishes outcomes:
- **PASS** in the test output: actual Linux kernel FUSE mount/unmount exercised.
  First confirmed PASS: [GitHub Actions run 39460873238](https://github.com/promirmir/KRYPTA/actions/runs/39460873238), Ubuntu 22.04.
- **SKIPPED (exit 77)**: runner lacks `/dev/fuse`, usable fusepy/libfuse or user
  mount support; this is NOT evidence of an actual mount.
- **FAIL**: integration failed and needs triage before claims of compatibility.

The protected OS partition, local persistent drives, reboot configuration,
BitLocker and LUKS are never used in this gate. Success would validate only
the **research flat filesystem** on that runner, not production full-disk
encryption, boot protection, long-duration resilience or Windows support.

### FUSE adapter security regression checks

`tests/test_fuse_boundary_security.py` requires file-descriptor identity
to match the requested file path on all read/write/flush/release calls,
rejects an exclusive-create on an existing file (`O_CREAT|O_EXCL`) and
rejects unsupported special descriptor modes. These tests execute on
Windows and Linux without a kernel mount.

## Threat model and next gates

- FUSE does not hide plaintext from the **currently authenticated user
  running the mount**, root, malware controlling that user, memory dumps or
  compromised kernel/driver code.
- Research image metadata uses authenticated commits but **does not contain
  independently trusted anti-rollback state**. A copy/restore of an older valid
  image can be accepted unless an external receipt is verified.
- There is no robust key recovery, TPM-bound short-PIN unlock, quantitative
  attack-resistance claim, proven crash durability or independently reviewed
  encryption primitive. HORIZON/0 is research, not proven stronger than AES.
- This adapter neither intercepts other disks nor protects Linux root or
  system startup. Windows support remains a separate WinFsp/driver adapter.
- Actual kernel FUSE integration should be exercised **only after creating
  disposable VM snapshots and confirming test-data recovery/unmount**.

Roadmap next: verify real disposable VM mounting; introduce scalable
hierarchical catalogue, POSIX semantics, authenticated copy-on-write index,
mount recovery, bounded per-write costs, mount-point isolation and complete
error injection, then separately develop Windows and system-boot integration.
