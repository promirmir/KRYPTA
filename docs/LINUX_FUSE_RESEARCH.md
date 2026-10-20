# KRYPTA-FS/0 — Linux FUSE research mount adapter

**Status: opt-in research adapter, NOT a tested real mount, production filesystem,
full-disk encryption, boot protection or suitable storage for important files.**

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

Before using FUSE you need Linux with \`/dev/fuse\`, \`fusermount3\` (or
\`fusermount\`), the optional \`fusepy\` Python binding and matching libfuse.
Actual mount startup, unmount recovery, kernel error propagation and host
compatibility **have not been exercised** by GitHub Actions. Do not test on a
machine storing unique user data.

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
    mountpoint.mkdir()
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
