# KRYPTA research virtual-block interface (Windows/Linux)

**Research prototype only; not a mountable filesystem, driver, disk encryptor, boot protector or production key vault.**

## What is implemented

The independent KRYPTA image `research/volume_image.py` provides authenticated 4096-byte sectors with an append-only authenticated metadata commit log and fixed logical size (128 sectors, 512 KiB). Writes are encrypted by HORIZON/0; changes spanning several sectors form one logical commit.

`research/virtual_device.py` provides `open_research_device()` returning a standard Python `io.RawIOBase`-compatible fixed-capacity byte stream. Callers can use `read`, `readinto`, `write`, `tell`, `seek` and standard `io.BufferedRandom`, with bounds checking and no manual invocation of an encryption function.

These calls exercise **application-initiated** transparent encryption of the simulated address space, **not automatic interception of arbitrary filesystem writes or operating-system disk writes**. No real disk is accessed; only new `.kvi` regular files are accepted.

```python
import os
import secrets
import tempfile
from pathlib import Path
from research.virtual_device import open_research_device

with tempfile.TemporaryDirectory(prefix="krypta-research-") as td:
    path = Path(td) / "synthetic.kvi"
    key = secrets.token_bytes(32)  # throwaway random key; never real data
    with open_research_device(path, key, create=True) as dev:
        dev.seek(4093)
        dev.write(b"Test cross-sector write")
        receipt = dev.commit_receipt
    with open_research_device(path, key, expected_sequence=1,
                              expected_receipt=receipt) as dev:
        dev.seek(4093)
        assert dev.read(23) == b"Test cross-sector write"
```

**Don't save the test key for real files; no PIN unlocking/recovery has been built.**

## Current isolation and recovery rules

- A single process holds the exclusive image writer lock. Linux/POSIX uses `flock`; Windows uses an OS byte-range lock on an unused sentinel byte beyond the maximum permitted image size. The lock is released on close/process termination.
- The image reader validates its authenticated metadata and optional external expected commit receipt/sequence **before** it removes incomplete trailing frames. Rejected requests must not modify the image.
- The logged commit receipt is only as trustworthy as the **separate** medium holding the expected value. Storing it with the mutable image cannot prevent snapshot rollback.
- If a write may have committed but an acknowledgement or fsync failed, the handle becomes poisoned; close and reopen to learn the committed state. A physical power failure and firmware/controller defects are still out of scope.
- Built EXE and Linux artifacts have distinct disposable `--self-test` (File Vault) and `--volume-self-test` (KRYPTA image) checks. These must complete in GitHub Actions before treating packaged application binaries as valid research builds.

## Important missing pieces

The virtual stream **does not** register a drive letter, create a disk block device, mount partitions, install kernel/boot code or offer a protected folder for user documents. It cannot encrypt already-existing system volumes. The entire image size is small by design; the image grows with every overwrite and lacks compaction. The experimental HORIZON cipher is not proven superior to AES-256.

Still required: real OS virtual block integration and drivers, provenance/reproducible signed binaries, hardware-bound short-PIN authorization, safe recovery/key rotation, rooted authenticated metadata and trusted monotonic anti-rollback, power-loss and performance tests on disposable machines. For Android, a normal APK can provide only app-owned storage encryption without privileged OS support.

KRYPTA remains a **standalone original encryption engine**, not a BitLocker/LUKS/VeraCrypt wrapper. See [PROJECT_CHARTER.md](PROJECT_CHARTER.md).
