# KRYPTA — Live-sector migration experiment, research checkpoint

**RESEARCH ONLY. NOT A production compactor, recovery tool, secure delete or safe protector of real data.**

## Implemented

`ResearchVolume.export_compacted_copy(destination)` creates a **separate** fresh `.kvi` image with `O_CREAT | O_EXCL` (no overwrite). It authenticates and decrypts all currently allocated source sectors, re-encrypts them in a new image with a new image ID and independently generated per-record salts/nonces, verifies the new plaintext sector values, and returns an explicit migration report:

- Source commit `source_sequence` and `source_receipt`.
- Destination `new_image_id`, `new_sequence` and `new_receipt`.
- Number of copied live sectors.

The original source file is **never truncated, replaced, unlinked or overwritten**. Both may coexist for manual testing; the exclusive single-writer lock on the original is held throughout. If destination assembly fails after its creation, KRYPTA attempts to remove only that exact newly created inode and never deletes another file swapped into the path.

`ResearchFileSystem.verify_all()` performs a separate **read-only** pass over the encrypted catalogue and every currently allocated file, including authenticated sectors and stored file SHA-256 values. Returns aggregate verified file/byte counts and source commit metadata without returning file contents.

### Demonstration — ONLY synthetic data, no real disk

```python
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from research.volume_image import ResearchVolume
from research.fs_image import ResearchFileSystem

with TemporaryDirectory(prefix="krypta-lab-") as td:
    root = Path(td)
    secret = os.urandom(32)                 # disposable TEST key
    with ResearchVolume(root / "source.kvi", secret, create=True) as volume:
        fs = ResearchFileSystem.format(volume)
        fs.write_file("example.txt", b"fake synthetic data")
        for n in range(6):
            fs.write_file("example.txt", f"revision {n}".encode(), replace=True)
        verified = fs.verify_all()
        report = volume.export_compacted_copy(root / "new.kvi")
        assert report["source_receipt"] == verified["receipt"]
    with ResearchVolume(root / "new.kvi", secret,
                        expected_receipt=report["new_receipt"]) as migrated:
        assert ResearchFileSystem(migrated).read_file("example.txt") == b"revision 5"
```

## Security and availability limits

1. **Not an in-place compaction** and not background garbage collection. It is a *copy into a new image*, which may be smaller because old encrypted sector versions are not replicated.
2. Existing committed snapshots are **not cryptographically erased**. An adversary retaining the original image still possesses those ciphertexts; after compromise of the shared encryption key they may be decrypted. Do not advertise deletion/forward secrecy.
3. New destination has a **different image ID**, new `sequence` typically 1 and **different expected receipt**. The original trusted anti-rollback receipt CANNOT simply be reused. Replacing an actively mounted image with the new image without first designing a trusted two-phase migration of the receipt and recovery metadata is unsafe. No external anchor store is supplied.
4. Same random 256-bit test key is reused across both images for this *research* migration, separated by new image identity and distinct per-record key derivation. No new hardware-bound access control or device recovery is provided.
5. `fsync` and successful unit tests do not prove correctness under power loss, disk firmware bugs, network FS, untrusted storage, an administrator with live access, or physical attacks.
6. `ResearchVolume` still supports at most **128 logical sectors × 4096 bytes (512 KiB)** and limits one `.kvi` image to 64 MiB. This experiment does **not** increase logical capacity, implement a real block device or provide Windows/Linux file-system mounting.
7. Failure cleanup is best-effort if the containing filesystem refuses unlink, or a power cut occurs. Do not assume any storage secure erase or portable crypto recovery.

## Evidence / Next architecture gate

Tests in `tests/test_compacted_migration.py` verify that original file bytes remain unchanged, a compact image authenticates and reopens with the new receipt, ciphertext differs, file contents match, tampered source blocks are rejected, failure cleanup does not delete existing files, and a failed genesis commit does not leave a new test image.

Next: authenticated scalable snapshot index, multi-phase trusted receipt migration, safe crash interruption across 2 images, verified resource limits, portable recovery, and a mountable OS volume adapter in isolated VMs — **not** a BitLocker or LUKS wrapper. 
