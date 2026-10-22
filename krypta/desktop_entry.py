"""GUI entry point for packaged Windows/Linux KRYPTA research builds.

``--self-test`` checks the *packaged executable* without touching user data.
It is not a cryptographic audit or full-disk encryption test.
"""
import sys
import tempfile
from pathlib import Path


def run_self_test() -> int:
    from krypta.core import decrypt_file, encrypt_file, file_info, generate_keyfile
    with tempfile.TemporaryDirectory(prefix="krypta-packaged-smoke-") as directory:
        root = Path(directory)
        original = root / "sample.bin"
        original.write_bytes(b"KRYPTA bundle smoke test\x00\x01" * 19)
        keyfile = root / "local-test-keyfile.bin"
        generate_keyfile(keyfile)
        encrypted = root / "sample.kry"
        restored = root / "restored.bin"
        encrypt_file(original, encrypted, "1234", keyfile)
        info = file_info(encrypted)
        if info.get("algorithm") != "AES-256-GCM-stream-v1" or not info.get("keyfile_required"):
            raise RuntimeError("Unexpected encrypted-file header")
        decrypt_file(encrypted, restored, "1234", keyfile)
        if restored.read_bytes() != original.read_bytes():
            raise RuntimeError("Packaged-file round trip failed")
    return 0


def run_volume_self_test() -> int:
    """Check the *packaged* independent VIMG test engine, not any real disk."""
    import secrets
    from research.virtual_device import open_research_device
    from research.volume_image import BLOCK_BYTES

    with tempfile.TemporaryDirectory(prefix="krypta-vimg-package-test-") as directory:
        image = Path(directory) / "disposable.kvi"
        key = secrets.token_bytes(32)
        offset = BLOCK_BYTES - 3
        sample = b"KRYPTA-INDEPENDENT-BLOCK-TEST" * 10
        with open_research_device(image, key, create=True) as device:
            device.seek(offset)
            if device.write(sample) != len(sample):
                raise RuntimeError("Virtual volume did not complete the test write")
            device.seek(offset)
            if device.read(len(sample)) != sample:
                raise RuntimeError("Virtual volume read/write mismatch")
            expected_receipt = device.commit_receipt
        with open_research_device(
                image, key, expected_sequence=1, expected_receipt=expected_receipt) as device:
            device.seek(offset)
            if device.read(len(sample)) != sample:
                raise RuntimeError("Packaged VIMG restore mismatch")
    return 0


def run_filesystem_self_test() -> int:
    """Exercise packaged KRYPTA-FS + authenticated copy using disposable data."""
    import secrets
    from research.fs_image import ResearchFileSystem
    from research.volume_image import ResearchVolume
    with tempfile.TemporaryDirectory(prefix="krypta-fs-package-test-") as directory:
        root = Path(directory)
        original = root / "synthetic-source.kvi"
        migrated = root / "synthetic-compacted.kvi"
        key = secrets.token_bytes(32)
        with ResearchVolume(original, key, create=True) as volume:
            filesystem = ResearchFileSystem.format(volume)
            for i in range(6):
                filesystem.write_file("test-data.txt", f"synthetic revision {i}".encode(),
                                      replace=i > 0)
            filesystem.write_file("Zażółć_你好.txt", b"another test")
            checked = filesystem.verify_all()
            if checked["files_verified"] != 2:
                raise RuntimeError("Packaged filesystem integrity count mismatch")
            migration = volume.export_compacted_copy(migrated)
            if migration["source_receipt"] != filesystem.receipt:
                raise RuntimeError("Compacted copy source receipt mismatch")
        with ResearchVolume(migrated, key, expected_receipt=migration["new_receipt"]) as fresh:
            restored = ResearchFileSystem(fresh)
            if restored.read_file("test-data.txt") != b"synthetic revision 5":
                raise RuntimeError("Packaged encrypted filesystem restore mismatch")
            if restored.read_file("Zażółć_你好.txt") != b"another test":
                raise RuntimeError("Packaged multilingual filename mismatch")
            if restored.verify_all()["files_verified"] != 2:
                raise RuntimeError("Packaged new image integrity sweep failed")
    return 0

def run_fuse_adapter_self_test() -> int:
    """Exercise *packaged* original KRYPTA-FS via FUSE-style callbacks.

    No libfuse device and NO kernel mount are accessed. All files, keys and
    images are synthetic and disappear with the private temporary directory.
    """
    import os
    import errno
    import secrets
    from research.fs_image import ResearchFileSystem
    from research.linux_fuse import FuseOSError, KryptaFuseOps
    from research.volume_image import ResearchVolume

    with tempfile.TemporaryDirectory(prefix="krypta-fuse-package-test-") as directory:
        root = Path(directory)
        path = root / "disposable.kvi"
        key = secrets.token_bytes(32)
        with ResearchVolume(path, key, create=True) as volume:
            filesystem = ResearchFileSystem.format(volume)
            adapter = KryptaFuseOps(filesystem)
            handle = adapter.create("/research.txt", 0o600)
            test_payload = b"KRYPTA-OWN-TRANSPARENT-FILE-WRITE" * 4
            if adapter.write("/research.txt", test_payload, 0, handle) != len(test_payload):
                raise RuntimeError("FUSE adapter failed to write the research file")
            if adapter.read("/research.txt", len(test_payload), 0, handle) != test_payload:
                raise RuntimeError("FUSE adapter failed to read the research file")
            if test_payload in path.read_bytes() or b"research.txt" in path.read_bytes():
                raise RuntimeError("Plaintext present in encrypted research image")
            try:
                adapter.read("/a-different-file.txt", 1, 0, handle)
            except FuseOSError as e:
                if e.errno != errno.EBADF:
                    raise RuntimeError("FUSE file identity check returned wrong error") from e
            else:
                raise RuntimeError("FUSE adapter accepted a mismatched handle and filename")
            if adapter.release("/research.txt", handle) != 0:
                raise RuntimeError("FUSE adapter failed to release the test handle")
            receipt = filesystem.receipt
        with ResearchVolume(path, key, expected_receipt=receipt) as verified:
            fs = ResearchFileSystem(verified)
            if fs.read_file("research.txt") != test_payload:
                raise RuntimeError("FUSE adapter encrypted-file recovery mismatch")
    return 0


def run_paged_volume_lab_self_test() -> int:
    """Packaged PFS2 create/import/verify/export/rekey with disposable data.

    This exercises the same GUI service layer, not just a mocked CLI.
    Nothing is mounted, and physical/system disks are never enumerated.
    """
    from krypta.volume_lab import (
        create_image, verify_image, import_file, export_file, rotate_image,
        review_uncertain_image, seal_existing_trusted_receipt,
        verify_sealed_receipt_image,
    )
    from research.paged_volume import PagedVolumeError
    with tempfile.TemporaryDirectory(prefix="krypta-pfs2-gui-smoke-") as directory:
        root = Path(directory)
        src = root / "synthetic-input.bin"
        sample = b"KRYPTA DESKTOP PVKEY/1 PFS/2" * 93
        src.write_bytes(sample)
        image = root / "synthetic.kpv"
        envelope = root / "synthetic.pvkey"
        recovery = root / "synthetic.recovery"
        password = "Disposable development passphrase 2026!"
        created = create_image(image, envelope, recovery, password, password)
        if verify_image(
            image, envelope, created["receipt"], password=password
        )["files_verified"] != 0:
            raise RuntimeError("New packaged PFS2 file list was not empty")
        # Test the same pinned-receipt service that the packaged GUI now calls.
        # A valid image does not automatically become a trusted future state.
        pin_dir = root / "independent-test-pin-dir"
        pin_dir.mkdir(mode=0o700)
        pin = pin_dir / "trusted-baseline.kpin"
        sealed = seal_existing_trusted_receipt(
            image, envelope, created["receipt"], pin, password=password
        )
        if (sealed["trust_promoted"] is not False or not pin.is_file()
                or len(sealed["seal_sha256"]) != 64):
            raise RuntimeError("Packaged sealed receipt pin enrollment failed")
        checked_pin = verify_sealed_receipt_image(
            image, envelope, pin, sealed["seal_sha256"], recovery=recovery
        )
        if (checked_pin["status"] != "SEALED_PIN_MATCH"
                or checked_pin["trust_promoted"] is not False
                or checked_pin["files_verified"] != 0):
            raise RuntimeError("Packaged sealed pin read-only verification failed")
        addition = import_file(
            image, envelope, created["receipt"], src, recovery=recovery
        )
        try:
            verify_sealed_receipt_image(
                image, envelope, pin, sealed["seal_sha256"], password=password
            )
        except PagedVolumeError:
            pass  # Changed state must NEVER silently advance the pinned receipt.
        else:
            raise RuntimeError("Packaged app accepted unpinned later image state")
        if addition["receipt"] == created["receipt"]:
            raise RuntimeError("Encrypted import failed to advance external receipt")
        image_before_review = image.read_bytes()
        review = review_uncertain_image(
            image, envelope, created["receipt"], recovery=recovery
        )
        if (review["status"] != "DESCENDANT_FOUND_MANUAL_REVIEW_REQUIRED"
                or review["commits_since_prior"] != 1
                or review["observed_receipt_UNTRUSTED"] != addition["receipt"]
                or "receipt" in review
                or review["review_only"] is not True
                or image.read_bytes() != image_before_review):
            raise RuntimeError("Packaged GUI forensic receipt review did not fail closed")
        exact = review_uncertain_image(
            image, envelope, addition["receipt"], password=password
        )
        if (exact["status"] != "CURRENT_RECEIPT_MATCHES_PRIOR"
                or exact["review_only"] is not True
                or "receipt" in exact
                or image.read_bytes() != image_before_review):
            raise RuntimeError("Packaged forensic review of current image failed")
        plaintext = root / "exported.bin"
        export_file(image, envelope, addition["receipt"], src.name, plaintext,
                    password=password)
        if plaintext.read_bytes() != sample:
            raise RuntimeError("Packaged PFS2 authenticated export mismatch")
        moved = rotate_image(
            image, envelope, addition["receipt"],
            root / "rotated.kpv", root / "rotated.pvkey",
            root / "rotated.recovery",
            "Another entirely different long passphrase 2026!",
            "Another entirely different long passphrase 2026!",
            old_recovery=recovery,
        )
        if moved["image_id"] == created["image_id"]:
            raise RuntimeError("Packaged rotation reused original image identity")
        if verify_image(
            root / "rotated.kpv", root / "rotated.pvkey", moved["receipt"],
            recovery=root / "rotated.recovery"
        )["files_verified"] != 1:
            raise RuntimeError("Packaged re-encrypted image validation failed")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return run_self_test()
    if len(sys.argv) == 2 and sys.argv[1] == "--volume-self-test":
        return run_volume_self_test()
    if len(sys.argv) == 2 and sys.argv[1] == "--filesystem-self-test":
        return run_filesystem_self_test()
    if len(sys.argv) == 2 and sys.argv[1] == "--fuse-self-test":
        return run_fuse_adapter_self_test()
    if len(sys.argv) == 2 and sys.argv[1] == "--paged-volume-self-test":
        return run_paged_volume_lab_self_test()
    if len(sys.argv) != 1:
        return 2
    from krypta.gui import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
