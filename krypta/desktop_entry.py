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


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return run_self_test()
    if len(sys.argv) != 1:
        return 2
    from krypta.gui import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
