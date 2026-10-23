"""KRYPTA-MOBILE/2 desktop recovery: pinned interoperable fixture + fail-closed tests."""
import json
from pathlib import Path

import pytest

from krypta.core import CryptoError
from krypta.mobile_recovery import verify_mobile_archive, recover_mobile_file

VECTOR = Path(__file__).parent / "vectors" / "mobile_v2_recovery.json"


def sample(tmp_path):
    v = json.loads(VECTOR.read_text("utf-8"))
    source = tmp_path / "android.km2"
    source.write_bytes(bytes.fromhex(v["ciphertext_hex"]))
    key = tmp_path / "independent-recovery.krc"
    key.write_bytes(bytes.fromhex(v["recovery_hex"]))
    return source, key, bytes.fromhex(v["plaintext_hex"])


def test_offline_android_recovery_vector(tmp_path):
    source, key, plaintext = sample(tmp_path)
    before = source.read_bytes()
    report = verify_mobile_archive(source, key)
    assert report["format"] == "KRYPTA-MOBILE/2"
    assert report["authenticated"] and not report["plaintext_written"]
    assert report["plaintext_bytes"] == len(plaintext)
    assert not list(tmp_path.glob("*.tmp"))
    restored = tmp_path / "restored.bin"
    recovered = recover_mobile_file(source, restored, key)
    assert recovered["authenticated"]
    assert restored.read_bytes() == plaintext
    assert source.read_bytes() == before


@pytest.mark.parametrize("change", ["wrong_key", "corrupt_header", "corrupt_data",
                                     "bad_eof", "truncated", "trailing", "v1_magic"])
def test_mobile_tampering_never_creates_plaintext(tmp_path, change):
    source, key, plaintext = sample(tmp_path)
    raw = bytearray(source.read_bytes())
    if change == "wrong_key":
        key.write_bytes(bytes([raw[0]]) * 32)
    elif change == "corrupt_header":
        raw[52] ^= 1
    elif change == "corrupt_data":
        raw[-42] ^= 1
    elif change == "bad_eof":
        raw[-1] ^= 1
    elif change == "truncated":
        raw = raw[:-2]
    elif change == "trailing":
        raw += b"!"
    elif change == "v1_magic":
        raw[:len(b"KRYPTA-MOBILE/1\n")] = b"KRYPTA-MOBILE/1\n"
    source.write_bytes(raw)
    dest = tmp_path / "should-not-exist.bin"
    with pytest.raises(CryptoError):
        verify_mobile_archive(source, key)
    with pytest.raises(CryptoError):
        recover_mobile_file(source, dest, key)
    assert not dest.exists()


def test_recovery_requires_exact_secret_and_no_overwrite(tmp_path):
    source, key, plain = sample(tmp_path)
    key.write_bytes(b"x" * 33)
    with pytest.raises(CryptoError):
        verify_mobile_archive(source, key)
    key.write_bytes(bytes(range(32)))
    target = tmp_path / "valuable.bin"
    target.write_bytes(b"preserve original")
    with pytest.raises(FileExistsError):
        recover_mobile_file(source, target, key)
    assert target.read_bytes() == b"preserve original"


def test_recovery_refuses_source_or_key_symlink(tmp_path):
    source, key, plain = sample(tmp_path)
    alias = tmp_path / "link.km2"
    try:
        alias.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    with pytest.raises((ValueError, CryptoError)):
        verify_mobile_archive(alias, key)
    key_alias = tmp_path / "link.key"
    key_alias.symlink_to(key)
    with pytest.raises((ValueError, CryptoError)):
        verify_mobile_archive(source, key_alias)
