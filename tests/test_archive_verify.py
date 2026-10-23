"""Authenticated archive verification without plaintext output."""
import hashlib

import pytest

from krypta.core import CryptoError, encrypt_file, generate_keyfile, verify_file

PASSWORD = "A long test-only offline passphrase!"


def test_verify_multichunk_with_external_key_without_plaintext_output(tmp_path):
    original = tmp_path / "sample.bin"
    data = bytes(range(256)) * 8200
    original.write_bytes(data)
    keyfile = tmp_path / "key.secret"
    generate_keyfile(keyfile)
    encrypted = tmp_path / "backup.krypta"
    encrypt_file(original, encrypted, PASSWORD, keyfile)
    before = set(tmp_path.iterdir())
    checked = verify_file(encrypted, PASSWORD, keyfile)
    assert checked == {
        "authenticated": True,
        "plaintext_bytes": len(data),
        "plaintext_sha256": hashlib.sha256(data).hexdigest(),
        "plaintext_written": False,
    }
    assert set(tmp_path.iterdir()) == before


def test_verify_rejects_wrong_password_and_keyfile_without_output(tmp_path):
    original = tmp_path / "source"
    original.write_bytes(b"private" * 10000)
    key = tmp_path / "secret"
    other = tmp_path / "different"
    generate_keyfile(key)
    generate_keyfile(other)
    encrypted = tmp_path / "encrypted.krypta"
    encrypt_file(original, encrypted, PASSWORD, key)
    before = set(tmp_path.iterdir())
    with pytest.raises(CryptoError):
        verify_file(encrypted, "incorrect passphrase", key)
    with pytest.raises(CryptoError):
        verify_file(encrypted, PASSWORD, other)
    with pytest.raises(CryptoError):
        verify_file(encrypted, PASSWORD, None)
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("damage", ["flip_chunk", "truncate", "append"])
def test_verify_rejects_archive_corruption(tmp_path, damage):
    original = tmp_path / "source"
    original.write_bytes(b"authenticated block" * 2000)
    encrypted = tmp_path / "archive.krypta"
    encrypt_file(original, encrypted, PASSWORD)
    damaged = tmp_path / "damaged.krypta"
    raw = bytearray(encrypted.read_bytes())
    if damage == "flip_chunk":
        raw[-40] ^= 0x80
    elif damage == "truncate":
        raw = raw[:-8]
    else:
        raw.extend(b"untrusted trailer")
    damaged.write_bytes(raw)
    before = set(tmp_path.iterdir())
    with pytest.raises(CryptoError):
        verify_file(damaged, PASSWORD)
    assert set(tmp_path.iterdir()) == before


def test_verify_empty_plaintext_has_authenticated_end_marker(tmp_path):
    original = tmp_path / "empty"
    original.write_bytes(b"")
    encrypted = tmp_path / "empty.krypta"
    encrypt_file(original, encrypted, PASSWORD)
    checked = verify_file(encrypted, PASSWORD)
    assert checked["plaintext_bytes"] == 0
    assert checked["plaintext_sha256"] == hashlib.sha256(b"").hexdigest()


def test_verify_fails_closed_on_symlink(tmp_path):
    original = tmp_path / "source"
    original.write_bytes(b"test")
    encrypted = tmp_path / "vault.krypta"
    encrypt_file(original, encrypted, PASSWORD)
    alias = tmp_path / "alias.krypta"
    try:
        alias.symlink_to(encrypted)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable")
    with pytest.raises(CryptoError):
        verify_file(alias, PASSWORD)
