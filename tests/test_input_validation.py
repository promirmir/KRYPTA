"""Adversarial, deterministic input checks for the experimental file parser.

Not a formal cryptographic security audit or proof of brute-force resistance.
"""
from __future__ import annotations

import random

import pytest

from krypta.core import CryptoError, encrypt_file, decrypt_file, file_info


@pytest.mark.parametrize("length", [0, 1, 2, 5, 9, 10, 30, 100, 1000, 5000])
def test_malformed_files_are_rejected(tmp_path, length):
    input_file = tmp_path / "malformed.kry"
    input_file.write_bytes(b"K" * length)
    with pytest.raises(CryptoError):
        file_info(input_file)


def test_random_untrusted_file_headers_are_rejected(tmp_path):
    rng = random.Random(0x4B5259505441)
    input_file = tmp_path / "untrusted.kry"
    for _ in range(256):
        size = rng.randrange(0, 2049)
        input_file.write_bytes(rng.randbytes(size))
        with pytest.raises(CryptoError):
            file_info(input_file)


def test_failed_decryption_does_not_overwrite_existing_output(tmp_path):
    src = tmp_path / "plain"
    src.write_bytes(b"private test bytes")
    encrypted = tmp_path / "private.kry"
    encrypt_file(src, encrypted, "1234")
    target = tmp_path / "existing.txt"
    target.write_bytes(b"PROTECTED EXISTING CONTENT")
    with pytest.raises(FileExistsError):
        decrypt_file(encrypted, target, "1234")
    assert target.read_bytes() == b"PROTECTED EXISTING CONTENT"


def test_empty_password_is_rejected_without_writing_file(tmp_path):
    src = tmp_path / "input"
    src.write_bytes(b"hello")
    target = tmp_path / "output.kry"
    with pytest.raises(CryptoError):
        encrypt_file(src, target, "")
    assert not target.exists()
