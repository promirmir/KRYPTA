import os
import struct
import pytest
from pathlib import Path
from krypta.core import MAGIC, CryptoError, decrypt_file, encrypt_file, generate_keyfile, file_info

@pytest.mark.parametrize('password', ['1', '0000', '1234', 'zażółć gęślą jaźń'])
@pytest.mark.parametrize('length', [0, 1, 1024 * 1024 + 42])
def test_roundtrip(tmp_path, password, length):
    source = tmp_path / 'src.dat'
    source.write_bytes(os.urandom(length))
    encrypted = tmp_path / 'cipher.kry'
    restored = tmp_path / 'restored.dat'
    encrypt_file(source, encrypted, password)
    assert encrypted.read_bytes().startswith(b"KRYPTA / AUTHENTICATED")
    assert MAGIC in encrypted.read_bytes()[:1024]
    assert file_info(encrypted)['algorithm'] == 'AES-256-GCM-stream-v1'
    decrypt_file(encrypted, restored, password)
    assert restored.read_bytes() == source.read_bytes()


def test_wrong_password_no_output(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'secret')
    dest = tmp_path / 'cipher'
    encrypt_file(src, dest, '1234')
    plain = tmp_path / 'plain'
    with pytest.raises(CryptoError):
        decrypt_file(dest, plain, '4321')
    assert not plain.exists()


def test_keyfile_required(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'hello')
    key = tmp_path / 'secret.key'
    generate_keyfile(key)
    enc = tmp_path / 'encrypted'
    encrypt_file(src, enc, '1', key)
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / 'no_key', '1')
    other = tmp_path / 'other.key'
    generate_keyfile(other)
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / 'wrong_key', '1', other)
    decrypt_file(enc, tmp_path / 'good', '1', key)
    assert (tmp_path / 'good').read_bytes() == b'hello'


def test_bitflip_rejected_without_plaintext(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'A' * 500)
    enc = tmp_path / 'enc'
    encrypt_file(src, enc, '1234')
    corrupted = bytearray(enc.read_bytes())
    corrupted[-25] ^= 0x01
    enc.write_bytes(corrupted)
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / 'out', '1234')
    assert not (tmp_path / 'out').exists()


def test_truncation_rejected_without_plaintext(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'C' * 100)
    enc = tmp_path / 'enc'
    encrypt_file(src, enc, '1234')
    enc.write_bytes(enc.read_bytes()[:-12])
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / 'out', '1234')
    assert not (tmp_path / 'out').exists()


def test_append_rejected(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'1')
    enc = tmp_path / 'enc'
    encrypt_file(src, enc, '1234')
    with enc.open('ab') as f:
        f.write(b'injected')
    with pytest.raises(CryptoError):
        decrypt_file(enc, tmp_path / 'out', '1234')
    assert not (tmp_path / 'out').exists()


def test_no_overwrite(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'hello')
    dest = tmp_path / 'enc'
    dest.write_text('important')
    with pytest.raises(FileExistsError):
        encrypt_file(src, dest, '1234')
    assert dest.read_text() == 'important'


def test_randomized_ciphertext(tmp_path):
    src = tmp_path / 'src'
    src.write_bytes(b'hello world')
    a, b = tmp_path / 'a', tmp_path / 'b'
    encrypt_file(src, a, '1234')
    encrypt_file(src, b, '1234')
    assert a.read_bytes() != b.read_bytes()


def test_keyfile_creation_no_overwrite(tmp_path):
    k = tmp_path / 'key'
    generate_keyfile(k)
    assert len(k.read_bytes()) == 32
    with pytest.raises(FileExistsError):
        generate_keyfile(k)