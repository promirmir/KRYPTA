"""Regression checks for two-pass authentication before writing plaintext."""

import pytest
import krypta.core as core


def test_corrupted_end_is_rejected_before_creating_plaintext_temp(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'KRYPTA-PRIVATE-TEST-DATA' * 100_000)
    sealed = tmp_path / 'sealed.kry'
    core.encrypt_file(source, sealed, '1234')
    corrupted = bytearray(sealed.read_bytes())
    corrupted[-1] ^= 1  # forged terminal authentication tag
    sealed.write_bytes(corrupted)

    attempted_writes = []
    real_atomic_write = core._atomic_write

    def trap_atomic_write(*args, **kwargs):
        attempted_writes.append(args)
        return real_atomic_write(*args, **kwargs)

    monkeypatch.setattr(core, '_atomic_write', trap_atomic_write)
    output = tmp_path / 'out'
    with pytest.raises(core.CryptoError):
        core.decrypt_file(sealed, output, '1234')
    assert attempted_writes == []
    assert not output.exists()
    assert list(tmp_path.glob('.krypta-*.tmp')) == []


def test_valid_multiple_chunk_decryption_is_successful_after_preflight(tmp_path):
    original = tmp_path / 'original'
    original.write_bytes(b'data' * (core.CHUNK_SIZE // 4 + 5))
    encrypted = tmp_path / 'encrypted.kry'
    decrypted = tmp_path / 'decrypted'
    core.encrypt_file(original, encrypted, '1')
    core.decrypt_file(encrypted, decrypted, '1')
    assert decrypted.read_bytes() == original.read_bytes()


def test_appended_bytes_do_not_create_plaintext_temp(tmp_path, monkeypatch):
    src = tmp_path / 'src'
    src.write_bytes(b'data')
    sealed = tmp_path / 'encrypted.kry'
    core.encrypt_file(src, sealed, '5678')
    with sealed.open('ab') as f:
        f.write(b'INJECTED')
    def forbid_atomic(*args, **kwargs):
        raise AssertionError('Corrupt file must not create a plaintext temp')
    monkeypatch.setattr(core, '_atomic_write', forbid_atomic)
    with pytest.raises(core.CryptoError):
        core.decrypt_file(sealed, tmp_path / 'out', '5678')