"""Filesystem-path safety checks; not a Windows reparse-point certification."""
import os
import stat
import pytest
import krypta.core as core


def test_keyfile_permissions_and_exclusive_create(tmp_path):
    keyfile = tmp_path / 'unique.key'
    core.generate_keyfile(keyfile)
    assert len(keyfile.read_bytes()) == 32
    if os.name == 'posix':
        assert stat.S_IMODE(keyfile.stat().st_mode) & 0o077 == 0
    with pytest.raises(FileExistsError):
        core.generate_keyfile(keyfile)


def test_keyfile_symlink_is_rejected(tmp_path):
    real = tmp_path / 'secret.key'
    core.generate_keyfile(real)
    link = tmp_path / 'link.key'
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation not permitted on this Windows runner')
    with pytest.raises(core.CryptoError):
        core._keyfile_digest(link)


def test_source_open_checks_descriptor_even_after_path_validation(tmp_path, monkeypatch):
    src = tmp_path / 'source'
    src.write_bytes(b'TEST ONLY')
    symlink = tmp_path / 'fake'
    try:
        symlink.symlink_to(src)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation not permitted on this runner')
    real_check = core._prepare_paths
    # Model a raced replacement after early path validation. The secure open
    # must independently reject a symlink before reading its contents.
    monkeypatch.setattr(core, '_prepare_paths', lambda a, b: (symlink, tmp_path / 'encrypted.kry'))
    with pytest.raises(core.CryptoError):
        core.encrypt_file(src, tmp_path / 'encrypted.kry', '1234')
    assert not (tmp_path / 'encrypted.kry').exists()
    monkeypatch.setattr(core, '_prepare_paths', real_check)


def test_keyfile_rejects_oversized_content(tmp_path):
    key = tmp_path / 'keyfile'
    key.write_bytes(b'K' * (core.MAX_KEYFILE_BYTES + 1))
    with pytest.raises(core.CryptoError):
        core._keyfile_digest(key)


def test_no_output_if_input_is_replaced_by_nonregular_file(tmp_path, monkeypatch):
    if os.name != 'posix':
        pytest.skip('POSIX FIFO-specific test')
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    src = tmp_path / 'good'
    src.write_bytes(b'good')
    monkeypatch.setattr(core, '_prepare_paths', lambda a, b: (fifo, tmp_path / 'cipher'))
    with pytest.raises(core.CryptoError):
        core.encrypt_file(src, tmp_path / 'cipher', '1')
    assert not (tmp_path / 'cipher').exists()


def test_file_format_still_compatible(tmp_path):
    src = tmp_path / 'plain'
    src.write_bytes(b'example-' * 100_000)
    k = tmp_path / 'key'
    core.generate_keyfile(k)
    ciphertext = tmp_path / 'out.kry'
    core.encrypt_file(src, ciphertext, '1', k)
    recovered = tmp_path / 'recovered'
    core.decrypt_file(ciphertext, recovered, '1', k)
    assert recovered.read_bytes() == src.read_bytes()