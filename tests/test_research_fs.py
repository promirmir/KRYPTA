"""Disposable KRYPTA-FS/0 API, crypto, recovery and directory regression tests."""
from __future__ import annotations

import os
import random

import pytest

from research.fs_image import (
    CATALOGUE_SECTORS, FS_MAGIC, MAX_FILENAME_BYTES, MAX_FILES, MAX_FILE_BYTES,
    ResearchFSError, ResearchFileSystem,
)
from research.volume_image import BLOCK_BYTES, MAX_BLOCKS, ResearchVolume, VolumeImageError


def new_fs(tmp_path):
    path, key = tmp_path / 'filesystem.kvi', os.urandom(32)
    volume = ResearchVolume(path, key, create=True)
    return path, key, volume, ResearchFileSystem.format(volume)


def test_format_and_reopen_and_no_unformatted_reads(tmp_path):
    p, key = tmp_path/'fresh.kvi', os.urandom(32)
    with ResearchVolume(p, key, create=True) as volume:
        with pytest.raises(ResearchFSError, match='not formatted'):
            ResearchFileSystem(volume)
        fs = ResearchFileSystem.format(volume)
        assert fs.list_files() == []
        assert fs.sequence == 1
        with pytest.raises(ResearchFSError, match='refused'):
            ResearchFileSystem.format(volume)
        receipt = fs.receipt
    with ResearchVolume(p, key, expected_sequence=1, expected_receipt=receipt) as volume:
        assert ResearchFileSystem(volume).list_files() == []


def test_unicode_round_trip_replace_and_reopen(tmp_path):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        assert fs.write_file('Zażółć gęślą_你好.txt', 'Szyfrowanie Привет'.encode()) == 2
        assert fs.read_file('Zażółć gęślą_你好.txt') == 'Szyfrowanie Привет'.encode()
        assert fs.stat('Zażółć gęślą_你好.txt')['size'] > 0
        with pytest.raises(FileExistsError):
            fs.write_file('Zażółć gęślą_你好.txt', b'overwrite without replace')
        assert fs.write_file('Zażółć gęślą_你好.txt', b'new bytes', replace=True) == 3
        assert fs.read_file('Zażółć gęślą_你好.txt') == b'new bytes'
        receipt = fs.receipt
    finally:
        volume.close()
    with ResearchVolume(p, key, expected_sequence=3, expected_receipt=receipt) as reopened:
        fs = ResearchFileSystem(reopened)
        assert fs.read_file('Zażółć gęślą_你好.txt') == b'new bytes'


def test_empty_file_rename_delete_and_sector_reuse(tmp_path):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        fs.write_file('empty', b'')
        assert fs.read_file('empty') == b''
        fs.write_file('blob', os.urandom(BLOCK_BYTES * 2 + 13))
        assert len(fs.read_file('blob')) == BLOCK_BYTES * 2 + 13
        fs.rename_file('blob', 'newname')
        assert 'blob' not in fs.list_files()
        fs.delete_file('newname')
        with pytest.raises(FileNotFoundError):
            fs.read_file('newname')
        fs.write_file('another', b'123')
        assert fs.read_file('another') == b'123'
        assert fs.list_files() == ['another', 'empty']
    finally:
        volume.close()


@pytest.mark.parametrize('bad',[ '', '.', '..', '../data', 'folder/file', r'C:\\data', 'CON', 'nul.txt', 'COM1.port', 'file ', '.hidden.',
    'abc\x00def', 'abc\n', 'tab\t', 'bad|name', 'e\u0301', 'A' * (MAX_FILENAME_BYTES + 1)])
def test_reject_dangerous_names_without_disk_mutation(tmp_path, bad):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        initial = p.read_bytes()
        with pytest.raises(ResearchFSError):
            fs.write_file(bad, b'test')
        assert p.read_bytes() == initial
    finally:
        volume.close()


def test_reject_too_many_files(tmp_path):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        for i in range(MAX_FILES):
            fs.write_file('file%02d' % i, b'')
        with pytest.raises(ResearchFSError, match='Maximum'):
            fs.write_file('overflow', b'')
        assert len(fs.list_files()) == MAX_FILES
    finally:
        volume.close()


def test_failure_does_not_publish_partial_new_file(tmp_path, monkeypatch):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        fs.write_file('old.txt', b'original data')
        expected_receipt = fs.receipt
        saved = volume._frame
        def fail_on_manifest(kind, data):
            if kind == b'C':
                raise OSError('synthetic interruption before metadata commit')
            return saved(kind, data)
        monkeypatch.setattr(volume, '_frame', fail_on_manifest)
        with pytest.raises(OSError):
            fs.write_file('new.txt', os.urandom(BLOCK_BYTES * 2))
        with pytest.raises(VolumeImageError, match='Uncertain'):
            fs.list_files()
    finally:
        volume.close()
    with ResearchVolume(p, key, expected_receipt=expected_receipt) as recovered:
        fs2 = ResearchFileSystem(recovered)
        assert fs2.list_files() == ['old.txt']
        assert fs2.read_file('old.txt') == b'original data'


def test_stale_catalogue_rejected(tmp_path):
    _, _, volume, fs1 = new_fs(tmp_path)
    try:
        fs2 = ResearchFileSystem(volume)
        fs1.write_file('a', b'b')
        with pytest.raises(ResearchFSError, match='Stale'):
            fs2.write_file('another', b'x')
        fs3 = ResearchFileSystem(volume)
        assert fs3.list_files() == ['a']
    finally:
        volume.close()


def test_large_file_one_transaction_and_reopen(tmp_path):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        payload = os.urandom(MAX_FILE_BYTES)
        assert fs.write_file('all.bin', payload) == 2
        assert fs.read_file('all.bin') == payload
        assert fs.receipt
        with pytest.raises(ResearchFSError, match='Not enough'):
            fs.write_file('excess', b'A')
    finally:
        volume.close()
    with ResearchVolume(p, key) as recovered:
        assert ResearchFileSystem(recovered).read_file('all.bin') == payload


def test_deterministic_random_operations_match_oracle(tmp_path):
    _, _, volume, fs = new_fs(tmp_path)
    rng = random.Random(0x4B5259505441)
    oracle = {}
    try:
        for _ in range(65):
            name = f'entry{rng.randrange(0, 16)}'
            choice = rng.randrange(0, 4)
            if choice == 0 and name in oracle:
                fs.delete_file(name)
                oracle.pop(name)
            else:
                data = rng.randbytes(rng.randrange(0, 7000))
                fs.write_file(name, data, replace=name in oracle)
                oracle[name] = data
            assert fs.list_files() == sorted(oracle)
            for key, data in oracle.items():
                assert fs.read_file(key) == data
    finally:
        volume.close()


def test_directory_metadata_encrypted_on_host_disk(tmp_path):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        fs.write_file('classified_example_label.txt', b'test-only-synthetic-secret' * 30)
    finally:
        volume.close()
    raw = p.read_bytes()
    assert FS_MAGIC not in raw
    assert b'classified_example_label' not in raw
    assert b'test-only-synthetic-secret' not in raw


def test_delete_does_not_claim_to_erase_ciphertext_history(tmp_path):
    p, key, volume, fs = new_fs(tmp_path)
    try:
        fs.write_file('gone', b'test data' * 100)
        length_before = p.stat().st_size
        fs.delete_file('gone')
        assert p.stat().st_size > length_before
        assert 'gone' not in fs.list_files()
    finally:
        volume.close()


def test_filesystem_does_not_mount_or_touch_physical_disks():
    import inspect
    from research import fs_image
    source = inspect.getsource(fs_image)
    assert 'subprocess' not in source
    assert 'Enable-BitLocker' not in source
    assert 'cryptsetup' not in source
    assert 'os.open(' not in source