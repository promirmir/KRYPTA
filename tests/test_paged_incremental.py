"""Incremental authenticated KRYPTA-PFS/1 updates.

Tests use only temporary .kpv images and ephemeral keys.
"""
import os

import pytest

from research.paged_fs import PagedFileSystem, PagedFSError
from research.paged_volume import BLOCK_BYTES, PagedResearchVolume, PagedVolumeError


def test_one_byte_edit_changes_only_one_encrypted_data_generation(tmp_path):
    path = tmp_path / "incremental.kpv"
    key = os.urandom(32)
    original = bytes([n % 251 for n in range(220 * BLOCK_BYTES)])
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("large.bin", original)
        blocks = list(fs._files["large.bin"]["blocks"])
        old_generations = [volume._entry(index)[0] for index in blocks]
        before_receipt = fs.receipt
        modified = bytearray(original)
        modified[183 * BLOCK_BYTES + 13] ^= 0x40
        fs.write_file("large.bin", bytes(modified), replace=True)
        after = [volume._entry(index)[0] for index in blocks]
        assert sum(a != b for a, b in zip(old_generations, after)) == 1
        assert after[183] == old_generations[183] + 1
        assert fs._files["large.bin"]["blocks"] == blocks
        assert fs.receipt != before_receipt
        assert fs.read_file("large.bin") == bytes(modified)
        latest = fs.receipt
    with PagedResearchVolume(path, key, expected_receipt=latest) as volume:
        assert PagedFileSystem(volume).read_file("large.bin") == bytes(modified)


def test_identical_replacement_is_a_true_noop(tmp_path):
    path, key = tmp_path / "same.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        data = b"unchanged" * 120
        fs.write_file("same", data)
        receipt, sequence = fs.receipt, fs.sequence
        ciphertext = path.read_bytes()
        assert fs.write_file("same", data, replace=True) == sequence
        assert fs.receipt == receipt
        assert path.read_bytes() == ciphertext


def test_shrink_zeroes_trailing_sector_and_releases_catalogue_blocks(tmp_path):
    path, key = tmp_path / "shrink.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("trunc", b"Q" * (5 * BLOCK_BYTES))
        old = list(fs._files["trunc"]["blocks"])
        fs.write_file("trunc", b"Q" * (BLOCK_BYTES + 2), replace=True)
        assert fs._files["trunc"]["blocks"] == old[:2]
        assert volume.read(old[1]) == b"QQ" + bytes(BLOCK_BYTES - 2)
        assert fs.read_file("trunc") == b"Q" * (BLOCK_BYTES + 2)
        fs.write_file("another", b"Z" * BLOCK_BYTES)
        assert not set(fs._files["another"]["blocks"]) & set(fs._files["trunc"]["blocks"])


def test_extension_changes_only_new_sectors_and_last_partial(tmp_path):
    path, key = tmp_path / "extend.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("x", b"A" * (BLOCK_BYTES + 1))
        before = fs._files["x"]["blocks"]
        generation = volume._entry(before[0])[0]
        fs.write_file("x", b"A" * (BLOCK_BYTES + 1) + b"B" * (2 * BLOCK_BYTES),
                      replace=True)
        assert volume._entry(before[0])[0] == generation
        assert fs.read_file("x") == b"A" * (BLOCK_BYTES + 1) + b"B" * (2 * BLOCK_BYTES)


def test_modified_pfs_io_does_not_overlap_another_file(tmp_path):
    path, key = tmp_path / "two.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("a", b"A" * (2 * BLOCK_BYTES))
        fs.write_file("b", b"B" * (2 * BLOCK_BYTES))
        b_blocks = fs._files["b"]["blocks"]
        b_gen = [volume._entry(index)[0] for index in b_blocks]
        fs.write_file("a", b"C" * (3 * BLOCK_BYTES), replace=True)
        assert set(fs._files["a"]["blocks"]).isdisjoint(b_blocks)
        assert [volume._entry(index)[0] for index in b_blocks] == b_gen
        assert fs.read_file("b") == b"B" * (2 * BLOCK_BYTES)


def test_previous_corruption_refuses_overwrite_without_new_commit(tmp_path):
    path, key = tmp_path / "bad.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("existing", b"A" * BLOCK_BYTES)
        block = fs._files["existing"]["blocks"][0]
        frame_offset = volume._entry(block)[1] + 14
        with open(path, "r+b") as handle:
            handle.seek(frame_offset)
            value = handle.read(1)
            handle.seek(frame_offset)
            handle.write(bytes([value[0] ^ 1]))
        before = path.read_bytes()
        receipt = fs.receipt
        with pytest.raises(PagedVolumeError):
            fs.write_file("existing", b"new", replace=True)
        assert path.read_bytes() == before
        assert fs.receipt == receipt


def test_old_catalogue_format_and_wrong_output_size_fail_closed(tmp_path):
    path, key = tmp_path / "invalid.kpv", os.urandom(32)
    with PagedResearchVolume(path, key, create=True) as volume:
        fs = PagedFileSystem.format(volume)
        fs.write_file("a", b"A")
        before = path.read_bytes()
        with pytest.raises(PagedFSError, match="size"):
            fs.write_file("a", b"B" * (fs.max_file_bytes + 1), replace=True)
        assert path.read_bytes() == before
        with pytest.raises(FileExistsError):
            fs.write_file("a", b"B")
        assert path.read_bytes() == before
