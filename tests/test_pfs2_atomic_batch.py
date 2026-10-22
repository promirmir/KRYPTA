"""Adversarial atomic multi-file import tests on disposable .kpv only."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from krypta.volume_lab import (
    create_image, export_file, import_folder_atomic, verify_image,
)
from research.paged_fs2 import (
    AtomicBatchCommitUncertain, PagedFS2, PagedFS2Error,
)
from research.paged_volume import PagedResearchVolume, PagedVolumeError


@pytest.fixture
def image(tmp_path):
    file = tmp_path / "batch.kpv"
    key = os.urandom(32)
    with PagedResearchVolume(file, key, create=True) as v:
        fs = PagedFS2.format(v)
        yield file, key, v, fs


def test_batch_encrypted_one_commit_and_independent_reopen(image):
    path, key, volume, fs = image
    start_sequence, old_receipt = fs.sequence, fs.receipt
    sources = {"alpha.txt": b"hello", "empty.bin": b"", "space.bin": bytes(4500)}
    fs.import_files_atomic(sources)
    assert fs.sequence == start_sequence + 1
    assert fs.receipt != old_receipt
    assert fs.verify_all()["files_verified"] == 3
    assert all(fs.read_file(k) == v for k, v in sources.items())
    assert b"alpha.txt" not in path.read_bytes()
    newer = fs.receipt
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=old_receipt)
    with PagedResearchVolume(path, key, expected_receipt=newer, read_only=True) as opened:
        checked = PagedFS2(opened)
        assert {k: checked.read_file(k) for k in sources} == sources


@pytest.mark.parametrize("payloads", [
    {}, {"a": b"x", "A": b"y"}, {"x": "not bytes"},
    {"y": b"x" * (8 * 1024 * 1024 + 1)},
    {f"file-{n}": b"x" for n in range(33)},
])
def test_invalid_batches_never_touch_ciphertext(image, payloads):
    path, _, _, fs = image
    before, receipt = path.read_bytes(), fs.receipt
    with pytest.raises((PagedFS2Error, ValueError)):
        fs.import_files_atomic(payloads)
    assert path.read_bytes() == before
    assert fs.receipt == receipt


def test_collision_refused_without_any_commit(image):
    path, _, _, fs = image
    fs.import_files_atomic({"one.txt": b"old"})
    original, receipt = path.read_bytes(), fs.receipt
    with pytest.raises(FileExistsError):
        fs.import_files_atomic({"one.txt": b"new"})
    with pytest.raises(PagedFS2Error, match="Ambiguous"):
        fs.import_files_atomic({"ONE.TXT": b"new"})
    assert path.read_bytes() == original
    assert fs.receipt == receipt
    assert fs.read_file("one.txt") == b"old"


def test_interruption_before_final_cow_root_preserves_all_old_files(image, monkeypatch):
    path, key, volume, fs = image
    fs.import_files_atomic({"old.txt": b"old"})
    prior = fs.receipt
    append = volume._append

    def interrupt(kind, payload):
        if kind == b"C":
            raise OSError("injected failure before final commit record")
        return append(kind, payload)

    monkeypatch.setattr(volume, "_append", interrupt)
    with pytest.raises(AtomicBatchCommitUncertain):
        fs.import_files_atomic({"a": b"new", "b": b"contents"})
    with pytest.raises(PagedVolumeError, match="Uncertain"):
        fs.list_files()
    volume.close()
    with PagedResearchVolume(path, key, expected_receipt=prior, read_only=True) as reopened:
        checked = PagedFS2(reopened)
        assert checked.list_files() == ["old.txt"]
        assert checked.read_file("old.txt") == b"old"


def test_lost_ack_never_marks_candidate_as_trusted(image, monkeypatch):
    path, key, volume, fs = image
    prior = fs.receipt
    commit = volume._commit

    def lost_ack(*a, **kw):
        commit(*a, **kw)
        raise OSError("ack lost after durable commit")

    monkeypatch.setattr(volume, "_commit", lost_ack)
    with pytest.raises(AtomicBatchCommitUncertain):
        fs.import_files_atomic({"a": b"persisted", "b": b"but untrusted"})
    volume.close()
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        PagedResearchVolume(path, key, expected_receipt=prior, read_only=True)


def test_volume_lab_folder_import_one_receipt_and_unchanged_sources(tmp_path):
    image = tmp_path / "v.kpv"
    env, backup = tmp_path / "v.pvkey", tmp_path / "v.recovery"
    password = "Disposable development passphrase 2026!"
    create = create_image(image, env, backup, password, password)
    directory = tmp_path / "batch"
    directory.mkdir()
    a, b = directory / "alpha.bin", directory / "beta.bin"
    a.write_bytes(b"alpha contents")
    b.write_bytes(bytes(8193))
    result = import_folder_atomic(image, env, create["receipt"], directory, recovery=backup)
    assert result["files_verified"] == 2
    assert result["bytes_verified"] == 8207
    assert result["receipt_changed"] is True
    assert result["receipt"] != create["receipt"]
    assert a.read_bytes() == b"alpha contents" and b.read_bytes() == bytes(8193)
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        verify_image(image, env, create["receipt"], password=password)
    verified = verify_image(image, env, result["receipt"], password=password)
    assert {f["name"] for f in verified["files"]} == {"alpha.bin", "beta.bin"}
    restored = tmp_path / "restored.bin"
    export_file(image, env, result["receipt"], "alpha.bin", restored, password=password)
    assert restored.read_bytes() == a.read_bytes()


def test_folder_import_refuses_subdirectories_and_does_not_touch_image(tmp_path):
    image = tmp_path / "v.kpv"
    env, backup = tmp_path / "v.pvkey", tmp_path / "v.recovery"
    password = "Disposable development passphrase 2026!"
    create = create_image(image, env, backup, password, password)
    folder = tmp_path / "source"
    folder.mkdir()
    (folder / "ok").write_bytes(b"untouched")
    (folder / "nested").mkdir()
    original = image.read_bytes()
    with pytest.raises(ValueError, match="regular flat"):
        import_folder_atomic(image, env, create["receipt"], folder, password=password)
    assert image.read_bytes() == original


def test_folder_import_prevents_self_encrypting_own_image(tmp_path):
    image = tmp_path / "v.kpv"
    env, backup = tmp_path / "v.pvkey", tmp_path / "v.recovery"
    password = "Disposable development passphrase 2026!"
    create = create_image(image, env, backup, password, password)
    before = image.read_bytes()
    with pytest.raises(ValueError, match="distinct"):
        import_folder_atomic(image, env, create["receipt"], tmp_path, password=password)
    assert image.read_bytes() == before
