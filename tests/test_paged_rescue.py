"""PFS/2 offline all-file recovery, from disposable synthetic images ONLY."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from krypta.volume_lab import create_image, import_file
from research.paged_rescue import (
    MANIFEST_NAME, RescueError, main, rescue_export_all,
)
from research.paged_keys import PagedKeyError, unlock_password
from research.paged_fs2 import PagedFS2
from research.paged_volume import PagedResearchVolume, PagedVolumeError

from research.rescue_output import private_output


def output_type(path):
    return type(private_output(path))


PASS = "A long independent password for offline rescue tests!"


@pytest.fixture
def prepared(tmp_path):
    image = tmp_path / "synthetic.kpv"
    envelope = tmp_path / "secret.pvkey"
    recovery = tmp_path / "offline-recovery.bin"
    created = create_image(image, envelope, recovery, PASS, PASS)
    return {
        "image": image, "envelope": envelope,
        "recovery": recovery, "receipt": created["receipt"],
        "root": tmp_path,
    }


def insert(case, name: str, content: bytes):
    srcdir = case["root"] / ("input-" + str(len(content)) + "-" + str(len(name)))
    srcdir.mkdir(exist_ok=True)
    source = srcdir / name
    source.write_bytes(content)
    result = import_file(
        case["image"], case["envelope"], case["receipt"], source,
        password=PASS,
    )
    case["receipt"] = result["receipt"]
    return source


def call(case, destination: Path):
    return rescue_export_all(
        case["image"], case["envelope"], case["recovery"],
        case["receipt"], destination,
    )


def test_full_rescue_with_recovery_key_and_file_integrity_report(prepared):
    a = insert(prepared, "Zażółć_你好.bin", os.urandom(23000))
    b = insert(prepared, "second.txt", b"rescue all, not only one file" * 107)
    before = prepared["image"].read_bytes()
    dest = prepared["root"] / "extracted-new"
    report = call(prepared, dest)
    assert report["files_verified"] == 2
    assert report["bytes_verified"] == a.stat().st_size + b.stat().st_size
    assert prepared["image"].read_bytes() == before
    assert (dest / a.name).read_bytes() == a.read_bytes()
    assert (dest / b.name).read_bytes() == b.read_bytes()
    manifest = json.loads((dest / MANIFEST_NAME).read_text())
    assert manifest["complete"] is True
    assert manifest["format"] == "KRYPTA-OFFLINE-RESCUE/1"
    assert manifest["trusted_external_receipt"] == prepared["receipt"]
    assert manifest["file_count"] == 2
    assert set(m["name"] for m in manifest["files"]) == {a.name, b.name}
    assert len(manifest["files"][0]["sha256"]) == 64


def test_empty_volume_still_creates_unambiguous_completion_manifest(prepared):
    dest = prepared["root"] / "empty-recovered"
    out = call(prepared, dest)
    assert out["files_verified"] == 0
    assert list(dest.iterdir()) == [dest / MANIFEST_NAME]


def test_wrong_external_receipt_does_not_create_output(prepared):
    dest = prepared["root"] / "wrong-receipt"
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        rescue_export_all(
            prepared["image"], prepared["envelope"], prepared["recovery"],
            "0" * 64, dest,
        )
    assert not dest.exists()


def test_tampered_recovery_key_fails_before_any_plaintext(prepared):
    with prepared["recovery"].open("r+b") as f:
        original = f.read(1)
        f.seek(0)
        f.write(bytes([original[0] ^ 1]))
    dest = prepared["root"] / "wrong-secret"
    with pytest.raises(PagedKeyError, match="authentication"):
        call(prepared, dest)
    assert not dest.exists()


def test_corrupted_existing_encrypted_sector_does_not_create_output(prepared):
    insert(prepared, "sentinel.bin", os.urandom(17000))
    key, _ = unlock_password(prepared["envelope"], PASS)
    with PagedResearchVolume(prepared["image"], key,
                             expected_receipt=prepared["receipt"],
                             read_only=True) as vol:
        sector = PagedFS2(vol)._files["sentinel.bin"]["blocks"][0]
        off = vol._entry(sector)[1] + 40
    with prepared["image"].open("r+b") as f:
        f.seek(off)
        x = f.read(1)
        f.seek(off)
        f.write(bytes([x[0] ^ 0x80]))
    before = prepared["image"].read_bytes()
    dest = prepared["root"] / "damaged"
    with pytest.raises(PagedVolumeError):
        call(prepared, dest)
    assert not dest.exists()
    assert prepared["image"].read_bytes() == before


def test_existing_destination_is_never_overwritten(prepared):
    dest = prepared["root"] / "occupied"
    dest.mkdir()
    (dest / "valuable.txt").write_text("do not touch")
    with pytest.raises(RescueError, match="must not already exist"):
        call(prepared, dest)
    assert (dest / "valuable.txt").read_text() == "do not touch"
    assert sorted(p.name for p in dest.iterdir()) == ["valuable.txt"]


def test_if_second_plaintext_export_fails_owned_first_is_cleaned(prepared, monkeypatch):
    insert(prepared, "first.bin", b"A" * 19000)
    insert(prepared, "second.bin", b"B" * 121)
    import research.paged_rescue as rescue
    backend = output_type(prepared["root"] / "unused")
    original = backend.write
    saved_image = prepared["image"].read_bytes()
    def fail_on_second(self, p, data):
        if Path(p).name == "second.bin":
            raise OSError("synthetic target I/O failure")
        return original(self, p, data)
    monkeypatch.setattr(backend, "write", fail_on_second)
    dest = prepared["root"] / "failed-mid-export"
    with pytest.raises(OSError, match="synthetic"):
        call(prepared, dest)
    assert not dest.exists()
    assert prepared["image"].read_bytes() == saved_image


def test_manifest_failure_leaves_no_incomplete_ordinary_result(prepared, monkeypatch):
    insert(prepared, "example", b"temporary-unencrypted-test")
    import research.paged_rescue as rescue
    backend = output_type(prepared["root"] / "unused")
    original = backend.write
    def fail_manifest(self, p, data):
        if Path(p).name == MANIFEST_NAME:
            raise OSError("synthetic manifest fsync error")
        return original(self, p, data)
    monkeypatch.setattr(backend, "write", fail_manifest)
    dest = prepared["root"] / "no-false-completion"
    with pytest.raises(OSError, match="manifest"):
        call(prepared, dest)
    assert not dest.exists()


def test_case_insensitive_duplicate_source_names_refused(prepared):
    # Source directory differs so test works also on case-insensitive Windows.
    insert(prepared, "Alpha.txt", b"upper")
    insert(prepared, "alpha.txt", b"lower")
    dest = prepared["root"] / "case-collision"
    with pytest.raises(RescueError, match="Case-insensitive"):
        call(prepared, dest)
    assert not dest.exists()


def test_manifest_name_collision_refused_before_any_output(prepared):
    insert(prepared, MANIFEST_NAME, b"not a real completion record")
    dest = prepared["root"] / "reserved-collision"
    with pytest.raises(RescueError, match="manifest"):
        call(prepared, dest)
    assert not dest.exists()


def test_incomplete_crash_log_is_preserved_exactly_during_rescue(prepared):
    insert(prepared, "sample.bin", b"authenticated" * 30)
    with prepared["image"].open("ab") as f:
        f.write(b"KPG1")  # incomplete frame header after valid commit
    before = prepared["image"].read_bytes()
    out = call(prepared, prepared["root"] / "read-only-rescue")
    assert out["files_verified"] == 1
    assert prepared["image"].read_bytes() == before


def test_cli_explicit_acknowledgement_and_success(prepared, capsys):
    args = [
        "--image", str(prepared["image"]),
        "--envelope", str(prepared["envelope"]),
        "--recovery", str(prepared["recovery"]),
        "--trusted-receipt", prepared["receipt"],
        "--new-directory", str(prepared["root"] / "cli-recovery"),
    ]
    with pytest.raises(SystemExit) as e:
        main(args)
    assert e.value.code == 2
    assert not (prepared["root"] / "cli-recovery").exists()
    assert main(args + ["--acknowledge-plaintext-test-only"]) == 0
    assert (prepared["root"] / "cli-recovery" / MANIFEST_NAME).exists()
    assert "UNENCRYPTED" in capsys.readouterr().out


def test_no_secret_text_is_written_to_completion_manifest(prepared):
    dest = prepared["root"] / "manifest"
    call(prepared, dest)
    raw = (dest / MANIFEST_NAME).read_bytes()
    assert PASS.encode() not in raw
    assert prepared["recovery"].read_bytes() not in raw
    assert b"UNENCRYPTED" in raw



def test_legacy_key_cli_verify_now_preserves_incomplete_crash_tail(prepared, capsys):
    import argparse
    from research.paged_key_cli import _check
    insert(prepared, "console-verify", b"unaltered after verify" * 45)
    with prepared["image"].open("ab") as f:
        f.write(b"KPG1")
    snapshot = prepared["image"].read_bytes()
    opts = argparse.Namespace(
        image=str(prepared["image"]),
        envelope=str(prepared["envelope"]),
        recovery=str(prepared["recovery"]),
        expected_receipt=prepared["receipt"],
    )
    _check(opts)
    assert "VERIFIED:" in capsys.readouterr().out
    assert prepared["image"].read_bytes() == snapshot



def test_completion_marker_is_not_published_if_directory_sync_fails(
        prepared, monkeypatch):
    insert(prepared, "durability.txt", b"durable-plaintext-contents")
    import research.paged_rescue as rescue
    calls = []
    def fail_first_directory_sync(path):
        calls.append(path)
        raise OSError("synthetic directory durability failure")
    monkeypatch.setattr(output_type(prepared["root"] / "unused"), "sync", fail_first_directory_sync)
    dest = prepared["root"] / "no-false-complete"
    with pytest.raises(OSError, match="durability"):
        call(prepared, dest)
    assert len(calls) == 1
    assert not dest.exists()
    # Failure cleanup must NEVER remove or overwrite encrypted source.
    assert prepared["image"].exists()


def test_symlinked_output_ancestor_is_refused_before_plaintext(prepared):
    real = prepared["root"] / "real-parent"
    real.mkdir()
    alias = prepared["root"] / "alias-parent"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("This platform cannot create directory symlinks")
    destination = alias / "recovered"
    with pytest.raises((RescueError, OSError)):
        call(prepared, destination)
    assert not (real / "recovered").exists()


def test_nested_symlinked_output_ancestor_is_refused(prepared):
    real = prepared["root"] / "trusted"
    real.mkdir()
    alias = prepared["root"] / "redirect"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks unavailable on this platform")
    nested = alias / "nested"
    nested.mkdir()
    destination = nested / "recovered"
    with pytest.raises((RescueError, OSError)):
        call(prepared, destination)
    assert not (real / "nested" / "recovered").exists()
