"""Offline PFS/2 disaster recovery without any GUI or mounted filesystem.

Exercises independent 256-bit recovery key, external receipt validation,
read-only source images and never-overwritten plaintext destinations.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from krypta.volume_lab import create_image, import_file
from research.paged_key_cli import main
from research.paged_volume import PagedVolumeError
from research.paged_keys import PagedKeyError

PASSWORD = "Reproducible but disposable test passphrase 2026!"


@pytest.fixture
def emergency(tmp_path):
    image = tmp_path / "emergency.kpv"
    envelope = tmp_path / "keys.pvkey"
    recovery = tmp_path / "independent.recovery"
    report = create_image(image, envelope, recovery, PASSWORD, PASSWORD)
    source = tmp_path / "owned-original.bin"
    original = os.urandom(9000) + b"\x00KRYPTA offline rescue\x00"
    source.write_bytes(original)
    new_state = import_file(
        image, envelope, report["receipt"], source, password=PASSWORD
    )
    return {
        "image": image, "envelope": envelope, "recovery": recovery,
        "receipt": new_state["receipt"], "file": source.name,
        "source": source, "bytes": original, "directory": tmp_path,
    }


def _argv(v, command):
    return [
        command, "--image", str(v["image"]), "--envelope", str(v["envelope"]),
        "--recovery", str(v["recovery"]), "--expected-receipt", v["receipt"],
        "--acknowledge-test-only",
    ]


def test_restore_one_file_using_only_offline_recovery_key(emergency, capsys):
    e = emergency
    # A crash-style partial, UNCOMMITTED tail must survive read-only actions.
    with e["image"].open("ab") as out:
        out.write(b"KPG1\x00")
    image_before = e["image"].read_bytes()
    assert main(_argv(e, "list-files")) == 0
    listed = capsys.readouterr().out
    assert repr(e["file"]) in listed
    assert "AUTHENTICATED FILES: 1" in listed
    assert e["image"].read_bytes() == image_before

    output = e["directory"] / "recovered-plaintext.bin"
    argv = _argv(e, "export-file") + [
        "--name", e["file"], "--output", str(output)
    ]
    assert main(argv) == 0
    assert "UNENCRYPTED" in capsys.readouterr().out
    assert output.read_bytes() == e["bytes"]
    assert e["image"].read_bytes() == image_before
    assert e["source"].read_bytes() == e["bytes"]


def test_fail_closed_on_wrong_receipt_before_export(emergency):
    e = emergency
    path = e["directory"] / "must-not-exist.txt"
    args = _argv(e, "export-file") + [
        "--name", e["file"], "--output", str(path)
    ]
    args[args.index(e["receipt"])] = "0" * 64
    with pytest.raises(PagedVolumeError, match="receipt mismatch"):
        main(args)
    assert not path.exists()


def test_existing_destination_remains_byte_for_byte_unchanged(emergency):
    e = emergency
    path = e["directory"] / "precious.txt"
    path.write_bytes(b"DO_NOT_REPLACE")
    args = _argv(e, "export-file") + [
        "--name", e["file"], "--output", str(path)
    ]
    with pytest.raises(PagedKeyError, match="overwrite"):
        main(args)
    assert path.read_bytes() == b"DO_NOT_REPLACE"


def test_offline_recovery_rejects_corrupt_ciphertext(emergency):
    e = emergency
    from research.paged_fs2 import PagedFS2
    from research.paged_volume import PagedResearchVolume
    from research.paged_keys import unlock_recovery
    key, _ = unlock_recovery(e["envelope"], e["recovery"])
    with PagedResearchVolume(e["image"], key, expected_receipt=e["receipt"],
                             read_only=True) as vol:
        fs = PagedFS2(vol)
        sector = fs._files[e["file"]]["blocks"][0]
        off = vol._entry(sector)[1] + 40
    with e["image"].open("r+b") as stream:
        stream.seek(off)
        previous = stream.read(1)
        stream.seek(off)
        stream.write(bytes([previous[0] ^ 1]))
    target = e["directory"] / "never-plaintext.bin"
    with pytest.raises((PagedVolumeError, ValueError)):
        main(_argv(e, "export-file") + [
            "--name", e["file"], "--output", str(target)
        ])
    assert not target.exists()


def test_no_recovery_operation_without_explicit_test_ack(emergency):
    e = emergency
    with pytest.raises(SystemExit) as exc:
        main(_argv(e, "list-files")[:-1])
    assert exc.value.code == 2


def test_verify_cli_reopen_is_byte_read_only(emergency, capsys):
    e = emergency
    with e["image"].open("ab") as out:
        out.write(b"partial_uncommitted_tail")
    before = e["image"].read_bytes()
    assert main(_argv(e, "verify")) == 0
    assert "VERIFIED: 1" in capsys.readouterr().out
    assert e["image"].read_bytes() == before
