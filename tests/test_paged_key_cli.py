"""End-to-end development key command and Linux mount unlock paths."""
from __future__ import annotations

import os
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from research.paged_key_cli import main, read_password_fd
from research.paged_keys import PagedKeyError, unlock_password
from research.paged_volume import PagedResearchVolume
from research.paged_fs2 import PagedFS2

PASSWORD = "A long 2026 test passphrase that protects data"
NEW_PASSWORD = "A separate new password with 25 characters"


def _password_pipe(password: str) -> int:
    reader, writer = os.pipe()
    try:
        os.write(writer, password.encode("utf-8"))
    finally:
        os.close(writer)
    return reader


def test_create_verify_recover_workflow(tmp_path, capsys):
    image, envelope, recovery, changed = (
        tmp_path / "data.kpv", tmp_path / "keys.pvkey",
        tmp_path / "recovery.secret", tmp_path / "new.pvkey"
    )
    reader = _password_pipe(PASSWORD)
    try:
        assert main(["create", "--image", str(image), "--envelope", str(envelope),
                     "--recovery", str(recovery), "--password-fd", str(reader),
                     "--acknowledge-test-only"]) == 0
    finally:
        os.close(reader)
    printed = capsys.readouterr().out
    receipt = re.search(r"EXTERNAL RECEIPT: ([0-9a-f]{64})", printed).group(1)
    assert image.exists() and envelope.exists() and recovery.exists()
    reader = _password_pipe(PASSWORD)
    try:
        assert main(["verify", "--image", str(image), "--envelope", str(envelope),
                     "--expected-receipt", receipt,
                     "--password-fd", str(reader),
                     "--acknowledge-test-only"]) == 0
    finally:
        os.close(reader)
    assert "VERIFIED: 0" in capsys.readouterr().out
    assert main(["verify", "--image", str(image), "--envelope", str(envelope),
                 "--expected-receipt", receipt, "--recovery", str(recovery),
                 "--acknowledge-test-only"]) == 0
    reader = _password_pipe(NEW_PASSWORD)
    try:
        assert main(["recover-password", "--envelope", str(envelope),
                     "--recovery", str(recovery), "--new-envelope", str(changed),
                     "--password-fd", str(reader),
                     "--acknowledge-test-only"]) == 0
    finally:
        os.close(reader)
    assert unlock_password(changed, NEW_PASSWORD) == unlock_password(envelope, PASSWORD)


def test_create_does_not_overwrite_preexisting_data(tmp_path):
    image = tmp_path / "original.kpv"
    image.write_bytes(b"IMPORTANT_EXISTING_BYTES")
    reader = _password_pipe(PASSWORD)
    try:
        with pytest.raises(Exception):
            main(["create", "--image", str(image),
                  "--envelope", str(tmp_path / "new.pvkey"),
                  "--recovery", str(tmp_path / "new.secret"),
                  "--password-fd", str(reader), "--acknowledge-test-only"])
    finally:
        os.close(reader)
    assert image.read_bytes() == b"IMPORTANT_EXISTING_BYTES"
    assert not (tmp_path / "new.pvkey").exists()
    assert not (tmp_path / "new.secret").exists()


def test_invalid_password_pipe_and_overlong_input():
    r, w = os.pipe()
    os.write(w, b"x" * 4097)
    os.close(w)
    try:
        with pytest.raises(PagedKeyError, match="maximum"):
            read_password_fd(r)
    finally:
        os.close(r)


def test_setup_failure_cleans_only_own_test_image(tmp_path):
    existing_recovery = tmp_path / "existing.key"
    existing_recovery.write_bytes(b"NEVER-DELETE")
    image = tmp_path / "new.kpv"
    reader = _password_pipe(PASSWORD)
    try:
        with pytest.raises(PagedKeyError):
            main(["create", "--image", str(image),
                  "--envelope", str(tmp_path / "new.pvkey"),
                  "--recovery", str(existing_recovery),
                  "--password-fd", str(reader), "--acknowledge-test-only"])
    finally:
        os.close(reader)
    assert existing_recovery.read_bytes() == b"NEVER-DELETE"
    assert not image.exists()
    assert not (tmp_path / "new.pvkey").exists()


def test_mount_command_rejects_combined_raw_key_and_password(tmp_path, monkeypatch):
    from research.linux_mount_paged import main as mount
    monkeypatch.setattr("research.linux_mount_paged.platform.system", lambda: "Linux")
    with pytest.raises(SystemExit):
        mount(["--image", str(tmp_path / "foo.kpv"),
               "--mountpoint", str(tmp_path / "mnt"),
               "--key-fd", "0", "--password-fd", "1",
               "--expected-receipt", "0" * 64,
               "--accept-development-risk"])
