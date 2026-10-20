"""Safety and test-key IPC contract for explicit Linux experimental mount CLI."""
from __future__ import annotations

import os
import platform

import pytest

from research import linux_mount
from research.fs_image import ResearchFileSystem
from research.volume_image import ResearchVolume


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipe semantics")
def test_research_key_is_read_from_opaque_pipe_only():
    rd, wr = os.pipe()
    try:
        secret = os.urandom(32)
        os.write(wr, secret)
        os.close(wr)
        wr = -1
        assert linux_mount.read_test_key_fd(rd) == secret
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor type")
def test_regular_file_is_rejected_as_key_fd(tmp_path):
    path = tmp_path / "not-a-pipe"
    path.write_bytes(os.urandom(32))
    with path.open("rb") as inp:
        with pytest.raises(ValueError, match="pipe"):
            linux_mount.read_test_key_fd(inp.fileno())


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipe semantics")
def test_incomplete_test_key_is_rejected():
    rd, wr = os.pipe()
    try:
        os.write(wr, b"short")
        os.close(wr)
        wr = -1
        with pytest.raises(ValueError, match="exactly 32"):
            linux_mount.read_test_key_fd(rd)
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)


def test_explicit_research_risk_opt_in_mandatory():
    with pytest.raises(SystemExit) as ex:
        linux_mount.main(["--image", "x.kvi", "--mountpoint", "/tmp/test",
                          "--key-fd", "0"])
    assert ex.value.code == 2


@pytest.mark.skipif(os.name != "posix", reason="Research Linux CLI not supported on Windows")
def test_cli_mounts_only_existing_test_image_and_closes_on_return(tmp_path, monkeypatch):
    path, key = tmp_path / "test.kvi", os.urandom(32)
    with ResearchVolume(path, key, create=True) as v:
        fs = ResearchFileSystem.format(v)
        trusted_receipt = fs.receipt
    folder = tmp_path / "empty"
    folder.mkdir()
    rd, wr = os.pipe()
    try:
        os.write(wr, key)
        os.close(wr)
        wr = -1
        called = []
        def fake_mount(volume, directory):
            called.append((volume.path, directory, volume.sequence))
            assert volume.read(0) != bytes(4096)
            return "NO ACTUAL MOUNT"
        monkeypatch.setattr(linux_mount, "mount_research_image", fake_mount)
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        result = linux_mount.main([
            "--image", str(path), "--mountpoint", str(folder),
            "--key-fd", str(rd), "--expected-receipt", trusted_receipt,
            "--accept-research-risk"])
        assert result == 0
        assert called == [(path, str(folder), 1)]
        # FUSE/volume file descriptor released upon exit.
        with ResearchVolume(path, key, expected_sequence=1):
            pass
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)


@pytest.mark.skipif(os.name != "posix", reason="Research Linux CLI not supported on Windows")
def test_cli_does_not_create_image_on_wrong_key(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    missing = tmp_path / "missing.kvi"
    rd, wr = os.pipe()
    try:
        os.write(wr, os.urandom(32))
        os.close(wr)
        wr = -1
        with pytest.raises((OSError, ValueError)):
            linux_mount.main([
                "--image", str(missing), "--mountpoint", str(tmp_path),
                "--key-fd", str(rd), "--expected-receipt", "0" * 64,
                "--accept-research-risk"])
        assert not missing.exists()
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)



@pytest.mark.skipif(os.name != "posix", reason="Research Linux CLI not supported on Windows")
def test_cli_refuses_old_snapshot_using_current_trusted_receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    path, key = tmp_path / "volume.kvi", os.urandom(32)
    with ResearchVolume(path, key, create=True) as volume:
        fs = ResearchFileSystem.format(volume)
        snapshot = path.read_bytes()
        old_receipt = volume.commit_receipt
        fs.write_file("later.txt", b"new synthetic data")
        current_receipt = volume.commit_receipt
        assert old_receipt != current_receipt
    path.write_bytes(snapshot)  # attacker restores an OLD but valid image
    folder = tmp_path / "mount"
    folder.mkdir(mode=0o700)
    rd, wr = os.pipe()
    try:
        os.write(wr, key)
        os.close(wr)
        wr = -1
        seen = []
        monkeypatch.setattr(linux_mount, "mount_research_image",
                            lambda *args: seen.append(args))
        before = path.read_bytes()
        with pytest.raises(ValueError, match="receipt mismatch"):
            linux_mount.main(["--image", str(path),
                              "--mountpoint", str(folder), "--key-fd", str(rd),
                              "--expected-receipt", current_receipt,
                              "--accept-research-risk"])
        assert seen == []
        assert path.read_bytes() == before
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)


@pytest.mark.skipif(os.name != "posix", reason="Research Linux CLI not supported on Windows")
def test_cli_without_expected_receipt_is_refused_before_key_read(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    rd, wr = os.pipe()
    try:
        with pytest.raises(SystemExit) as error:
            linux_mount.main(["--image", str(tmp_path / "x.kvi"),
                              "--mountpoint", str(tmp_path),
                              "--key-fd", str(rd), "--accept-research-risk"])
        assert error.value.code == 2
    finally:
        os.close(rd)
        os.close(wr)
