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
        ResearchFileSystem.format(v)
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
            "--key-fd", str(rd), "--accept-research-risk"])
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
                "--key-fd", str(rd), "--accept-research-risk"])
        assert not missing.exists()
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)
