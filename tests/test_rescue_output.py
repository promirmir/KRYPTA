"""Adversarial output tests use disposable data; no encrypted key fixtures."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from research.rescue_output import RescueError, private_output


def test_roundtrip_including_empty_and_unicode_files(tmp_path):
    destination = tmp_path / "new"
    with private_output(destination) as output:
        output.write("empty", b"")
        output.write("Zażółć_你好.bin", b"verified" * 9000)
        output.sync()
    assert (destination / "empty").read_bytes() == b""
    assert (destination / "Zażółć_你好.bin").read_bytes() == b"verified" * 9000


@pytest.mark.parametrize("name", ["../escape", "a/b", "a\\b", ".", "..", "", "a:stream", "a\0b"])
def test_invalid_leaf_never_escapes_output(tmp_path, name):
    destination = tmp_path / "new"
    with pytest.raises(RescueError):
        with private_output(destination) as output:
            output.write(name, b"secret")
    assert not destination.exists()
    assert not (tmp_path / "escape").exists()


def test_exclusive_create_preserves_unexpected_manifest(tmp_path):
    destination = tmp_path / "new"
    with pytest.raises(OSError):
        with private_output(destination) as output:
            output.write("owned", b"ours")
            (destination / "manifest").write_bytes(b"unfamiliar")
            output.write("manifest", b"must never overwrite")
    assert (destination / "manifest").read_bytes() == b"unfamiliar"
    assert not (destination / "owned").exists()


def test_hardlink_collision_never_changes_external_file(tmp_path):
    external = tmp_path / "valuable"
    external.write_bytes(b"keep")
    destination = tmp_path / "new"
    with pytest.raises(OSError):
        with private_output(destination) as output:
            if os.name == "nt":
                # NTFS refuses link creation into the exclusively pinned
                # directory before there can even be a collision.
                with pytest.raises(OSError):
                    os.link(external, destination / "collision")
                raise OSError("hardlink attack blocked by directory sharing lock")
            os.link(external, destination / "collision")
            output.write("collision", b"secret")
    assert external.read_bytes() == b"keep"
    if os.name == "nt":
        assert not destination.exists()
    else:
        assert (destination / "collision").read_bytes() == b"keep"


def test_fsync_failure_cleans_even_partially_written_file(tmp_path, monkeypatch):
    def fail(fd):
        raise OSError("injected data sync failure")
    destination = tmp_path / "new"
    with pytest.raises(OSError, match="injected"):
        with private_output(destination) as output:
            monkeypatch.setattr(os, "fsync", fail)
            output.write("partial", b"secret")
    assert not destination.exists()


def test_verification_uses_original_descriptor(tmp_path, monkeypatch):
    # Any path-based Python follow-up open would fail this test. Low-level
    # relative create is deliberately unaffected.
    import builtins
    destination = tmp_path / "new"
    with private_output(destination) as output:
        def forbidden(*args, **kwargs):
            raise AssertionError("path-based plaintext reopen")
        with monkeypatch.context() as patch:
            patch.setattr(builtins, "open", forbidden)
            patch.setattr(Path, "open", forbidden)
            output.write("data", b"private contents")
    assert (destination / "data").read_bytes() == b"private contents"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor race")
@pytest.mark.parametrize("depth", [0, 1, 3])
def test_linux_symlink_ancestors_at_multiple_depths(tmp_path, depth):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    nested = alias
    for index in range(depth):
        nested = nested / str(index)
        nested.mkdir()
    with pytest.raises(OSError):
        with private_output(nested / "new"):
            pytest.fail("symlink followed")
    assert not (nested / "new").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor race")
def test_linux_swap_after_check_cannot_redirect_plaintext(tmp_path, monkeypatch):
    destination = tmp_path / "new"
    moved = tmp_path / "original"
    with pytest.raises(RescueError, match="identity changed"):
        with private_output(destination) as output:
            original_open = os.open
            def swap(name, flags, *args, **kwargs):
                if name == "data":
                    destination.rename(moved)
                    destination.mkdir()
                    (destination / "sentinel").write_bytes(b"preserve replacement")
                return original_open(name, flags, *args, **kwargs)
            monkeypatch.setattr(os, "open", swap)
            output.write("data", b"must stay with pinned directory")
    assert sorted(p.name for p in destination.iterdir()) == ["sentinel"]
    assert (destination / "sentinel").read_bytes() == b"preserve replacement"
    assert not list(moved.iterdir())  # own data removed through original dirfd


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor cleanup")
def test_linux_cleanup_preserves_replacement_identity(tmp_path):
    destination = tmp_path / "new"
    with pytest.raises(RuntimeError):
        with private_output(destination) as output:
            output.write("data", b"ours")
            (destination / "data").unlink()
            (destination / "data").write_bytes(b"replacement")
            raise RuntimeError("trigger cleanup")
    assert (destination / "data").read_bytes() == b"replacement"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux parent pinning")
def test_linux_parent_swap_at_mkdir_does_not_redirect_creation(tmp_path, monkeypatch):
    parent, moved = tmp_path / "parent", tmp_path / "moved"
    parent.mkdir()
    original_mkdir = os.mkdir
    def swap(name, *args, **kwargs):
        if name == "new":
            parent.rename(moved)
            original_mkdir(parent)
        return original_mkdir(name, *args, **kwargs)
    monkeypatch.setattr(os, "mkdir", swap)
    with pytest.raises(RescueError, match="ancestor identity changed"):
        with private_output(parent / "new"):
            pytest.fail("replaced ancestry accepted")
    assert not list(parent.iterdir())
    assert not list(moved.iterdir())


@pytest.mark.skipif(sys.platform != "linux", reason="Linux hardlink injection")
def test_linux_hardlink_during_write_is_detected_and_preserved(tmp_path, monkeypatch):
    destination = tmp_path / "new"
    external = tmp_path / "unexpected-link"
    original_write = os.write
    def link_after_write(fd, data):
        count = original_write(fd, data)
        os.link(destination / "data", external)
        return count
    with pytest.raises(RescueError, match="does not match"):
        with private_output(destination) as output:
            monkeypatch.setattr(os, "write", link_after_write)
            output.write("data", b"synthetic")
    # Same-UID mutation is outside the confidentiality boundary, but cleanup
    # must still preserve unexpected aliases and never publish completion.
    assert external.read_bytes() == b"synthetic"
    assert (destination / "data").stat().st_nlink == 2


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX permissions")
def test_linux_shared_nonsticky_ancestor_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o777)
    shared.chmod(0o777)
    with pytest.raises(RescueError, match="Shared writable"):
        with private_output(shared / "new"):
            pytest.fail("shared output accepted")
    assert not (shared / "new").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing locks")
def test_windows_pinned_directory_and_file_cannot_be_replaced(tmp_path):
    destination = tmp_path / "new"
    with private_output(destination) as output:
        for directory in (destination, tmp_path):
            with pytest.raises(OSError):
                directory.rename(directory.with_name(directory.name + "-replaced"))
        output.write("data", b"ours")
        with pytest.raises(OSError):
            (destination / "data").unlink()
        with pytest.raises(OSError):
            (destination / "data").write_bytes(b"replacement")
    assert (destination / "data").read_bytes() == b"ours"


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions require no symlink privilege")
@pytest.mark.parametrize("depth", [0, 2])
def test_windows_junction_ancestor_refused(tmp_path, depth):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "junction"
    # Fixed command with argument-list invocation, only disposable test paths.
    subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(real)],
                   check=True, capture_output=True)
    try:
        nested = alias
        for index in range(depth):
            nested = nested / str(index)
            nested.mkdir()
        with pytest.raises((RescueError, OSError)):
            with private_output(nested / "new"):
                pytest.fail("junction followed")
        assert not (nested / "new").exists()
    finally:
        alias.rmdir()  # remove junction itself, never recurse through it


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL")
def test_windows_untrusted_write_acl_refused(tmp_path):
    import win32security as security
    shared = tmp_path / "shared"
    shared.mkdir()
    sd = security.GetFileSecurity(str(shared), security.DACL_SECURITY_INFORMATION)
    acl = sd.GetSecurityDescriptorDacl()
    acl.AddAccessAllowedAce(security.ACL_REVISION, 0x001F01FF,
                            security.ConvertStringSidToSid("S-1-1-0"))
    security.SetNamedSecurityInfo(str(shared), security.SE_FILE_OBJECT,
                                  security.DACL_SECURITY_INFORMATION,
                                  None, None, acl, None)
    with pytest.raises(RescueError, match="Shared writable"):
        with private_output(shared / "new"):
            pytest.fail("untrusted writable ACL accepted")
    assert not (shared / "new").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows protected DACL")
def test_windows_private_dacl_applied_at_creation(tmp_path):
    import win32security as security
    from research.rescue_output_windows import _trusted_sids
    current, _ = _trusted_sids()
    destination = tmp_path / "new"
    with private_output(destination) as output:
        output.write("data", b"private")
    for path in (destination, destination / "data"):
        sd = security.GetFileSecurity(str(path), security.DACL_SECURITY_INFORMATION)
        assert sd.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED
        acl = sd.GetSecurityDescriptorDacl()
        assert {security.ConvertSidToStringSid(acl.GetAce(i)[2])
                for i in range(acl.GetAceCount())} == {current, "S-1-5-18", "S-1-5-32-544"}
