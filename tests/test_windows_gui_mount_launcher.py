"""Non-destructive tests for desktop-to-WinFsp hand-off."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from krypta import windows_mount_launcher as mount


@pytest.fixture
def inputs(tmp_path):
    image = tmp_path / "synthetic.kpv"
    envelope = tmp_path / "synthetic.pvkey"
    recovery = tmp_path / "offline.secret"
    for path in (image, envelope, recovery):
        path.write_bytes(b"synthetic-only")
    return image, envelope, recovery


def command(inputs, tmp_path, **overrides):
    image, envelope, recovery = inputs
    app = tmp_path / "KRYPTA.exe"
    app.write_bytes(b"synthetic-only")
    helper = tmp_path / mount.HELPER_NAME
    helper.write_bytes(b"synthetic-only")
    kwargs = {
        "packaged": True, "app_executable": app,
        "image": str(image), "envelope": str(envelope),
        "receipt": "a" * 64, "drive": "z:", "recovery": str(recovery)
    }
    kwargs.update(overrides)
    return mount.build_mount_command(**kwargs)


def test_gui_command_uses_only_sibling_helper_and_no_password(inputs, tmp_path):
    argv, cwd = command(inputs, tmp_path)
    assert argv[0] == str(tmp_path / mount.HELPER_NAME)
    assert cwd == tmp_path
    assert argv[argv.index("--drive") + 1] == "Z:"
    assert argv[argv.index("--expected-receipt") + 1] == "a" * 64
    assert argv[argv.index("--recovery") + 1] == str(inputs[2])
    assert "--password" not in argv
    assert "--acknowledge-test-only" in argv


@pytest.mark.parametrize("bad", ["", "C:", "A:", "z:\\", "Z:dir", "\\\\.\\PhysicalDrive0"])
def test_gui_rejects_unsafe_drive(inputs, tmp_path, bad):
    with pytest.raises(ValueError, match="drive"):
        command(inputs, tmp_path, drive=bad)


@pytest.mark.parametrize("bad", ["", "A" * 64, "a" * 63, "a" * 65, "invalid"])
def test_gui_rejects_unsafe_receipt(inputs, tmp_path, bad):
    with pytest.raises(ValueError, match="receipt"):
        command(inputs, tmp_path, receipt=bad)


def test_gui_requires_separate_existing_helper(inputs, tmp_path):
    command(inputs, tmp_path)
    (tmp_path / mount.HELPER_NAME).unlink()
    with pytest.raises(RuntimeError, match="next to"):
        command(inputs, tmp_path)


def test_gui_rejects_image_key_hardlink_and_symlink(inputs, tmp_path):
    image, envelope, _ = inputs
    alias = tmp_path / "alias.pvkey"
    try:
        alias.hardlink_to(image)
    except OSError:
        pytest.skip("Hardlinks unavailable on this filesystem")
    with pytest.raises(ValueError, match="Hardlink"):
        command(inputs, tmp_path, envelope=str(alias))
    alias.unlink()
    try:
        alias.symlink_to(envelope)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ValueError, match="non-symlink"):
        command(inputs, tmp_path, envelope=str(alias))


def test_gui_password_is_entered_only_in_the_child_console(monkeypatch, inputs, tmp_path):
    from krypta import volume_lab_gui as ui
    argv, cwd = command(inputs, tmp_path, recovery="")
    called = []
    monkeypatch.setattr(mount, "launch_readonly_mount",
                        lambda **kw: called.append(kw))
    monkeypatch.setattr(ui.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showerror",
                        lambda *a, **k: pytest.fail("mount launch failed"))
    class Field:
        def __init__(self, value):
            self.value = value
        def get(self):
            return self.value
    fake = SimpleNamespace(
        busy=False, forms={"mount_readonly": {
            "image": Field(str(inputs[0])), "envelope": Field(str(inputs[1])),
            "receipt": Field("a" * 64), "drive": Field("z:"),
            "recovery": Field("")
        }}, status=SimpleNamespace(set=lambda value: None),
    )
    ui.VolumeLabWindow._start_readonly_mount(fake)
    assert len(called) == 1
    assert called[0]["drive"] == "z:"
    assert "password" not in called[0]
