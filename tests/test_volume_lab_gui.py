"""Tk frontend smoke: do not require a display on headless CI runners."""
from __future__ import annotations

import os

import pytest


@pytest.mark.skipif(os.name != "nt" and not os.environ.get("DISPLAY"),
                    reason="Tk requires graphical display")
def test_volume_lab_window_has_six_explicit_no_disk_operations():
    import tkinter as tk
    from krypta.volume_lab_gui import VolumeLabWindow
    root = tk.Tk()
    root.withdraw()
    try:
        win = VolumeLabWindow(root)
        try:
            win.update_idletasks()
            assert set(win.forms) == {
                "create", "verify", "import", "export", "rotate", "recover",
            }
            assert len(win.buttons) == 6
            assert "nie dyski" in win.title()
            assert "receipt" in win.forms["verify"]
            assert "recovery" in win.forms["verify"]
            assert "old_recovery" in win.forms["rotate"]
        finally:
            win.destroy()
    finally:
        root.destroy()


@pytest.mark.skipif(os.name != "nt" and not os.environ.get("DISPLAY"),
                    reason="Tk requires graphical display")
def test_volume_lab_sidebar_opens_separate_window_without_enabling_disk_shield():
    from krypta.gui import KryptaApp
    from krypta.volume_lab_gui import VolumeLabWindow
    app = KryptaApp()
    try:
        app.update_idletasks()
        assert "Volume Lab" in app.module_buttons[5]["text"]
        app._show_module(5)
        app.update_idletasks()
        labs = [w for w in app.winfo_children() if isinstance(w, VolumeLabWindow)]
        assert len(labs) == 1
        assert app.active_module == 0
        assert app.module_status["text"].startswith("●")
        labs[0].destroy()
    finally:
        app.destroy()


@pytest.mark.skipif(os.name != "nt" and not os.environ.get("DISPLAY"),
                    reason="Tk requires graphical display")
def test_volume_lab_receipt_save_never_overwrites_and_root_close_guard(monkeypatch, tmp_path):
    from krypta.gui import KryptaApp
    from krypta.volume_lab_gui import VolumeLabWindow
    import krypta.volume_lab_gui as ui
    app = KryptaApp()
    try:
        app._show_module(5)
        lab = next(w for w in app.winfo_children() if isinstance(w, VolumeLabWindow))
        success_messages = []
        denied_messages = []
        monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)
        monkeypatch.setattr(ui.messagebox, "showinfo",
                            lambda *a, **k: success_messages.append(True))
        monkeypatch.setattr(ui.messagebox, "showerror",
                            lambda *a, **k: denied_messages.append(True))
        monkeypatch.setattr(ui.messagebox, "askyesno", lambda *a, **k: True)
        destination = tmp_path / "trusted-new.receipt"
        monkeypatch.setattr(ui.filedialog, "asksaveasfilename",
                            lambda *a, **k: str(destination))
        receipt = "a" * 64
        lab._finish(True, {"receipt": receipt, "operation": "test"})
        assert str(lab.save_receipt_button["state"]) == "normal"
        lab._save_receipt()
        assert destination.read_bytes() == (receipt + "\n").encode()
        assert success_messages
        lab._save_receipt()
        assert denied_messages
        assert destination.read_bytes() == (receipt + "\n").encode()

        # Changing desktop language must not destroy an open volume window.
        from krypta.i18n import LANGUAGES
        other = next(name for code, name in LANGUAGES.items()
                     if code != app.language_code)
        app.language_name.set(other)
        app._language_changed()
        assert lab.winfo_exists()

        lab.busy = True
        monkeypatch.setattr("krypta.gui.messagebox.showwarning",
                            lambda *a, **k: denied_messages.append(True))
        app._close_workstation()
        assert app.winfo_exists()
        assert denied_messages
        lab.busy = False
        lab.destroy()
    finally:
        if app.winfo_exists():
            app.destroy()



@pytest.mark.skipif(os.name != "nt" and not os.environ.get("DISPLAY"),
                    reason="Tk requires graphical display")
def test_readonly_receipt_is_not_falsely_reported_as_changed(monkeypatch):
    import tkinter as tk
    import krypta.volume_lab_gui as ui

    root = tk.Tk()
    root.withdraw()
    lab = ui.VolumeLabWindow(root)
    warnings, errors = [], []
    monkeypatch.setattr(ui.messagebox, "showwarning",
                        lambda *args, **kwargs: warnings.append(args))
    monkeypatch.setattr(ui.messagebox, "showerror",
                        lambda *args, **kwargs: errors.append(args))
    try:
        receipt = "a" * 64
        lab._finish(True, {"operation": "Authenticated image verification",
                           "receipt": receipt, "receipt_changed": False})
        assert warnings == []
        assert lab.latest_receipt == receipt

        lab._finish(True, {"operation": "Imported encrypted file",
                           "receipt": "b" * 64, "receipt_changed": True})
        assert len(warnings) == 1
        assert lab.latest_receipt == "b" * 64

        lab._finish(False, {
            "result": "Post-commit check failed",
            "UNVERIFIED_RECEIPT_RECOVERY_ONLY": "c" * 64,
        })
        assert errors
        assert lab.latest_receipt is None
        assert str(lab.save_receipt_button["state"]) == "disabled"
        assert "UNVERIFIED_RECEIPT_RECOVERY_ONLY" in lab.result.get("1.0", "end")
    finally:
        lab.destroy()
        root.destroy()
