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
