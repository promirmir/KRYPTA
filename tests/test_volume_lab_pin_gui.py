"""Desktop sealed-receipt pin regression tests (never operate on real drives)."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

import krypta.volume_lab_gui as ui


@pytest.mark.parametrize("action", ["pin_create", "pin_verify"])
def test_pin_actions_delegate_without_silent_enrollment(monkeypatch, action):
    calls = []

    def seal(image, envelope, receipt, destination, *, password=None, recovery=None):
        calls.append(("pin_create", image, envelope, receipt, destination, password, recovery))
        return {"operation": "pin", "seal_sha256": "b" * 64,
                "trust_promoted": False, "read_only_verified": True,
                "receipt_changed": False}

    def verify(image, envelope, path, seal_value, *, password=None, recovery=None):
        calls.append(("pin_verify", image, envelope, path, seal_value, password, recovery))
        return {"operation": "verify", "status": "SEALED_PIN_MATCH",
                "receipt": "a" * 64, "trust_promoted": False,
                "read_only_verified": True, "receipt_changed": False}

    monkeypatch.setattr(ui.operations, "seal_existing_trusted_receipt", seal)
    monkeypatch.setattr(ui.operations, "verify_sealed_receipt_image", verify)
    results = []
    fake = SimpleNamespace(
        after=lambda delay, callback: callback(),
        _finish=lambda ok, value: results.append((ok, value)),
    )
    fields = {
        "image": "/tmp/synthetic.kpv", "envelope": "/tmp/synthetic.pvkey",
        "receipt": "a" * 64, "pin_path": "/tmp/isolated/baseline.kpin",
        "trusted_seal": "b" * 64, "password": "do-not-log-password",
        "recovery": "",
    }
    ui.VolumeLabWindow._worker(fake, action, fields)
    assert fields == {}
    assert len(calls) == 1
    assert calls[0][0] == action
    assert calls[0][-2:] == ("do-not-log-password", None)
    assert results[0][0] is True
    assert results[0][1]["trust_promoted"] is False
    assert "do-not-log-password" not in str(results)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get("DISPLAY"),
                    reason="Tk requires graphical display")
def test_pin_verify_cannot_export_its_receipt_as_newly_trusted(monkeypatch):
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    win = ui.VolumeLabWindow(root)
    try:
        win._finish(True, {
            "operation": "Read-only verification",
            "status": "SEALED_PIN_MATCH",
            "receipt": "b" * 64,
            "trust_promoted": False,
            "read_only_verified": True,
            "receipt_changed": False,
        })
        assert win.latest_receipt is None
        assert str(win.save_receipt_button["state"]) == "disabled"
        assert "SEALED_PIN_MATCH" in win.result.get("1.0", "end")
    finally:
        win.destroy()
        root.destroy()


@pytest.mark.skipif(os.name != "nt" and not os.environ.get("DISPLAY"),
                    reason="Tk requires graphical display")
def test_pin_enrollment_is_cancelable_before_any_worker_runs(monkeypatch):
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    win = ui.VolumeLabWindow(root)
    warnings = []
    try:
        fields = win.forms["pin_create"]
        for key in ("image", "envelope", "receipt", "pin_path", "password"):
            fields[key].set("a" * 64 if key == "receipt" else "dummy")
        monkeypatch.setattr(ui.messagebox, "askyesno", lambda *args, **kwargs: False)
        monkeypatch.setattr(ui.messagebox, "showwarning",
                            lambda *args, **kwargs: warnings.append(args))
        win._start("pin_create")
        assert not win.busy
        assert fields["password"].get() == ""
        assert all(str(button["state"]) == "normal" for button in win.buttons)
    finally:
        win.destroy()
        root.destroy()
