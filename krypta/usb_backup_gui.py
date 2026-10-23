"""Linux-only, explicitly opted-in encrypted USB backup window.

Uses the existing read-only physical_backup service; never writes to source
block devices. This is an encrypted COPY, not whole-device in-place encryption.
"""
from __future__ import annotations

import json
import platform
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .physical_backup import backup_linux_usb_encrypted
from .physical_disks import inspect_physical_disks


def usb_backup_candidates(report: dict) -> list[str]:
    """Display eligible read-only sources; backend repeats all safety checks."""
    if (type(report) is not dict or report.get("platform") != "Linux" or
            report.get("physical_disk_encryption_enabled") is not False or
            type(report.get("devices")) is not list):
        return []
    result = []
    for dev in report["devices"]:
        if (type(dev) is dict and type(dev.get("device")) is str and
                dev["device"].startswith("/dev/") and
                type(dev.get("bus")) is str and dev["bus"].lower() == "usb" and
                dev.get("inspection_complete") is True and
                dev.get("system_or_boot") is False and
                dev.get("mounted") is False and
                dev.get("write_authorized") is False and
                type(dev.get("bytes")) is int and dev["bytes"] >= 4096):
            result.append(dev["device"])
    return sorted(set(result))


class LinuxUSBBackupWindow(tk.Toplevel):
    """No source writes, no implicit device selection, no destructive actions."""

    def __init__(self, master):
        if platform.system() != "Linux":
            raise RuntimeError("The USB encrypted backup UI is Linux-only")
        super().__init__(master)
        self.title("KRYPTA / LINUX USB BACKUP — SOURCE READ ONLY")
        self.geometry("780x580")
        self.minsize(690, 510)
        self.configure(bg="#0D1812")
        self.busy = False
        self._candidates = []
        self.device = tk.StringVar()
        self.destination = tk.StringVar()
        self.keyfile = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm = tk.StringVar()
        pl = getattr(master, "language_code", "en") == "pl"
        self._pl = pl
        self._label(
            "KRYPTA / " + ("ZASZYFROWANA KOPIA USB (ODCZYT)" if pl else
                           "ENCRYPTED USB BACKUP (READ ONLY)"), 17, "#8CF5A7"
        ).pack(anchor="w", padx=20, pady=(20, 9))
        self._label(
            ("To NIE szyfruje dysku w miejscu. Źródło nie jest modyfikowane. "
             "Nie jest to spójna migawka — testuj odtworzenie przed użyciem."
             if pl else
             "NOT in-place encryption. Source disk is never modified. "
             "Not a consistent snapshot — test recovery before relying on this copy."),
            10, "#E7C37D", wraplength=720
        ).pack(anchor="w", padx=20, pady=(0, 12))
        area = tk.Frame(self, bg="#0D1812")
        area.pack(fill="x", padx=20)
        self._label("USB / /dev/sdX", 10).pack(in_=area, anchor="w")
        line = tk.Frame(area, bg="#0D1812")
        line.pack(fill="x", pady=(3, 10))
        self.pick_device = ttk.Combobox(line, textvariable=self.device, state="readonly",
                                        values=[], width=54)
        self.pick_device.pack(side="left", fill="x", expand=True)
        self.scan_button = ttk.Button(line, text="SCAN R/O", command=self._scan)
        self.scan_button.pack(side="left", padx=(10, 0))
        self._path_field(area, "Encrypted destination / .krypta",
                         self.destination, self._select_destination)
        self._path_field(area, "Independent secret keyfile",
                         self.keyfile, self._select_keyfile)
        self._label("Password / hasło (12+ znaków)", 10).pack(in_=area, anchor="w")
        self.pass_entry = ttk.Entry(area, textvariable=self.password, show="•")
        self.pass_entry.pack(fill="x", pady=(3, 10))
        self._label("Repeat password / powtórz hasło", 10).pack(in_=area, anchor="w")
        self.confirm_entry = ttk.Entry(area, textvariable=self.confirm, show="•")
        self.confirm_entry.pack(fill="x", pady=(3, 14))
        self.start_button = ttk.Button(
            area, text=("UTWÓRZ KOPIĘ — TYLKO ODCZYT Z USB" if pl else
                        "CREATE ENCRYPTED COPY — READ USB ONLY"),
            command=self._start,
        )
        self.start_button.pack(anchor="w", pady=(4, 10))
        self.state_label = self._label(
            ("Wybierz SKANUJ i urządzenie USB." if pl else
             "Scan and explicitly select an unmounted USB source."),
            10, "#8CF5A7", wraplength=720
        )
        self.state_label.pack(fill="x", padx=20, pady=(0, 10))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._scan()

    def _label(self, value, size, color="#DCEBE0", wraplength=None):
        return tk.Label(self, text=value, bg="#0D1812", fg=color,
                        font=("DejaVu Sans", size), justify="left",
                        anchor="w", wraplength=wraplength or 740)

    def _path_field(self, parent, title, variable, callback):
        tk.Label(parent, text=title, bg="#0D1812", fg="#DCEBE0",
                 anchor="w").pack(fill="x")
        row = tk.Frame(parent, bg="#0D1812")
        row.pack(fill="x", pady=(3, 10))
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="...", command=callback).pack(side="left", padx=(10, 0))

    def _select_destination(self):
        if self.busy:
            return
        selected = filedialog.asksaveasfilename(
            parent=self, title="New encrypted archive",
            defaultextension=".krypta", filetypes=[("KRYPTA", "*.krypta")]
        )
        if selected:
            self.destination.set(selected)

    def _select_keyfile(self):
        if self.busy:
            return
        selected = filedialog.askopenfilename(
            parent=self, title="Existing independent secret keyfile"
        )
        if selected:
            self.keyfile.set(selected)

    def _scan(self):
        if self.busy:
            return
        self._candidates = []
        self.device.set("")
        self.pick_device.configure(values=[], state="disabled")
        self.scan_button.configure(state="disabled")
        self.state_label.configure(text="Scanning USB inventory (read only)...")
        def worker():
            try:
                candidates = usb_backup_candidates(inspect_physical_disks())
                result = (candidates, None)
            except Exception:
                result = ([], "Cannot inspect USB devices safely / Brak bezpiecznej listy USB")
            def done():
                if not self.winfo_exists():
                    return
                self._candidates = result[0]
                self.pick_device.configure(values=self._candidates, state="readonly")
                self.scan_button.configure(state="normal")
                self.state_label.configure(
                    text=(result[1] or (
                        "Select unmounted USB / Wybierz odmontowany dysk USB."
                        if result[0] else
                        "No eligible USB source. Unmount it and scan again."
                    ))
                )
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _start(self):
        if self.busy:
            return
        device = self.device.get()
        dest = self.destination.get().strip()
        key = self.keyfile.get().strip()
        secret = self.password.get()
        confirmation = self.confirm.get()
        if (device not in self._candidates or not dest.endswith(".krypta") or
                not key or not Path(key).is_file() or not secret or
                len(secret) < 12 or secret != confirmation or
                Path(dest).exists() or not Path(dest).parent.is_dir()):
            messagebox.showerror(
                "KRYPTA",
                "Check USB choice, NEW .krypta output, keyfile and two matching "
                "12+ character passwords. No file was created.",
                parent=self,
            )
            return
        if not messagebox.askyesno(
            "KRYPTA / READ-ONLY USB",
            "Source: " + device + "\nEncrypted file: " + dest +
            "\n\nThis copies the ENTIRE unmounted disk without modifying it. "
            "No crash-consistent snapshot is guaranteed. Continue?",
            parent=self,
        ):
            return
        self.busy = True
        self.password.set("")
        self.confirm.set("")
        self.pick_device.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.state_label.configure(
            text="ENCRYPTING USB COPY — DO NOT CLOSE / TRWA ZAPIS KOPII",
            fg="#E7C37D",
        )
        def worker():
            try:
                info = backup_linux_usb_encrypted(device, dest, secret, key)
                success, report = True, info
            except Exception as exc:
                success, report = False, {"error": str(exc)}
            def done():
                if not self.winfo_exists():
                    return
                self.busy = False
                self.pick_device.configure(state="readonly")
                self.scan_button.configure(state="normal")
                self.start_button.configure(state="normal")
                self.state_label.configure(
                    text=("Encrypted archive created; independently test its recovery."
                          if success else "Backup failed. Original USB was NOT written."),
                    fg="#8CF5A7" if success else "#EBA69F",
                )
                if success:
                    messagebox.showinfo("KRYPTA / BACKUP",
                                        json.dumps(report, indent=2), parent=self)
                else:
                    messagebox.showerror("KRYPTA / BACKUP", report["error"], parent=self)
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _close(self):
        if self.busy:
            messagebox.showwarning(
                "KRYPTA", "Encrypted copy is running; do not close now.",
                parent=self,
            )
            return
        self.destroy()


def open_usb_backup_dialog(master):
    """One window per request. No auto-selection or background encryption."""
    return LinuxUSBBackupWindow(master)
