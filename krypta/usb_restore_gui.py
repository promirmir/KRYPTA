"""Desktop recovery drill for an encrypted USB archive; NEVER writes raw disks."""
from __future__ import annotations

import json
from pathlib import Path
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .physical_restore import restore_usb_archive_to_image


class USBImageRestoreWindow(tk.Toplevel):
    """Explicit user action with plaintext-image warning and close guard."""

    def __init__(self, master):
        super().__init__(master)
        self.title("KRYPTA / VERIFIED ARCHIVE RECOVERY TO .IMG")
        self.geometry("720x460")
        self.minsize(620, 430)
        self.configure(bg="#0D1812")
        self.busy = False
        self.archive = tk.StringVar()
        self.destination = tk.StringVar()
        self.keyfile = tk.StringVar()
        self.password = tk.StringVar()
        pl = getattr(master, "language_code", "en") == "pl"
        label = lambda text: tk.Label(
            self, text=text, bg="#0D1812", fg="#DCEBE0",
            justify="left", anchor="w", wraplength=670
        )
        label("PRZYWRÓĆ ARCHIWUM USB DO PLIKU .IMG" if pl else
              "RESTORE USB ARCHIVE TO A NEW .IMG").pack(
            anchor="w", padx=18, pady=(18, 7)
        )
        label(
            "Tworzy jawny plik .img na wskazanym dysku. NIE zapisuje na USB. "
            "Wybierz bezpieczny, zaszyfrowany dysk docelowy." if pl else
            "Creates a plaintext .img file on the selected destination disk. "
            "NEVER writes USB; select an encrypted destination."
        ).pack(anchor="w", padx=18, pady=(0, 12))
        for title, variable, callback in (
            ("KRYPTA-FILE/2 archive / backup.krypta", self.archive, self._pick_archive),
            ("NEW regular image / restored.img", self.destination, self._pick_destination),
            ("Independent secret keyfile", self.keyfile, self._pick_keyfile),
        ):
            label(title).pack(anchor="w", padx=18)
            line = tk.Frame(self, bg="#0D1812")
            line.pack(fill="x", padx=18, pady=(0, 7))
            ttk.Entry(line, textvariable=variable).pack(
                side="left", fill="x", expand=True)
            ttk.Button(line, text="...", command=callback).pack(side="left", padx=(8, 0))
        label("Password / Hasło").pack(anchor="w", padx=18)
        ttk.Entry(self, textvariable=self.password, show="•").pack(
            fill="x", padx=18, pady=(0, 12))
        self.start_button = ttk.Button(
            self, text=("SPRAWDŹ I PRZYWRÓĆ .IMG" if pl else
                        "VERIFY AND RESTORE .IMG"), command=self._start
        )
        self.start_button.pack(anchor="w", padx=18)
        self.status = label("Wybierz archiwum, nowy .img i klucz." if pl else
                            "Select archive, new .img path and keyfile.")
        self.status.pack(fill="x", padx=18, pady=(12, 0))
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _pick_archive(self):
        if not self.busy:
            value = filedialog.askopenfilename(
                parent=self, filetypes=[("KRYPTA", "*.krypta")])
            if value:
                self.archive.set(value)

    def _pick_destination(self):
        if not self.busy:
            value = filedialog.asksaveasfilename(
                parent=self, defaultextension=".img",
                filetypes=[("Disk image", "*.img")])
            if value:
                self.destination.set(value)

    def _pick_keyfile(self):
        if not self.busy:
            value = filedialog.askopenfilename(parent=self)
            if value:
                self.keyfile.set(value)

    def _start(self):
        if self.busy:
            return
        source = self.archive.get().strip()
        destination = self.destination.get().strip()
        keyfile = self.keyfile.get().strip()
        secret = self.password.get()
        if (not source.lower().endswith(".krypta") or
                not Path(source).is_file() or
                not destination.lower().endswith(".img") or
                Path(destination).exists() or
                not Path(destination).parent.is_dir() or
                not keyfile or not Path(keyfile).is_file() or not secret):
            messagebox.showerror("KRYPTA",
                                 "Select a .krypta archive, a NEW .img, keyfile and password.",
                                 parent=self)
            return
        if not messagebox.askyesno(
            "KRYPTA / PLAINTEXT IMAGE",
            "The recovered .img contains PLAINTEXT, and will be stored on the "
            "selected filesystem. No physical USB will be written. Continue?",
            parent=self
        ):
            return
        self.busy = True
        self.password.set("")
        self.start_button.configure(state="disabled")
        self.status.configure(text="Authenticating, restoring and verifying...")

        def work():
            try:
                outcome = restore_usb_archive_to_image(
                    source, destination, secret, keyfile
                )
                success = True
            except Exception as exc:
                outcome, success = str(exc), False

            def done():
                if not self.winfo_exists():
                    return
                self.busy = False
                self.start_button.configure(state="normal")
                self.status.configure(text=(
                    "Restoration verified; plaintext .img published."
                    if success else "Restore failed; original archive unchanged."
                ))
                if success:
                    messagebox.showinfo("KRYPTA / RECOVERY",
                                        json.dumps(outcome, indent=2), parent=self)
                else:
                    messagebox.showerror("KRYPTA / RECOVERY", outcome, parent=self)
            self.after(0, done)

        threading.Thread(target=work, daemon=True).start()

    def _close(self):
        if self.busy:
            messagebox.showwarning("KRYPTA",
                                   "Archive recovery is running; do not close.",
                                   parent=self)
            return
        self.destroy()


def open_usb_restore_dialog(master):
    return USBImageRestoreWindow(master)
