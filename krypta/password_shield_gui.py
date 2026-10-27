"""Desktop Password Shield window for KRYPTA-FILE/2 encrypted secrets.

Passwords are not written to plaintext files, passed on command lines or put
on the clipboard by this module. The process / Tk widgets still hold plaintext
temporarily: do not claim OS-compromise resistance or audited memory erasure.
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .core import CryptoError
from .password_shield import (
    VaultError, create_vault, list_entries, store_entry,
    read_entry, remove_entry,
)


class PasswordShieldWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("KRYPTA / PASSWORD SHIELD (DESKTOP)")
        self.geometry("780x650")
        self.minsize(650, 590)
        self.configure(bg="#0D1812")
        self.busy = False
        self.vault = tk.StringVar()
        self.keyfile = tk.StringVar()
        self.master_pass = tk.StringVar()
        self.entry_name = tk.StringVar()
        self.entry_user = tk.StringVar()
        self.entry_secret = tk.StringVar()
        self.entry_note = tk.StringVar()
        self._reveal_timer = None
        pl = getattr(master, "language_code", "en") == "pl"

        def label(text):
            return tk.Label(self, text=text, justify="left", anchor="w",
                            wraplength=710, bg="#0D1812", fg="#D7EDDB")
        label("PASSWORD SHIELD / SEJF HASEŁ" if pl else
              "PASSWORD SHIELD / OFFLINE SECRETS VAULT").pack(
                  fill="x", padx=20, pady=(16, 5))
        label("Lokalny sejf szyfrowany KRYPTA-FILE/2. Hasło minimum 12 znaków. "
              "Brak automatycznej synchronizacji i sprzętowej ochrony PIN-u. "
              "Regularnie wykonuj kopię .ksecrets i pliku klucza." if pl else
              "Local KRYPTA-FILE/2 encrypted vault. Master passphrase >=12 "
              "characters. No automatic sync or hardware PIN attempt limit. "
              "Back up the .ksecrets and independent keyfile.").pack(
                  fill="x", padx=20, pady=(0, 12))

        def row(text, variable, chooser=None, secret=False):
            label(text).pack(fill="x", padx=20)
            line = tk.Frame(self, bg="#0D1812")
            line.pack(fill="x", padx=20, pady=(0, 8))
            entry = ttk.Entry(line, textvariable=variable,
                              show="•" if secret else "")
            entry.pack(side="left", fill="x", expand=True)
            if chooser is not None:
                ttk.Button(line, text="...", command=chooser).pack(
                    side="left", padx=(8, 0))
            return entry

        row("Encrypted vault / Sejf (*.ksecrets)", self.vault, self._pick_vault)
        row("Independent keyfile (optional) / Klucz dodatkowy", self.keyfile,
            self._pick_key)
        row("Master password / Hasło główne (>=12)", self.master_pass, secret=True)
        row("Entry title / Nazwa wpisu", self.entry_name)
        row("Username / Login", self.entry_user)
        row("Secret / Hasło wpisu", self.entry_secret, secret=True)
        row("Notes / Notatka", self.entry_note)

        bar = tk.Frame(self, bg="#0D1812")
        bar.pack(fill="x", padx=20, pady=(7, 5))
        self.controls = []
        for title, action in (
            ("CREATE VAULT", self._create),
            ("LIST TITLES", self._list),
            ("ADD ENTRY", self._add),
            ("REVEAL 15s", self._reveal),
            ("DELETE ENTRY", self._remove),
        ):
            button = ttk.Button(bar, text=title, command=action)
            button.pack(side="left", padx=(0, 7))
            self.controls.append(button)
        self.display = tk.Text(self, height=5, state="disabled", wrap="word",
                               bg="#11251A", fg="#D7EDDB", relief="flat",
                               padx=12, pady=10)
        self.display.pack(fill="both", expand=True, padx=20, pady=(7, 16))
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _pick_vault(self):
        if self.busy:
            return
        value = filedialog.asksaveasfilename(parent=self,
            defaultextension=".ksecrets", filetypes=[("KRYPTA Vault", "*.ksecrets")])
        if value:
            self.vault.set(value)

    def _pick_key(self):
        if self.busy:
            return
        value = filedialog.askopenfilename(parent=self)
        if value:
            self.keyfile.set(value)

    def _clear_display(self):
        if self._reveal_timer is not None:
            self.after_cancel(self._reveal_timer)
            self._reveal_timer = None
        self.display.configure(state="normal")
        self.display.delete("1.0", "end")
        self.display.configure(state="disabled")

    def _display(self, text, secret=False):
        self._clear_display()
        self.display.configure(state="normal")
        self.display.insert("1.0", text)
        self.display.configure(state="disabled")
        if secret:
            self._reveal_timer = self.after(15_000, self._clear_display)

    def _task(self, action, requires_entry=False, reveal=False):
        if self.busy:
            return
        vault = self.vault.get().strip()
        key = self.keyfile.get().strip() or None
        password = self.master_pass.get()
        title = self.entry_name.get()
        user = self.entry_user.get()
        entry_secret = self.entry_secret.get()
        note = self.entry_note.get()
        if not vault or not password or (requires_entry and not title):
            messagebox.showerror("KRYPTA", "Enter vault path, master passphrase and entry title.", parent=self)
            return
        if action == "remove" and not messagebox.askyesno(
                "KRYPTA", "Delete the selected entry? This modifies the encrypted vault.",
                parent=self):
            return
        if reveal and not messagebox.askyesno(
                "KRYPTA", "Reveal secret for 15 seconds on screen? Avoid screen recording.",
                parent=self):
            return
        self._clear_display()
        self.busy = True
        for button in self.controls:
            button.configure(state="disabled")
        # Discard sensitive fields from Tk before running the worker.
        self.master_pass.set("")
        self.entry_secret.set("")

        def work():
            try:
                if action == "create":
                    create_vault(vault, password, key)
                    result = "Created a new encrypted vault."
                elif action == "list":
                    titles = list_entries(vault, password, key)
                    result = "Entry titles:\n" + "\n".join(titles or ["(empty)"])
                elif action == "add":
                    store_entry(vault, password, title, user, entry_secret, note,
                                keyfile=key)
                    result = "New encrypted entry saved. Back up the vault."
                elif action == "remove":
                    remove_entry(vault, password, title, keyfile=key)
                    result = "Encrypted entry removed. Back up the vault."
                elif action == "reveal":
                    record = read_entry(vault, password, title, keyfile=key)
                    result = ("Title: " + record["title"] + "\nLogin: " +
                              record["username"] + "\nSecret: " +
                              record["secret"] + "\nNote: " + record["note"])
                else:
                    raise VaultError("Unsupported operation")
                ok = True
            except (VaultError, CryptoError, ValueError, OSError) as exc:
                result = "Vault operation refused: " + str(exc)
                ok = False
            except Exception:
                result = "Vault operation failed; original encrypted file was not intentionally changed."
                ok = False

            def finish():
                if not self.winfo_exists():
                    return
                self.busy = False
                for button in self.controls:
                    button.configure(state="normal")
                self._display(result, secret=ok and reveal)
                if not ok:
                    messagebox.showerror("KRYPTA / PASSWORD SHIELD", result, parent=self)
            self.after(0, finish)

        threading.Thread(target=work, daemon=True).start()

    def _create(self):
        self._task("create")

    def _list(self):
        self._task("list")

    def _add(self):
        self._task("add", requires_entry=True)

    def _remove(self):
        self._task("remove", requires_entry=True)

    def _reveal(self):
        self._task("reveal", requires_entry=True, reveal=True)

    def _close(self):
        if self.busy:
            messagebox.showwarning("KRYPTA", "Encryption in progress; cannot close.", parent=self)
            return
        self._clear_display()
        self.master_pass.set("")
        self.entry_secret.set("")
        self.destroy()


def open_password_shield(master):
    return PasswordShieldWindow(master)
