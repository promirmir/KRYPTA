"""Opt-in graphical operations on disposable KRYPTA-PFS/2 file images.

No OS disk enumeration, partition APIs, transparent mount or system encryption.
An independent receipt is mandatory for EVERY operation on an existing image.
Never call Tk from a worker thread except via root.after, as the main GUI does.
"""
from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import volume_lab as operations

# (id, human-readable label, is_secret, destination_filename)
CREATE = [
    ("image", "Nowy obraz .kpv", False, True),
    ("envelope", "Nowy plik kluczy .pvkey", False, True),
    ("recovery", "Nowy ODDZIELNY klucz odzyskiwania", False, True),
    ("password", "Długie hasło (minimum 12 znaków)", True, False),
    ("confirmation", "Powtórz hasło", True, False),
]
OPEN = [
    ("image", "Istniejący zaszyfrowany obraz .kpv", False, False),
    ("envelope", "Istniejący plik kluczy .pvkey", False, False),
    ("receipt", "Aktualny ZAUFANY receipt (64 znaki hex)", False, False),
    ("password", "Hasło (lub użyj pola klucza odzyskiwania)", True, False),
    ("recovery", "ALBO plik klucza odzyskiwania", False, False),
]
ROTATE = OPEN[:3] + [
    ("old_password", "STARE hasło (albo stary klucz poniżej)", True, False),
    ("old_recovery", "ALBO stary klucz odzyskiwania", False, False),
    ("new_image", "NOWY obraz docelowy .kpv", False, True),
    ("new_envelope", "NOWY plik kluczy .pvkey", False, True),
    ("new_recovery", "NOWY klucz odzyskiwania", False, True),
    ("new_password", "NOWE długie hasło", True, False),
    ("confirmation", "Powtórz nowe hasło", True, False),
]
RECOVER = [
    ("envelope", "Istniejący plik kluczy .pvkey", False, False),
    ("recovery", "Istniejący klucz odzyskiwania", False, False),
    ("new_envelope", "NOWY plik .pvkey (bez nadpisywania)", False, True),
    ("password", "Nowe długie hasło", True, False),
    ("confirmation", "Powtórz hasło", True, False),
]
FORMS = [
    ("Utwórz", CREATE, "create"),
    ("Weryfikuj", OPEN, "verify"),
    ("Dodaj plik", OPEN + [("source", "Zwykły plik do zaszyfrowania (maks. 32 MiB)", False, False)], "import"),
    ("Eksportuj", OPEN + [
        ("name", "Nazwa pliku WEWNĄTRZ zaszyfrowanego obrazu", False, False),
        ("output", "NOWY plik wyjściowy — JAWNY", False, True),
    ], "export"),
    ("Zmień klucz", ROTATE, "rotate"),
    ("Odzyskaj hasło", RECOVER, "recover"),
]


class VolumeLabWindow(tk.Toplevel):
    """Separate module so existing selected-file vault is not altered."""

    def __init__(self, master):
        super().__init__(master)
        self.title("KRYPTA / Volume Lab — zwykłe pliki .kpv, nie dyski")
        self.geometry("920x770")
        self.minsize(770, 600)
        self.busy = False
        self.forms: dict[str, dict[str, tk.StringVar]] = {}
        self.buttons: list[ttk.Button] = []
        self.protocol("WM_DELETE_WINDOW", self._close)

        top = ttk.Frame(self, padding=14)
        top.pack(fill="both", expand=True)
        tk.Label(
            top, text="KRYPTA / VOLUME LAB — OBRAZY TESTOWE PFS/2",
            anchor="w", fg="#8CF5A7", bg="#101813",
            font=("Arial", 13, "bold"), padx=12, pady=10
        ).pack(fill="x")
        warning = (
            "NIE szyfruje dysku Windows C:, partycji Linux ani całego telefonu. "
            "Tylko nowe lub istniejące zwykłe pliki .kpv. Nie używaj jedynej kopii danych.\n"
            "Receipt musi pochodzić z niezależnie zaufanego miejsca; nie akceptuj "
            "automatycznie wartości odczytanej z niezaufanego obrazu. "
            "Oryginalne pliki pozostają niezmienione."
        )
        ttk.Label(top, text=warning, wraplength=840, justify="left").pack(
            fill="x", pady=(10, 12)
        )

        notebook = ttk.Notebook(top)
        notebook.pack(fill="both", expand=True)
        for title, fields, command in FORMS:
            panel = ttk.Frame(notebook, padding=14)
            notebook.add(panel, text=title)
            values: dict[str, tk.StringVar] = {}
            for index, (key, label, secret, is_output) in enumerate(fields):
                ttk.Label(panel, text=label).grid(
                    row=index, column=0, sticky="w", pady=5
                )
                value = tk.StringVar()
                values[key] = value
                entry = ttk.Entry(panel, textvariable=value, width=57,
                                  show="●" if secret else "")
                entry.grid(row=index, column=1, sticky="ew", padx=(10, 5), pady=5)
                if key not in {"receipt", "password", "confirmation",
                               "old_password", "new_password", "name"}:
                    ttk.Button(panel, text="...", width=4,
                               command=lambda k=key, v=value, dest=is_output:
                               self._browse(k, v, dest)).grid(
                        row=index, column=2, padx=2
                    )
            panel.columnconfigure(1, weight=1)
            self.forms[command] = values
            action = ttk.Button(
                panel, text="Wykonaj tylko dla obrazu testowego",
                command=lambda name=command: self._start(name)
            )
            action.grid(row=len(fields), column=1, sticky="w", pady=16)
            self.buttons.append(action)

        ttk.Label(top, text="Wynik / NOWY RECEIPT — skopiuj do niezależnie chronionego miejsca").pack(
            anchor="w", pady=(12, 4)
        )
        self.result = tk.Text(
            top, height=8, wrap="word", bg="#101813",
            fg="#E0F0E1", insertbackground="#8CF5A7"
        )
        self.result.pack(fill="both", expand=False)
        self.result.insert("1.0", "Brak operacji. Hasła nie są zapisywane do dziennika.\n")
        self.result.configure(state="disabled")
        self.status = tk.StringVar(value="Gotowe — brak aktywnej operacji")
        ttk.Label(top, textvariable=self.status).pack(anchor="w", pady=(8, 0))

    def _browse(self, key: str, variable: tk.StringVar, destination: bool):
        if self.busy:
            return
        kwargs = {}
        if key in {"image", "new_image"}:
            kwargs["filetypes"] = [("KRYPTA PVIMG", "*.kpv"), ("All files", "*.*")]
        if destination:
            selected = filedialog.asksaveasfilename(parent=self, **kwargs)
        else:
            selected = filedialog.askopenfilename(parent=self, **kwargs)
        if selected:
            variable.set(selected)

    def _start(self, action: str) -> None:
        if self.busy:
            return
        data = {key: value.get() for key, value in self.forms[action].items()}
        for key, val in data.items():
            if key in {"password", "confirmation", "new_password", "old_password"}:
                self.forms[action][key].set("")
            elif key not in {"recovery", "old_recovery"} and not val.strip():
                messagebox.showwarning("KRYPTA Volume Lab", "Uzupełnij wymagane pole.", parent=self)
                return
        if action in {"verify", "import", "export"}:
            if bool(data.get("password")) == bool(data.get("recovery")):
                messagebox.showerror("KRYPTA Volume Lab",
                                     "Podaj hasło ALBO plik odzyskiwania.", parent=self)
                return
        if action == "rotate" and bool(data.get("old_password")) == bool(data.get("old_recovery")):
            messagebox.showerror("KRYPTA Volume Lab",
                                 "Podaj dokładnie jedną starą metodę odblokowania.", parent=self)
            return
        if not messagebox.askyesno(
            "KRYPTA / test-only",
            "Potwierdzasz, że używasz wyłącznie jednorazowych plików testowych .kpv, "
            "masz kopie zapasowe i nie szyfrujesz partycji ani jedynej kopii ważnych danych?",
            parent=self
        ):
            return
        self.busy = True
        self.status.set("Przetwarzanie i weryfikacja…")
        for button in self.buttons:
            button.configure(state="disabled")
        job = threading.Thread(target=self._worker, args=(action, data), daemon=True)
        job.start()

    def _worker(self, action: str, data: dict[str, str]) -> None:
        try:
            method = {
                "create": lambda: operations.create_image(**data),
                "verify": lambda: operations.verify_image(
                    data["image"], data["envelope"], data["receipt"],
                    password=data["password"] or None, recovery=data["recovery"] or None),
                "import": lambda: operations.import_file(
                    data["image"], data["envelope"], data["receipt"], data["source"],
                    password=data["password"] or None, recovery=data["recovery"] or None),
                "export": lambda: operations.export_file(
                    data["image"], data["envelope"], data["receipt"], data["name"], data["output"],
                    password=data["password"] or None, recovery=data["recovery"] or None),
                "rotate": lambda: operations.rotate_image(
                    data["image"], data["envelope"], data["receipt"], data["new_image"],
                    data["new_envelope"], data["new_recovery"], data["new_password"],
                    data["confirmation"], old_password=data["old_password"] or None,
                    old_recovery=data["old_recovery"] or None),
                "recover": lambda: operations.recover_password(**data),
            }[action]
            response = method()
        except Exception as exc:
            # No secret, plaintext, path, stack trace or ciphertext in UI errors.
            kind = type(exc).__name__
            self.after(0, lambda k=kind: self._finish(
                False, {"result": "Operacja odmówiona lub nieudana", "category": k,
                        "advice": "Sprawdź ścieżki, długość hasła, zgodność receipt i kopie zapasowe."}))
        else:
            self.after(0, lambda value=response: self._finish(True, value))
        finally:
            data.clear()  # Discard application references to secret strings.

    def _finish(self, success: bool, report: dict):
        self.busy = False
        for button in self.buttons:
            button.configure(state="normal")
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0", json.dumps(report, ensure_ascii=False, indent=2))
        self.result.configure(state="disabled")
        self.status.set("Zakończono" if success else "Odmowa / błąd — brak potwierdzenia powodzenia")
        if success and "receipt" in report:
            messagebox.showwarning(
                "KRYPTA / RECEIPT",
                "Operacja zakończona. NOWY RECEIPT z pola wynikowego MUSI zostać "
                "zachowany w osobnym, niezależnie zaufanym miejscu przed następnym "
                "otwarciem woluminu. Stary receipt nie jest już aktualny.",
                parent=self,
            )

    def _close(self):
        if self.busy:
            messagebox.showwarning("KRYPTA", "Nie zamykaj okna podczas zapisu.", parent=self)
            return
        self.destroy()


def open_volume_lab(master):
    """Open a separate, manually controlled PFS2 development window."""
    return VolumeLabWindow(master)
