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
from pathlib import Path
from research.paged_keys import _new_private_file

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
MOUNT_READONLY = OPEN[:3] + [
    ("drive", "WOLNA litera dysku Windows (D: do Z:)", False, False),
    ("recovery", "Opcjonalny plik odzyskiwania; bez niego hasło w osobnej konsoli", False, False),
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
    ("Montuj R/O WinFsp", MOUNT_READONLY, "mount_readonly"),
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
        self.latest_receipt: str | None = None
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
        self.save_receipt_button = ttk.Button(
            top, text="Zapisz receipt do NOWEGO pliku (poza zaszyfrowanym obrazem)",
            command=self._save_receipt, state="disabled")
        self.save_receipt_button.pack(anchor="w", pady=(6, 0))
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

    def _start_readonly_mount(self) -> None:
        """Launch an independent interactive console; never take a GUI password."""
        if self.busy:
            return
        values = self.forms["mount_readonly"]
        data = {key: value.get() for key, value in values.items()}
        if not messagebox.askyesno(
            "KRYPTA / montowanie wyłącznie do odczytu",
            "To tylko TEST zwykłego obrazu .kpv, nie ochrona całego dysku. "
            "Po zamontowaniu jawne dane będą dostępne dla bieżącego użytkownika "
            "Windows i SYSTEM (również dla indeksowania/antywirusa). "
            "Otworzy się osobna konsola: tam wpisz hasło i naciśnij Enter, "
            "aby bezpiecznie odmontować. Masz kopie testowych danych?",
            parent=self,
        ):
            return
        try:
            from .windows_mount_launcher import launch_readonly_mount
            launch_readonly_mount(**data)
        except (ValueError, RuntimeError, OSError):
            self.status.set("Montowanie nieuruchomione — sprawdź WinFsp, dane i EXE")
            messagebox.showerror(
                "KRYPTA / WinFsp",
                "Nie można uruchomić konsoli montowania. Wymagany jest Windows "
                "oraz źródłowy Python.exe albo oddzielny, zaufany plik "
                "KRYPTA-Windows-ReadOnly-Mount-TEST.exe obok głównej aplikacji. "
                "Sprawdź ścieżki, 64-znakowy receipt i literę dysku.",
                parent=self,
            )
            return
        self.status.set("Uruchomiono konsolę — montowanie NIE jest jeszcze potwierdzone")
        messagebox.showinfo(
            "KRYPTA / WinFsp",
            "Uruchomiono osobną konsolę. Dopiero po sprawdzeniu hasła, "
            "receipt i integralności obrazu konsola potwierdzi montowanie. "
            "Do odmontowania naciśnij Enter w konsoli. Zamknięcie tego okna "
            "nie odmontowuje dysku. Nie używaj ważnych danych.",
            parent=self,
        )

    def _start(self, action: str) -> None:
        if self.busy:
            return
        if action == "mount_readonly":
            self._start_readonly_mount()
            return
        data = {key: value.get() for key, value in self.forms[action].items()}
        required = {
            "create": {"image", "envelope", "recovery", "password", "confirmation"},
            "verify": {"image", "envelope", "receipt"},
            "import": {"image", "envelope", "receipt", "source"},
            "export": {"image", "envelope", "receipt", "name", "output"},
            "rotate": {"image", "envelope", "receipt", "new_image", "new_envelope",
                       "new_recovery", "new_password", "confirmation"},
            "recover": {"envelope", "recovery", "new_envelope", "password", "confirmation"},
        }[action]
        for key in {"password", "confirmation", "new_password", "old_password"}:
            if key in self.forms[action]:
                self.forms[action][key].set("")
        if any(not data[key].strip() for key in required):
            messagebox.showwarning("KRYPTA Volume Lab",
                                   "Uzupełnij wymagane pole.", parent=self)
            data.clear()
            return
        if action in {"verify", "import", "export"}:
            if bool(data.get("password")) == bool(data.get("recovery")):
                messagebox.showerror("KRYPTA Volume Lab",
                                     "Podaj hasło ALBO plik odzyskiwania.", parent=self)
                data.clear()
                return
        if action == "rotate" and bool(data.get("old_password")) == bool(data.get("old_recovery")):
            messagebox.showerror("KRYPTA Volume Lab",
                                 "Podaj dokładnie jedną starą metodę odblokowania.", parent=self)
            data.clear()
            return
        if not messagebox.askyesno(
            "KRYPTA / test-only",
            "Potwierdzasz, że używasz wyłącznie jednorazowych plików testowych .kpv, "
            "masz kopie zapasowe i nie szyfrujesz partycji ani jedynej kopii ważnych danych?",
            parent=self
        ):
            data.clear()
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
            # Do not lose recovery metadata if the write committed before
            # an integrity check subsequently failed; never call it trusted.
            if isinstance(exc, operations.PostCommitVerificationError):
                report = {
                    "result": "ZAPIS MÓGŁ SIĘ ZAKOŃCZYĆ, ALE WERYFIKACJA NIE PRZESZŁA",
                    "UNVERIFIED_RECEIPT_RECOVERY_ONLY": exc.unverified_receipt,
                    "warning": "NIE UŻYWAJ jako zaufanego receipt. "
                               "Zachowaj kopię obrazu; wymagane osobne sprawdzenie odzyskiwania.",
                }
            else:
                report = {
                    "result": "Operacja odmówiona lub nieudana",
                    "category": type(exc).__name__,
                    "advice": "Sprawdź ścieżki, hasło, receipt i kopie zapasowe.",
                }
            self.after(0, lambda value=report: self._finish(False, value))
        else:
            self.after(0, lambda value=response: self._finish(True, value))
        finally:
            data.clear()  # Discard application references to secret strings.

    def _save_receipt(self):
        """Create a separate receipt file, never silently replace an old one."""
        if self.busy or self.latest_receipt is None:
            return
        receipt = self.latest_receipt
        if not messagebox.askyesno(
            "KRYPTA / receipt poza obrazem",
            "Czy zapiszesz nowy plik receipt na niezależnie chronionym nośniku? "
            "Plik w tym samym katalogu co .kpv NIE chroni przed rollback. "
            "Nie usuwaj starej zaufanej kopii przed sprawdzeniem nowej.",
            parent=self,
        ):
            return
        destination = filedialog.asksaveasfilename(
            parent=self, title="NOWY niezależny plik receipt",
            defaultextension=".receipt",
            filetypes=[("Receipt KRYPTA", "*.receipt"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            if len(receipt) != 64 or any(ch not in "0123456789abcdef" for ch in receipt):
                raise ValueError("Invalid authenticated receipt")
            _new_private_file(Path(destination), (receipt + "\n").encode("ascii"))
        except (OSError, ValueError) as exc:
            messagebox.showerror("KRYPTA", "Nie zapisano receipt. Sprawdź, czy plik "
                                 "już istnieje i czy masz dostęp do folderu.", parent=self)
            return
        messagebox.showinfo("KRYPTA", "Zapisano NOWY plik receipt. "
                            "Przechowuj go w niezależnie zaufanym miejscu.", parent=self)

    def _finish(self, success: bool, report: dict):
        self.busy = False
        for button in self.buttons:
            button.configure(state="normal")
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0", json.dumps(report, ensure_ascii=False, indent=2))
        self.result.configure(state="disabled")
        self.latest_receipt = (
            report.get("receipt") if success and
            isinstance(report.get("receipt"), str) else None
        )
        self.save_receipt_button.configure(
            state="normal" if self.latest_receipt else "disabled")
        self.status.set("Zakończono" if success else "Odmowa / błąd — brak potwierdzenia powodzenia")
        if "UNVERIFIED_RECEIPT_RECOVERY_ONLY" in report:
            messagebox.showerror(
                "KRYPTA / UWAGA: wynik NIEZWERYFIKOWANY",
                "Zapis mógł zostać zatwierdzony, ale późniejszy test danych zawiódł. "
                "Nie ufaj staremu receipt. W polu wyniku jest NIEZWERYFIKOWANY "
                "receipt tylko do diagnostyki. Zachowaj obraz i kopie zapasowe.",
                parent=self,
            )
        if success and report.get("receipt_changed") is True:
            messagebox.showwarning(
                "KRYPTA / RECEIPT",
                "Operacja ZMIENIŁA stan zaszyfrowanego obrazu. NOWY RECEIPT "
                "z pola wynikowego zapisz w niezależnie zaufanym miejscu. "
                "Nie stosuj starego receipt do tego nowego stanu.",
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
