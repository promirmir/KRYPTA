"""KRYPTA desktop interface. Offline Tkinter UI for *test-file* vault only.

No web server, telemetry, clipboard handling or implicit destructive operation.
Future disk/system/password operations are represented as clearly disabled modules.
"""
from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from .core import CryptoError, decrypt_file, encrypt_file, file_info, generate_keyfile
from .ui_model import password_warning

INK = '#080F0C'
PANEL = '#0D1812'
PANEL_ALT = '#111F17'
BORDER = '#254A36'
GREEN = '#8CF5A7'
GREEN_DIM = '#5EA777'
TEXT = '#DCEBE0'
MUTED = '#8BA392'
AMBER = '#E7C37D'
RED = '#EBA69F'
FONT = 'Consolas' if os.name == 'nt' else 'DejaVu Sans Mono'


class KryptaApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('KRYPTA / SECURITY WORKSTATION  ·  ALPHA')
        self.geometry('1180x895')
        self.minsize(930, 820)
        self.configure(bg=INK)
        self.busy = False
        self.active_module = 0
        self.mode = tk.StringVar(value='encrypt')
        self.source = tk.StringVar()
        self.destination = tk.StringVar()
        self.keyfile = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm = tk.StringVar()
        self.reveal = tk.BooleanVar(value=False)
        self.state_msg = tk.StringVar(value='GOTOWY  /  Operacje wyłącznie na zwykłych plikach testowych')
        self._setup_style()
        self._layout()
        self.password.trace_add('write', lambda *_: self._update_advisory())
        self.keyfile.trace_add('write', lambda *_: self._update_advisory())
        self.mode.trace_add('write', lambda *_: self._set_mode())
        self._update_advisory()

    def _setup_style(self):
        self.option_add('*Font', f'{{{FONT}}} 10')
        self.option_add('*Entry.background', PANEL_ALT)
        self.option_add('*Entry.foreground', TEXT)
        self.option_add('*Entry.insertBackground', GREEN)
        self.option_add('*Text.background', PANEL)
        self.option_add('*Text.foreground', TEXT)
        self.option_add('*Text.insertBackground', GREEN)
        st = ttk.Style(self)
        st.theme_use('clam')
        st.configure('KV.TEntry', fieldbackground=PANEL_ALT, foreground=TEXT,
                     bordercolor=BORDER, insertcolor=GREEN, padding=9)
        st.map('KV.TEntry', bordercolor=[('focus', GREEN_DIM)],
               fieldbackground=[('readonly', PANEL_ALT)])
        st.configure('KV.TButton', background=PANEL_ALT, foreground=GREEN,
                     bordercolor=BORDER, padding=(12, 9), font=(FONT, 10, 'bold'))
        st.map('KV.TButton', background=[('active', '#1A3222'), ('disabled', PANEL)],
               foreground=[('disabled', MUTED)])
        st.configure('KPrimary.TButton', background=GREEN, foreground=INK,
                     padding=(18, 12), bordercolor=GREEN, font=(FONT, 10, 'bold'))
        st.map('KPrimary.TButton', background=[('active', '#C5FFD1'), ('disabled', PANEL_ALT)],
               foreground=[('disabled', MUTED)])
        st.configure('KRadio.TRadiobutton', background=PANEL, foreground=TEXT,
                     font=(FONT, 10), padding=(10, 10))
        st.map('KRadio.TRadiobutton', background=[('active', PANEL)],
               foreground=[('active', GREEN)])
        st.configure('KCheck.TCheckbutton', background=PANEL, foreground=MUTED,
                     font=(FONT, 9))
        st.map('KCheck.TCheckbutton', background=[('active', PANEL)])

    def _label(self, parent, text, fg=MUTED, size=10, bold=False, **kw):
        return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=fg,
                        font=(FONT, size, 'bold' if bold else 'normal'), **kw)

    def _layout(self):
        root = tk.Frame(self, bg=INK)
        root.pack(fill='both', expand=True, padx=26, pady=19)
        mast = tk.Frame(root, bg=INK)
        mast.pack(fill='x', pady=(0, 18))
        brand = tk.Frame(mast, bg=INK)
        brand.pack(side='left')
        self._label(brand, '⌁', GREEN, 25, True).pack(side='left', padx=(0, 8))
        self._label(brand, 'K R Y P T A', GREEN, 22, True).pack(side='left')
        self._label(brand, '  /  SECURITY WORKSTATION', MUTED, 10).pack(side='left', pady=(9, 0))
        right = tk.Frame(mast, bg=INK)
        right.pack(side='right')
        self._label(right, 'RESEARCH BUILD   0.4.0-ALPHA', AMBER, 9, True).pack(anchor='e')
        self._label(right, 'LOCAL MODE  ●  NO CLOUD CONNECTION', GREEN_DIM, 9).pack(anchor='e', pady=(4, 0))
        strip = tk.Frame(root, height=1, bg=GREEN_DIM)
        strip.pack(fill='x', pady=(0, 16))
        strip.pack_propagate(False)
        main = tk.Frame(root, bg=INK)
        main.pack(fill='both', expand=True)
        sidebar = tk.Frame(main, bg=INK, width=225)
        sidebar.pack(side='left', fill='y', padx=(0, 17))
        sidebar.pack_propagate(False)
        self._label(sidebar, 'MODULES  /  01—05', GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 14))
        specs = [
            ('01', 'FILE VAULT', 'ACTIVE', True),
            ('02', 'DRIVE SHIELD', 'PLANNED', False),
            ('03', 'SYSTEM SHIELD', 'PLANNED', False),
            ('04', 'PASSWORD SHIELD', 'PLANNED', False),
            ('05', 'ANDROID SHIELD', 'PLANNED', False),
        ]
        self.module_buttons = []
        for index, (i, name, status, active) in enumerate(specs):
            btn = tk.Button(
                sidebar, text=f'{i}  {name}\n{status}', command=lambda idx=index: self._show_module(idx),
                justify='left', anchor='w', bg=PANEL_ALT if active else INK,
                fg=GREEN if active else MUTED, activebackground='#162B1E',
                activeforeground=GREEN, highlightthickness=0, bd=1,
                relief='solid' if active else 'flat',
                font=(FONT, 10), padx=12, pady=11, cursor='hand2',
            )
            btn.pack(fill='x', pady=(0, 5))
            self.module_buttons.append(btn)
        tk.Frame(sidebar, bg=INK, height=22).pack()
        self._label(sidebar, 'SECURITY PRINCIPLE', GREEN_DIM, 9, True).pack(anchor='w')
        self._label(sidebar,
                    'Public design. Private keys.\nNo false claims.\nIndependent verification.',
                    MUTED, 9, justify='left', anchor='nw').pack(fill='x', pady=(9, 0))
        body = tk.Frame(main, bg=INK)
        body.pack(side='left', fill='both', expand=True)
        heading = tk.Frame(body, bg=INK)
        heading.pack(fill='x', pady=(0, 13))
        self.module_title = self._label(heading, '01 / FILE VAULT', TEXT, 18, True)
        self.module_title.pack(side='left')
        self.module_status = self._label(heading, '● AVAILABLE IN RESEARCH BUILD', GREEN_DIM, 9, True)
        self.module_status.pack(side='right', pady=(8, 0))
        self.module_subtitle = self._label(body,
            'Szyfrowanie plików testowych  ·  AES-256-GCM  ·  Argon2id  ·  brak sieci', MUTED, 10)
        self.module_subtitle.pack(anchor='w', pady=(0, 14))
        self.vault_panel = tk.Frame(body, bg=INK)
        self.vault_panel.pack(fill='both', expand=True)
        self.future_panel = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        self.future_heading = self._label(self.future_panel, 'MODULE IN DEVELOPMENT', AMBER, 16, True)
        self.future_heading.pack(anchor='w', padx=25, pady=(30, 15))
        self.future_copy = self._label(self.future_panel, '', TEXT, 11, justify='left',
                                       anchor='w', wraplength=670)
        self.future_copy.pack(anchor='w', padx=25)
        self._label(self.future_panel, '\nNO SECURITY CLAIM WITHOUT IMPLEMENTATION AND AUDIT',
                    GREEN_DIM, 9, True).pack(anchor='w', padx=25, pady=(25, 20))
        card = tk.Frame(self.vault_panel, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill='x')
        pad = tk.Frame(card, bg=PANEL)
        pad.pack(fill='x', padx=23, pady=19)
        modebar = tk.Frame(pad, bg=PANEL)
        modebar.pack(fill='x', pady=(0, 14))
        self._label(modebar, 'OPERATION', GREEN_DIM, 9, True).pack(side='left', padx=(0, 15))
        for value, label in [('encrypt', 'ENCRYPT'), ('decrypt', 'DECRYPT'), ('info', 'INSPECT HEADER')]:
            ttk.Radiobutton(modebar, text=label, variable=self.mode, value=value,
                            style='KRadio.TRadiobutton').pack(side='left', padx=2)
        self._field(pad, 'SOURCE FILE', self.source, 'source')
        self.dest_row = self._field(pad, 'DESTINATION  /  NEW FILE', self.destination, 'destination')
        self.key_row = self._field(pad, 'OPTIONAL SECOND FACTOR  /  EXTERNAL KEYFILE', self.keyfile, 'keyfile')
        row = tk.Frame(pad, bg=PANEL)
        row.pack(fill='x', pady=(2, 4))
        self._label(row, 'PIN / PASSPHRASE', GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 6))
        password_line = tk.Frame(row, bg=PANEL)
        password_line.pack(fill='x')
        self.pwd_entry = ttk.Entry(password_line, textvariable=self.password, show='•', style='KV.TEntry')
        self.pwd_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))
        ttk.Checkbutton(password_line, text='REVEAL', variable=self.reveal,
                        command=self._toggle_reveal, style='KCheck.TCheckbutton').pack(side='left')
        self.confirm_row = tk.Frame(pad, bg=PANEL)
        self.confirm_row.pack(fill='x', pady=(8, 0))
        self._label(self.confirm_row, 'CONFIRM PIN / PASSPHRASE', GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 6))
        self.confirm_entry = ttk.Entry(self.confirm_row, textvariable=self.confirm, show='•', style='KV.TEntry')
        self.confirm_entry.pack(fill='x')
        bottom = tk.Frame(pad, bg=PANEL)
        bottom.pack(fill='x', pady=(17, 0))
        self.action = ttk.Button(bottom, text='ENCRYPT TEST FILE  →', command=self._run,
                                 style='KPrimary.TButton')
        self.action.pack(side='left')
        ttk.Button(bottom, text='GENERATE KEYFILE', command=self._new_keyfile,
                   style='KV.TButton').pack(side='right')
        risk_frame = tk.Frame(self.vault_panel, bg=PANEL_ALT, highlightthickness=1, highlightbackground=BORDER)
        risk_frame.pack(fill='x', pady=(14, 0))
        self.risk = tk.Label(risk_frame, text='', bg=PANEL_ALT, fg=AMBER,
                             font=(FONT, 10), justify='left', anchor='w', wraplength=700)
        self.risk.pack(fill='x', padx=16, pady=14)
        info = tk.Frame(self.vault_panel, bg=INK)
        info.pack(fill='both', expand=True, pady=(15, 0))
        self._label(info, 'CONSOLE  /  SECURITY EVENTS', GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 7))
        self.console = tk.Text(info, height=6, bg='#09120D', fg=GREEN_DIM,
                               font=(FONT, 9), wrap='word', relief='flat', state='disabled',
                               padx=14, pady=12, highlightbackground=BORDER, highlightthickness=1)
        self.console.pack(fill='both', expand=True)
        self._log('SECURITY NOTICE: ALPHA PROTOTYPE — NO INDEPENDENT AUDIT')
        self._log('Do not use for irreplaceable data or live system partitions.')
        self._log('Raw disk encryption and TPM-enforced brute-force limits: NOT IMPLEMENTED.')
        foot = tk.Frame(root, bg=INK)
        foot.pack(fill='x', pady=(14, 0))
        tk.Frame(root, bg=BORDER, height=1).pack(side='bottom', fill='x')
        self.status = self._label(foot, '●  READY', GREEN, 9, True)
        self.status.pack(side='left')
        self._label(foot, 'KRYPTA  ·  OFFLINE  ·  FILE VAULT ONLY  ·  DEVELOPMENT / NOT CERTIFIED',
                    MUTED, 8).pack(side='right')

    def _show_module(self, index):
        if self.busy or index == self.active_module:
            return
        names = ('FILE VAULT', 'DRIVE SHIELD', 'SYSTEM SHIELD', 'PASSWORD SHIELD', 'ANDROID SHIELD')
        summaries = (
            '',
            'Docelowo: niezależne szyfrowanie woluminów USB, SSD i HDD.\n'
            'Klucze nie będą ujawniane w nagłówkach. PIN sprzętowy wymaga\n'
            'odpowiednio zaprojektowanego nieeksportowalnego sekretu.\n\n'
            'STATUS: BRAK SILNIKA SZYFROWANIA WOLUMINÓW. NIC NIE JEST MODYFIKOWANE.',
            'Docelowo: ochrona dysku rozruchowego przed startem systemu,\n'
            'TPM 2.0, Secure Boot, bezpieczna procedura odzyskiwania.\n\n'
            'STATUS: BRAK STEROWNIKA, INSTALATORA I MECHANIZMU PRE-BOOT.\n'
            'NIE WOLNO TESTOWAĆ TEGO MODUŁU NA SYSTEMOWYM DYSKU.',
            'Docelowo: odrębny sejf haseł, autoryzacja użycia sekretów,\n'
            'integracje z uprawnionymi aplikacjami.\n\n'
            'STATUS: FUNKCJA NIEZAIMPLEMENTOWANA. ISTNIEJĄCE HASŁA NIE SĄ PRZEJMOWANE.',
            'Docelowo: zarządzanie ochroną Android FBE oraz Android Keystore.\n'
            'Zwykła aplikacja APK nie zastąpi szyfrowania systemowego.\n\n'
            'STATUS: FUNKCJA NIEZAIMPLEMENTOWANA.',
        )
        self.active_module = index
        for i, btn in enumerate(self.module_buttons):
            selected = i == index
            btn.configure(bg=PANEL_ALT if selected else INK,
                          fg=GREEN if selected else MUTED,
                          relief='solid' if selected else 'flat')
        self.module_title.configure(text=f'{index+1:02d} / {names[index]}')
        self.module_status.configure(text='● AVAILABLE IN RESEARCH BUILD' if index == 0
                                     else '◌ PLANNED / NOT IMPLEMENTED',
                                     fg=GREEN_DIM if index == 0 else AMBER)
        self.module_subtitle.configure(text=(
            'Szyfrowanie plików testowych  ·  AES-256-GCM  ·  Argon2id  ·  brak sieci'
            if index == 0 else 'PROTECTED ARCHITECTURE  /  DEVELOPMENT STAGE'))
        if index == 0:
            self.future_panel.pack_forget()
            self.vault_panel.pack(fill='both', expand=True)
        else:
            self.vault_panel.pack_forget()
            self.future_heading.configure(text=f'0{index+1}  /  {names[index]}')
            self.future_copy.configure(text=summaries[index])
            self.future_panel.pack(fill='both', expand=True)

    def _field(self, parent, label, var, role):
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill='x', pady=(0, 12))
        self._label(frame, label, GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 6))
        line = tk.Frame(frame, bg=PANEL)
        line.pack(fill='x')
        entry = ttk.Entry(line, textvariable=var, style='KV.TEntry')
        entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        button = ttk.Button(line, text='BROWSE', style='KV.TButton',
                            command=lambda: self._choose(role))
        button.pack(side='left')
        return frame

    def _choose(self, role):
        if self.busy:
            return
        if role == 'destination':
            path = filedialog.asksaveasfilename(title='Nowy plik wynikowy (bez nadpisywania)')
            if path:
                self.destination.set(path)
        else:
            path = filedialog.askopenfilename(title='Wybierz plik źródłowy' if role == 'source'
                                               else 'Wybierz dodatkowy plik klucza')
            if path:
                getattr(self, role).set(path)

    def _toggle_reveal(self):
        show = '' if self.reveal.get() else '•'
        self.pwd_entry.configure(show=show)
        self.confirm_entry.configure(show=show)

    def _set_mode(self):
        mode = self.mode.get()
        if mode == 'info':
            self.dest_row.pack_forget()
            self.key_row.pack_forget()
            self.confirm_row.pack_forget()
            self.pwd_entry.configure(state='disabled')
            self.action.configure(text='INSPECT PUBLIC HEADER  →')
        else:
            # Avoid reordering by explicitly packing each row ahead of the PIN section.
            self.dest_row.pack(fill='x', pady=(0, 12), before=self.pwd_entry.master.master)
            self.key_row.pack(fill='x', pady=(0, 12), before=self.pwd_entry.master.master)
            if mode == 'encrypt':
                self.confirm_row.pack(fill='x', pady=(8, 0), before=self.action.master)
            else:
                self.confirm_row.pack_forget()
            self.pwd_entry.configure(state='normal')
            self.action.configure(text='ENCRYPT TEST FILE  →' if mode == 'encrypt'
                                  else 'DECRYPT TEST FILE  →')
        self._update_advisory()

    def _update_advisory(self):
        if self.mode.get() == 'info':
            msg = 'HEADER IS PUBLIC / UNVERIFIED — it becomes authenticated only after successful decryption.'
        else:
            msg = password_warning(self.password.get(), bool(self.keyfile.get().strip()))
        self.risk.configure(text='▸  ' + msg,
                            fg=RED if 'OFFLINE' in msg or 'NIE' in msg else AMBER)

    def _log(self, line):
        self.console.configure(state='normal')
        self.console.insert('end', f'> {line}\n')
        self.console.see('end')
        self.console.configure(state='disabled')

    def _set_busy(self, busy, status):
        self.busy = busy
        self.action.configure(state='disabled' if busy else 'normal')
        self.status.configure(text=('◌  ' if busy else '●  ') + status,
                              fg=AMBER if busy else GREEN)

    def _run(self):
        if self.busy:
            return
        mode = self.mode.get()
        src = self.source.get().strip()
        dst = self.destination.get().strip()
        key = self.keyfile.get().strip() or None
        pw = self.password.get()
        if not src or (mode != 'info' and not dst):
            messagebox.showwarning('KRYPTA / Missing path', 'Wybierz plik wejściowy i plik wyjściowy.')
            return
        if mode != 'info' and not pw:
            messagebox.showwarning('KRYPTA / Empty secret', 'Hasło nie może być puste.')
            return
        if mode == 'encrypt' and pw != self.confirm.get():
            messagebox.showwarning('KRYPTA / Confirmation', 'Wpisane hasła różnią się.')
            return
        if mode == 'encrypt' and len(pw) <= 4 and not key:
            if not messagebox.askyesno('KRYPTA / OFFLINE ATTACK RISK',
                    'Krótki PIN bez drugiego sekretu NIE chroni przed nieograniczonym odgadywaniem '
                    'na skopiowanym pliku.\n\nTo jest wyłącznie wersja badawcza. Kontynuować test?'):
                return
        if mode != 'info' and Path(dst).exists():
            messagebox.showerror('KRYPTA / File exists', 'Nie nadpisujemy istniejących plików.')
            return
        self._set_busy(True, 'PROCESSING / DO NOT CLOSE')
        self._log(f'{mode.upper()} — operation requested (no plaintext / keys in logs).')
        # Keep Tk on main thread; cryptographic work runs on worker thread.
        def job():
            try:
                if mode == 'info':
                    result = file_info(src)
                    msg = json.dumps(result, ensure_ascii=False, indent=2)
                elif mode == 'encrypt':
                    encrypt_file(src, dst, pw, key)
                    msg = 'Zaszyfrowano plik. Oryginał nie został usunięty.'
                else:
                    decrypt_file(src, dst, pw, key)
                    msg = 'Odszyfrowano plik. Integralność została sprawdzona.'
            except (CryptoError, OSError, ValueError) as exc:
                self.after(0, lambda m=str(exc): self._complete(False, m))
            except Exception:
                self.after(0, lambda: self._complete(False, 'Nieoczekiwany błąd.'))
            else:
                self.after(0, lambda m=msg: self._complete(True, m))
        threading.Thread(target=job, daemon=True).start()
        # Remove references from entry widgets while operation runs; Python may retain strings.
        self.password.set('')
        self.confirm.set('')

    def _complete(self, ok, message):
        self._set_busy(False, 'READY' if ok else 'OPERATION FAILED')
        if ok:
            self._log('SUCCESS  /  ' + message)
            if '\n' in message:
                self._log(message)
            messagebox.showinfo('KRYPTA / Completed', message)
        else:
            self._log('ERROR  /  ' + message)
            messagebox.showerror('KRYPTA / Failure', message)

    def _new_keyfile(self):
        if self.busy:
            return
        path = filedialog.asksaveasfilename(title='Utwórz nowy losowy plik klucza (backup wymagany)',
                                             defaultextension='.key')
        if not path:
            return
        if not messagebox.askyesno('KRYPTA / Key material',
                'Klucz musi być przechowywany poza zaszyfrowanym plikiem i mieć kopię zapasową. '
                'Utrata klucza oznacza utratę dostępu. Utworzyć?'):
            return
        try:
            generate_keyfile(path)
        except (OSError, ValueError, CryptoError) as exc:
            messagebox.showerror('KRYPTA / Cannot create', str(exc))
            return
        self.keyfile.set(path)
        self._log('32-byte random keyfile generated (secret not logged).')
        messagebox.showinfo('KRYPTA / Keyfile', 'Utworzono klucz. Zrób bezpieczną kopię.')


def main():
    app = KryptaApp()
    app.mainloop()


if __name__ == '__main__':
    main()