"""KRYPTA desktop interface. Offline Tkinter UI for *test-file* vault only.

No web server, telemetry, clipboard handling or implicit destructive operation.
Future disk/system/password operations are represented as clearly disabled modules.
"""
from __future__ import annotations

import json
import os
import locale
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from .core import CryptoError, decrypt_file, encrypt_file, file_info, generate_keyfile
from .i18n import LANGUAGES, normalize_language, translate
from .volume_status import inspect_volumes
from .physical_devices import inspect_physical_disks

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
        self.title('KRYPTA / SECURITY WORKSTATION · ALPHA')
        self.geometry('1180x895')
        self.minsize(930, 820)
        self.configure(bg=INK)
        self.language_code = normalize_language(locale.getlocale()[0] or 'en')
        self.language_name = tk.StringVar(value=LANGUAGES[self.language_code])
        self.busy = False
        self.active_module = 0
        self.mode = tk.StringVar(value='encrypt')
        self.source = tk.StringVar()
        self.destination = tk.StringVar()
        self.keyfile = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm = tk.StringVar()
        self.reveal = tk.BooleanVar(value=False)
        self.state_msg = tk.StringVar(value='')
        self._setup_style()
        self._layout()
        self.password.trace_add('write', lambda *_: self._update_advisory())
        self.keyfile.trace_add('write', lambda *_: self._update_advisory())
        self.mode.trace_add('write', lambda *_: self._set_mode())
        self._update_advisory()
        self.protocol("WM_DELETE_WINDOW", self._close_workstation)

    def _close_workstation(self):
        """Never kill a running encrypted-image write by closing the root UI."""
        from .volume_lab_gui import VolumeLabWindow
        if any(isinstance(window, VolumeLabWindow) and window.busy
               for window in self.winfo_children()):
            messagebox.showwarning(
                'KRYPTA', 'Trwa zapis zaszyfrowanego obrazu. Poczekaj na wynik.',
                parent=self)
            return
        if self.busy:
            messagebox.showwarning(
                'KRYPTA', self._t('processing'), parent=self)
            return
        self.destroy()

    def _t(self, key):
        return translate(self.language_code, key)

    def _language_changed(self, _event=None):
        if self.busy:
            return
        chosen = self.language_name.get()
        match = next((code for code, name in LANGUAGES.items() if name == chosen), None)
        if not match or match == self.language_code:
            return
        selected = self.active_module
        self.language_code = match
        # Keep independent Volume Lab Toplevel windows alive, especially
        # during an encrypted write. A locale change is NEVER permission to
        # terminate an active COW commit and lose the updated receipt.
        for child in self.winfo_children():
            if not isinstance(child, tk.Toplevel):
                child.destroy()
        self._setup_style()
        self._layout()
        self.active_module = 0
        if selected:
            self._show_module(selected)
        self._set_mode()
        self._update_advisory()

    def _font_family(self):
        # Use fonts with coverage for scripts not present in typical monospace fonts.
        if os.name == 'nt':
            return {'zh': 'Microsoft YaHei UI', 'hi': 'Nirmala UI',
                    'ar': 'Segoe UI'}.get(self.language_code, FONT)
        return {'zh': 'Noto Sans CJK SC', 'hi': 'Noto Sans Devanagari',
                'ar': 'Noto Sans Arabic'}.get(self.language_code, FONT)

    def _setup_style(self):
        ui_font = self._font_family()
        self.option_add('*Font', f'{{{ui_font}}} 10')
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
                     bordercolor=BORDER, padding=(12, 9), font=(ui_font, 10, 'bold'))
        st.map('KV.TButton', background=[('active', '#1A3222'), ('disabled', PANEL)],
               foreground=[('disabled', MUTED)])
        st.configure('KPrimary.TButton', background=GREEN, foreground=INK,
                     padding=(18, 12), bordercolor=GREEN, font=(ui_font, 10, 'bold'))
        st.map('KPrimary.TButton', background=[('active', '#C5FFD1'), ('disabled', PANEL_ALT)],
               foreground=[('disabled', MUTED)])
        st.configure('KRadio.TRadiobutton', background=PANEL, foreground=TEXT,
                     font=(ui_font, 10), padding=(10, 10))
        st.map('KRadio.TRadiobutton', background=[('active', PANEL)],
               foreground=[('active', GREEN)])
        st.configure('KCheck.TCheckbutton', background=PANEL, foreground=MUTED,
                     font=(ui_font, 9))
        st.map('KCheck.TCheckbutton', background=[('active', PANEL)])

    def _label(self, parent, text, fg=MUTED, size=10, bold=False, **kw):
        return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=fg,
                        font=(self._font_family(), size, 'bold' if bold else 'normal'), **kw)

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
        self._label(right, self._t('research_build') + '   0.4.0-ALPHA', AMBER, 9, True).pack(anchor='e')
        self._label(right, self._t('offline'), GREEN_DIM, 9).pack(anchor='e', pady=(4, 0))
        self.lang_picker = ttk.Combobox(right, values=list(LANGUAGES.values()),
                                       textvariable=self.language_name, state='readonly', width=20)
        self.lang_picker.pack(anchor='e', pady=(6, 0))
        self.lang_picker.bind('<<ComboboxSelected>>', self._language_changed)
        strip = tk.Frame(root, height=1, bg=GREEN_DIM)
        strip.pack(fill='x', pady=(0, 16))
        strip.pack_propagate(False)
        main = tk.Frame(root, bg=INK)
        main.pack(fill='both', expand=True)
        sidebar = tk.Frame(main, bg=INK, width=225)
        sidebar.pack(side='left', fill='y', padx=(0, 17))
        sidebar.pack_propagate(False)
        self._label(sidebar, self._t('modules') + ' / 01—06', GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 14))
        specs = [
            ('01', self._t('file_vault'), self._t('available'), True),
            ('02', self._t('drive_shield'), self._t('planned'), False),
            ('03', self._t('system_shield'), self._t('planned'), False),
            ('04', self._t('password_shield'), self._t('planned'), False),
            ('05', self._t('android_shield'), self._t('planned'), False),
            ('06', 'Woluminy / Volume Lab' if self.language_code == 'pl'
             else 'Volume Lab (PFS/2)',
             'tylko testowe .kpv' if self.language_code == 'pl'
             else 'test .kpv only', True),
        ]
        self.module_buttons = []
        for index, (i, name, status, active) in enumerate(specs):
            btn = tk.Button(
                sidebar, text=f'{i}  {name}\n{status}', command=lambda idx=index: self._show_module(idx),
                justify='left', anchor='w', bg=PANEL_ALT if active else INK,
                fg=GREEN if active else MUTED, activebackground='#162B1E',
                activeforeground=GREEN, highlightthickness=0, bd=1,
                relief='solid' if active else 'flat',
                font=(self._font_family(), 10), padx=12, pady=11, cursor='hand2',
            )
            btn.pack(fill='x', pady=(0, 5))
            self.module_buttons.append(btn)
        tk.Frame(sidebar, bg=INK, height=22).pack()
        self._label(sidebar, self._t('principle'), GREEN_DIM, 9, True).pack(anchor='w')
        self._label(sidebar,
                    self._t('principle_body'),
                    MUTED, 9, justify='left', anchor='nw').pack(fill='x', pady=(9, 0))
        body = tk.Frame(main, bg=INK)
        body.pack(side='left', fill='both', expand=True)
        heading = tk.Frame(body, bg=INK)
        heading.pack(fill='x', pady=(0, 13))
        self.module_title = self._label(heading, '01 / ' + self._t('file_vault'), TEXT, 18, True)
        self.module_title.pack(side='left')
        self.module_status = self._label(heading, '● ' + self._t('available'), GREEN_DIM, 9, True)
        self.module_status.pack(side='right', pady=(8, 0))
        self.module_subtitle = self._label(body,
            self._t('vault_subtitle'), MUTED, 10)
        self.module_subtitle.pack(anchor='w', pady=(0, 14))
        self.vault_panel = tk.Frame(body, bg=INK)
        self.vault_panel.pack(fill='both', expand=True)
        self.future_panel = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        self.future_heading = self._label(self.future_panel, self._t('future_heading'), AMBER, 16, True)
        self.future_heading.pack(anchor='w', padx=25, pady=(30, 15))
        self.future_copy = self._label(self.future_panel, '', TEXT, 11, justify='left',
                                       anchor='w', wraplength=670)
        self.future_copy.pack(anchor='w', padx=25)
        self._label(self.future_panel, '\n' + self._t('future_warning'),
                    GREEN_DIM, 9, True).pack(anchor='w', padx=25, pady=(25, 20))
        # Windows BitLocker / Linux LUKS state is OS-managed; this UI ONLY reads it.
        self.volume_scan_button = ttk.Button(
            self.future_panel, text='SCAN SYSTEM / USB ENCRYPTION (READ-ONLY)',
            command=self._scan_volumes, style='KV.TButton')
        self.physical_scan_button = ttk.Button(
            self.future_panel,
            text='IDENTYFIKUJ FIZYCZNE DYSKI USB/SSD/HDD (TYLKO ODCZYT)',
            command=self._scan_physical_devices, style='KV.TButton')
        self.volume_scan_results = tk.Text(
            self.future_panel, height=9, bg=PANEL_ALT, fg=TEXT,
            font=(self._font_family(), 9), wrap='word', relief='flat',
            padx=14, pady=10, state='disabled', highlightthickness=1,
            highlightbackground=BORDER)
        self.volume_scan_note = self._label(
            self.future_panel,
            'OS-managed transparent encryption only. Detection does not enable encryption, '
            'verify TPM PIN limits or protect an unlocked device.',
            AMBER, 9, justify='left', wraplength=680)
        card = tk.Frame(self.vault_panel, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill='x')
        pad = tk.Frame(card, bg=PANEL)
        pad.pack(fill='x', padx=23, pady=19)
        modebar = tk.Frame(pad, bg=PANEL)
        modebar.pack(fill='x', pady=(0, 14))
        self._label(modebar, self._t('operation'), GREEN_DIM, 9, True).pack(side='left', padx=(0, 15))
        for value, label in [('encrypt', self._t('encrypt')), ('decrypt', self._t('decrypt')), ('info', self._t('inspect'))]:
            ttk.Radiobutton(modebar, text=label, variable=self.mode, value=value,
                            style='KRadio.TRadiobutton').pack(side='left', padx=2)
        self._field(pad, self._t('source'), self.source, 'source')
        self.dest_row = self._field(pad, self._t('destination'), self.destination, 'destination')
        self.key_row = self._field(pad, self._t('keyfile'), self.keyfile, 'keyfile')
        row = tk.Frame(pad, bg=PANEL)
        row.pack(fill='x', pady=(2, 4))
        self._label(row, self._t('pin'), GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 6))
        password_line = tk.Frame(row, bg=PANEL)
        password_line.pack(fill='x')
        self.pwd_entry = ttk.Entry(password_line, textvariable=self.password, show='•', style='KV.TEntry')
        self.pwd_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))
        ttk.Checkbutton(password_line, text=self._t('reveal'), variable=self.reveal,
                        command=self._toggle_reveal, style='KCheck.TCheckbutton').pack(side='left')
        self.confirm_row = tk.Frame(pad, bg=PANEL)
        self.confirm_row.pack(fill='x', pady=(8, 0))
        self._label(self.confirm_row, self._t('confirm'), GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 6))
        self.confirm_entry = ttk.Entry(self.confirm_row, textvariable=self.confirm, show='•', style='KV.TEntry')
        self.confirm_entry.pack(fill='x')
        bottom = tk.Frame(pad, bg=PANEL)
        bottom.pack(fill='x', pady=(17, 0))
        self.action = ttk.Button(bottom, text=self._t('encrypt_action'), command=self._run,
                                 style='KPrimary.TButton')
        self.action.pack(side='left')
        ttk.Button(bottom, text=self._t('generate_keyfile'), command=self._new_keyfile,
                   style='KV.TButton').pack(side='right')
        risk_frame = tk.Frame(self.vault_panel, bg=PANEL_ALT, highlightthickness=1, highlightbackground=BORDER)
        risk_frame.pack(fill='x', pady=(14, 0))
        self.risk = tk.Label(risk_frame, text='', bg=PANEL_ALT, fg=AMBER,
                             font=(self._font_family(), 10), justify='left', anchor='w', wraplength=700)
        self.risk.pack(fill='x', padx=16, pady=14)
        info = tk.Frame(self.vault_panel, bg=INK)
        info.pack(fill='both', expand=True, pady=(15, 0))
        self._label(info, self._t('events'), GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 7))
        self.console = tk.Text(info, height=6, bg='#09120D', fg=GREEN_DIM,
                               font=(self._font_family(), 9), wrap='word', relief='flat', state='disabled',
                               padx=14, pady=12, highlightbackground=BORDER, highlightthickness=1)
        self.console.pack(fill='both', expand=True)
        self._log(self._t('research_notice'))
        self._log(self._t('no_irreplaceable'))
        self._log(self._t('not_disk'))
        foot = tk.Frame(root, bg=INK)
        foot.pack(fill='x', pady=(14, 0))
        tk.Frame(root, bg=BORDER, height=1).pack(side='bottom', fill='x')
        self.status = self._label(foot, '●  ' + self._t('ready'), GREEN, 9, True)
        self.status.pack(side='left')
        self._label(foot, 'KRYPTA  ·  ' + self._t('experimental_footer'),
                    MUTED, 8).pack(side='right')

    def _show_module(self, index):
        if self.busy:
            return
        if index == 5:
            # Volume Lab opens a separate, explicitly labeled disposable-image
            # window. Keep the normal file vault selection and disk shielding
            # modules unchanged, and do not suggest system-disk protection.
            from .volume_lab_gui import open_volume_lab
            open_volume_lab(self)
            return
        if index == self.active_module:
            return
        names = tuple(self._t(key) for key in
                      ('file_vault', 'drive_shield', 'system_shield', 'password_shield', 'android_shield'))
        summaries = ('', self._t('future_drive'), self._t('future_system'),
                     self._t('future_password'), self._t('future_android'))
        self.active_module = index
        self.volume_scan_button.pack_forget()
        self.physical_scan_button.pack_forget()
        self.volume_scan_results.pack_forget()
        self.volume_scan_note.pack_forget()
        for i, btn in enumerate(self.module_buttons):
            selected = i == index
            btn.configure(bg=PANEL_ALT if selected else INK,
                          fg=GREEN if selected else MUTED,
                          relief='solid' if selected else 'flat')
        self.module_title.configure(text=f'{index+1:02d} / {names[index]}')
        self.module_status.configure(text=('● ' + self._t('available')) if index == 0
                                     else ('◌ ' + self._t('planned')),
                                     fg=GREEN_DIM if index == 0 else AMBER)
        self.module_subtitle.configure(text=(
            self._t('vault_subtitle')
            if index == 0 else self._t('future_subtitle')))
        if index == 0:
            self.future_panel.pack_forget()
            self.vault_panel.pack(fill='both', expand=True)
        else:
            self.vault_panel.pack_forget()
            self.future_heading.configure(text=f'0{index+1}  /  {names[index]}')
            self.future_copy.configure(text=summaries[index])
            self.future_panel.pack(fill='both', expand=True)
            if index in (1, 2):
                self.volume_scan_button.pack(anchor='w', padx=25, pady=(0, 12))
                if index == 1:
                    self.physical_scan_button.pack(anchor='w', padx=25, pady=(0, 12))
                self.volume_scan_results.pack(fill='x', padx=25)
                self.volume_scan_note.pack(fill='x', padx=25, pady=(10, 20))


    def _scan_physical_devices(self):
        """Show physical hardware identity without any raw-device write path."""
        if self.busy:
            return
        self.physical_scan_button.configure(state='disabled')

        def work():
            try:
                report = inspect_physical_disks()
                presentation = json.dumps(report, ensure_ascii=False, indent=2)
            except Exception:
                presentation = "UNKNOWN: nie mozna odczytac listy dyskow; brak zmian."
            def done():
                if not self.winfo_exists():
                    return
                self.volume_scan_results.configure(state='normal')
                self.volume_scan_results.delete('1.0', 'end')
                self.volume_scan_results.insert('end', presentation)
                self.volume_scan_results.configure(state='disabled')
                self.physical_scan_button.configure(state='normal')
            self.after(0, done)
        threading.Thread(target=work, daemon=True).start()

    def _scan_volumes(self):
        """Run strictly read-only operating-system checks off the UI thread."""
        if self.busy:
            return
        self.volume_scan_button.configure(state='disabled')
        def work():
            try:
                report = inspect_volumes()
                presentation = json.dumps(report, ensure_ascii=False, indent=2)
            except Exception:
                presentation = "UNKNOWN: could not inspect encryption status"
            def done():
                if not self.winfo_exists():
                    return
                self.volume_scan_results.configure(state='normal')
                self.volume_scan_results.delete('1.0', 'end')
                self.volume_scan_results.insert('end', presentation)
                self.volume_scan_results.configure(state='disabled')
                self.volume_scan_button.configure(state='normal')
            self.after(0, done)
        threading.Thread(target=work, daemon=True).start()

    def _field(self, parent, label, var, role):
        frame = tk.Frame(parent, bg=PANEL)
        frame.pack(fill='x', pady=(0, 12))
        self._label(frame, label, GREEN_DIM, 9, True).pack(anchor='w', pady=(0, 6))
        line = tk.Frame(frame, bg=PANEL)
        line.pack(fill='x')
        entry = ttk.Entry(line, textvariable=var, style='KV.TEntry')
        entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        button = ttk.Button(line, text=self._t('browse'), style='KV.TButton',
                            command=lambda: self._choose(role))
        button.pack(side='left')
        return frame

    def _choose(self, role):
        if self.busy:
            return
        if role == 'destination':
            path = filedialog.asksaveasfilename(title=self._t('output_title'))
            if path:
                self.destination.set(path)
        else:
            path = filedialog.askopenfilename(title=self._t('input_title') if role == 'source'
                                               else self._t('key_title'))
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
            self.action.configure(text=self._t('inspect_action'))
        else:
            # Avoid reordering by explicitly packing each row ahead of the PIN section.
            self.dest_row.pack(fill='x', pady=(0, 12), before=self.pwd_entry.master.master)
            self.key_row.pack(fill='x', pady=(0, 12), before=self.pwd_entry.master.master)
            if mode == 'encrypt':
                self.confirm_row.pack(fill='x', pady=(8, 0), before=self.action.master)
            else:
                self.confirm_row.pack_forget()
            self.pwd_entry.configure(state='normal')
            self.action.configure(text=self._t('encrypt_action') if mode == 'encrypt'
                                  else 'DECRYPT TEST FILE  →')
        self._update_advisory()

    def _update_advisory(self):
        if self.mode.get() == 'info':
            key = 'advice_header'
        elif not self.password.get():
            key = 'advice_empty'
        elif bool(self.keyfile.get().strip()):
            key = 'advice_key'
        elif len(self.password.get()) <= 4:
            key = 'advice_short'
        elif len(self.password.get()) < 12:
            key = 'advice_medium'
        else:
            key = 'advice_strong'
        self.risk.configure(text='▸  ' + self._t(key),
                            fg=RED if key == 'advice_short' else AMBER)

    def _log(self, line):
        self.console.configure(state='normal')
        self.console.insert('end', f'> {line}\n')
        self.console.see('end')
        self.console.configure(state='disabled')

    def _set_busy(self, busy, status):
        self.busy = busy
        self.action.configure(state='disabled' if busy else 'normal')
        self.lang_picker.configure(state='disabled' if busy else 'readonly')
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
            messagebox.showwarning('KRYPTA', self._t('missing_path'))
            return
        if mode != 'info' and not pw:
            messagebox.showwarning('KRYPTA', self._t('empty_password'))
            return
        if mode == 'encrypt' and pw != self.confirm.get():
            messagebox.showwarning('KRYPTA', self._t('mismatch'))
            return
        if mode == 'encrypt' and len(pw) <= 4 and not key:
            if not messagebox.askyesno('KRYPTA / ' + self._t('risk_title'),
                    self._t('risk_confirm')):
                return
        if mode != 'info' and Path(dst).exists():
            messagebox.showerror('KRYPTA', self._t('exists'))
            return
        self._set_busy(True, self._t('processing'))
        self._log(f'{mode.upper()} — ' + self._t('operation_log'))
        # Keep Tk on main thread; cryptographic work runs on worker thread.
        def job():
            try:
                if mode == 'info':
                    result = file_info(src)
                    if self.language_code != 'pl':
                        result['verification'] = self._t('advice_header')
                    msg = json.dumps(result, ensure_ascii=False, indent=2)
                elif mode == 'encrypt':
                    encrypt_file(src, dst, pw, key)
                    msg = self._t('encrypt_ok')
                else:
                    decrypt_file(src, dst, pw, key)
                    msg = self._t('decrypt_ok')
            except (CryptoError, OSError, ValueError) as exc:
                detail = str(exc) if self.language_code == 'pl' else self._t('failure')
                self.after(0, lambda m=detail: self._complete(False, m))
            except Exception:
                self.after(0, lambda: self._complete(False, self._t('unexpected')))
            else:
                self.after(0, lambda m=msg: self._complete(True, m))
        threading.Thread(target=job, daemon=True).start()
        # Remove references from entry widgets while operation runs; Python may retain strings.
        self.password.set('')
        self.confirm.set('')

    def _complete(self, ok, message):
        self._set_busy(False, self._t('ready') if ok else self._t('failed'))
        if ok:
            self._log('SUCCESS  /  ' + message)
            if '\n' in message:
                self._log(message)
            messagebox.showinfo('KRYPTA / ' + self._t('success'), message)
        else:
            self._log('ERROR  /  ' + message)
            messagebox.showerror('KRYPTA / ' + self._t('failure'), message)

    def _new_keyfile(self):
        if self.busy:
            return
        path = filedialog.asksaveasfilename(title=self._t('choose_key'),
                                             defaultextension='.key')
        if not path:
            return
        if not messagebox.askyesno('KRYPTA',
                self._t('key_backup_question')):
            return
        try:
            generate_keyfile(path)
        except (OSError, ValueError, CryptoError) as exc:
            messagebox.showerror('KRYPTA / ' + self._t('failure'), str(exc) if self.language_code == 'pl' else self._t('failure'))
            return
        self.keyfile.set(path)
        self._log(self._t('key_log'))
        messagebox.showinfo('KRYPTA / Keyfile', self._t('key_created'))


def main():
    app = KryptaApp()
    app.mainloop()


if __name__ == '__main__':
    main()