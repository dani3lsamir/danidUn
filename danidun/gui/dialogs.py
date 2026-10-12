"""Forced-uninstall input, quarantine manager and settings dialogs."""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import winapi
from ..forced import ForcedInputError, ForcedRequest, build_forced_program
from ..i18n import t
from ..models import Kind, Program
from ..paths import norm
from ..scanner import ScanMode
from . import theme


class _Dialog(tk.Toplevel):
    def __init__(self, app, title: str, geometry: str) -> None:
        super().__init__(app)
        self.app = app
        self.title(title)
        self.geometry(geometry)
        self.configure(bg=theme.BG)
        self.transient(app)
        self.body = ttk.Frame(self, padding=18)
        self.body.pack(fill="both", expand=True)


class ForcedDialog(_Dialog):
    def __init__(self, app, selected: Program | None) -> None:
        super().__init__(app, t("forced.title"), "720x460")
        self.selected = selected
        self.use_entry = tk.BooleanVar(value=selected is not None)
        self.name = tk.StringVar()
        self.publisher = tk.StringVar()
        self.folder = tk.StringVar(value=selected.install_location if selected else "")
        self.exe = tk.StringVar()

        ttk.Label(self.body, text=t("forced.title"), style="H2.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(self.body, text=t("forced.intro"), wraplength=660, style="Muted.TLabel").grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(4, 12))
        row = 2
        if selected is not None:
            ttk.Checkbutton(self.body, text=t("forced.use_entry", name=selected.name), variable=self.use_entry,
                            command=self._toggle).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 8))
            row += 1
        self.entries = []
        for label, var, browse in ((t("forced.name"), self.name, None), (t("forced.publisher"), self.publisher, None),
                                   (t("forced.folder"), self.folder, self._browse_folder),
                                   (t("forced.exe"), self.exe, self._browse_exe)):
            ttk.Label(self.body, text=label).grid(row=row, column=0, sticky="w", pady=4)
            entry = ttk.Entry(self.body, textvariable=var, width=60)
            entry.grid(row=row, column=1, sticky="ew", pady=4, padx=8)
            self.entries.append(entry)
            if browse:
                ttk.Button(self.body, text=t("forced.browse"), command=browse).grid(row=row, column=2, sticky="w")
            row += 1
        self.body.columnconfigure(1, weight=1)
        buttons = ttk.Frame(self.body)
        buttons.grid(row=row + 1, column=0, columnspan=3, sticky="e", pady=(24, 0))
        ttk.Button(buttons, text=t("forced.next"), style="Accent.TButton", command=self._next).pack(side="right")
        ttk.Button(buttons, text=t("cancel"), command=self.destroy).pack(side="right", padx=8)
        self._toggle()

    def _toggle(self) -> None:
        state = "disabled" if self.use_entry.get() and self.selected is not None else "normal"
        for entry in self.entries[:2]:
            entry.configure(state=state)

    def _browse_folder(self) -> None:
        path = filedialog.askdirectory(parent=self, mustexist=True)
        if path:
            self.folder.set(path.replace("/", "\\"))

    def _browse_exe(self) -> None:
        path = filedialog.askopenfilename(parent=self, filetypes=[("Executable", "*.exe")])
        if path:
            self.exe.set(path.replace("/", "\\"))

    def _next(self) -> None:
        entry = self.selected if self.use_entry.get() else None
        folder = self.folder.get().strip()
        if entry is None and folder:
            # A registered entry already owns this folder: identify the program through it.
            for p in self.app.all_programs():
                if p.install_location and norm(p.install_location) == norm(folder):
                    if messagebox.askyesno(t("forced.title"), t("forced.use_entry", name=p.name) + "?", parent=self):
                        entry = p
                    break
        req = ForcedRequest(self.name.get(), self.publisher.get(), folder, self.exe.get(), entry)
        try:
            program = build_forced_program(req, self.app.runtime.policy(entry, self.app.all_programs()))
        except ForcedInputError as exc:
            messagebox.showerror(t("forced.title"), t(str(exc)), parent=self)
            return
        self.destroy()
        self.app.open_wizard(program, "forced")


class QuarantineDialog(_Dialog):
    def __init__(self, app) -> None:
        super().__init__(app, t("q.title"), "860x480")
        ttk.Label(self.body, text=t("q.intro"), style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        cols = ("date", "app", "items")
        self.tree = ttk.Treeview(self.body, columns=cols, show="headings", selectmode="browse")
        for col, key, width in (("date", "q.col.date", 180), ("app", "q.col.app", 420), ("items", "q.col.items", 140)):
            self.tree.heading(col, text=t(key))
            self.tree.column(col, width=width, stretch=col == "app")
        self.tree.pack(fill="both", expand=True)
        bar = ttk.Frame(self.body)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text=t("close"), command=self.destroy).pack(side="right")
        ttk.Button(bar, text=t("q.purge"), style="Danger.TButton", command=self._purge).pack(side="right", padx=8)
        ttk.Button(bar, text=t("q.open"), command=self._open).pack(side="right")
        ttk.Button(bar, text=t("q.restore"), style="Accent.TButton", command=self._restore).pack(side="right", padx=8)
        self._load()

    def _load(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.sessions = self.app.runtime.quarantine.sessions()
        for index, s in enumerate(self.sessions):
            restored = sum(1 for i in s.items if i.restored)
            count = f"{s.removed}" + (f" ({restored} ↺)" if restored else "")
            self.tree.insert("", "end", iid=str(index), values=(s.created.replace("T", " "), s.application, count))

    def _current(self):
        sel = self.tree.selection()
        return self.sessions[int(sel[0])] if sel else None

    def _restore(self) -> None:
        session = self._current()
        if not session or not messagebox.askyesno(t("q.restore"), t("q.confirm_restore"), parent=self):
            return
        rt = self.app.runtime

        def work():
            return rt.quarantine.restore(session, rt.policy(None, rt.load_programs()))

        def done(result):
            restored, errors = result
            details = "\n".join(errors[:6])
            if any(i.leftover.kind == Kind.SERVICE for i in session.items):
                details += "\n" + t("q.service_note")
            messagebox.showinfo(t("q.restore"), t("q.restored", n=restored, e=len(errors), details=details), parent=self)
            self._load()
            self.app.refresh()

        self.app.dispatcher.run(work, done, lambda exc: messagebox.showerror(t("err.title"), str(exc), parent=self))

    def _purge(self) -> None:
        session = self._current()
        if not session or not messagebox.askyesno(t("q.purge"), t("q.confirm_purge"), parent=self, icon="warning"):
            return
        try:
            self.app.runtime.quarantine.purge(session)
        except (OSError, RuntimeError) as exc:
            messagebox.showerror(t("err.title"), str(exc), parent=self)
        self._load()

    def _open(self) -> None:
        session = self._current()
        winapi.open_in_explorer(str(session.path if session else self.app.runtime.quarantine.base))


class SettingsDialog(_Dialog):
    def __init__(self, app) -> None:
        super().__init__(app, t("set.title"), "520x320")
        s = app.settings
        self.lang = tk.StringVar(value={"": t("set.auto"), "es": "Español", "en": "English"}.get(s.language, t("set.auto")))
        self.mode = tk.StringVar(value=t("mode." + s.scan_mode.lower()))
        self.restore = tk.BooleanVar(value=s.create_restore_point)
        self.store = tk.BooleanVar(value=s.show_store_apps)
        ttk.Label(self.body, text=t("set.language")).grid(row=0, column=0, sticky="w", pady=6)
        ttk.Combobox(self.body, textvariable=self.lang, state="readonly",
                     values=[t("set.auto"), "Español", "English"]).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Label(self.body, text=t("set.mode")).grid(row=1, column=0, sticky="w", pady=6)
        ttk.Combobox(self.body, textvariable=self.mode, state="readonly",
                     values=[t("mode." + m.name.lower()) for m in ScanMode]).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Checkbutton(self.body, text=t("set.restore"), variable=self.restore).grid(row=2, column=0, columnspan=2, sticky="w", pady=6)
        ttk.Checkbutton(self.body, text=t("set.store"), variable=self.store).grid(row=3, column=0, columnspan=2, sticky="w", pady=6)
        self.body.columnconfigure(1, weight=1)
        ttk.Button(self.body, text=t("set.save"), style="Accent.TButton", command=self._save).grid(
            row=5, column=1, sticky="e", pady=(24, 0))

    def _save(self) -> None:
        s = self.app.settings
        s.language = {"Español": "es", "English": "en"}.get(self.lang.get(), "")
        s.scan_mode = next((m.name for m in ScanMode if t("mode." + m.name.lower()) == self.mode.get()), "MODERATE")
        s.create_restore_point = self.restore.get()
        s.show_store_apps = self.store.get()
        s.save()
        self.destroy()
        self.app.refresh()
