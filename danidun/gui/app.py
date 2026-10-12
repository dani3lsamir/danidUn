"""Main window: installed-application manager."""
from __future__ import annotations

import base64
import logging
import tkinter as tk
from tkinter import messagebox, ttk

from .. import APP_NAME, __version__, icons, winapi
from ..config import Settings, reports_dir
from ..i18n import t
from ..models import Program, Source
from ..paths import human_size
from ..quarantine import default_base
from . import theme
from .dialogs import ForcedDialog, QuarantineDialog, SettingsDialog
from .wizard import Wizard
from .worker import Dispatcher

log = logging.getLogger(__name__)
FILTERS = ("all", "win32", "msi", "store", "user", "broken")
COLUMNS = (("publisher", "col.publisher", 220), ("version", "col.version", 110), ("size", "col.size", 90),
           ("date", "col.date", 100), ("type", "col.type", 140))


class MainWindow(tk.Tk):
    def __init__(self, runtime, settings: Settings) -> None:
        super().__init__()
        self.runtime = runtime
        self.settings = settings
        self.dispatcher = Dispatcher(self)
        self.win32: list[Program] = []
        self.store: list[Program] = []
        self.store_loaded = False
        self.visible: list[Program] = []
        self.sort_key, self.sort_reverse = "name", False
        self.icon_images: dict[str, tk.PhotoImage] = {}
        self.icon_pending: set[str] = set()

        self.title(f"{APP_NAME} {__version__}")
        self.geometry("1180x740")
        self.minsize(900, 560)
        theme.apply(self)
        self._menu()
        self._header()
        self._toolbar()
        self._filters()
        self._table()
        self._details()
        self._statusbar()
        self.bind("<F5>", lambda _e: self.refresh())
        self.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.bind("<Delete>", lambda _e: self.uninstall())
        self.after(100, self.refresh)

    # ------------------------------------------------------------------ layout
    def _menu(self) -> None:
        bar = tk.Menu(self)
        file_menu = tk.Menu(bar, tearoff=False)
        file_menu.add_command(label=t("tb.refresh"), accelerator="F5", command=self.refresh)
        file_menu.add_command(label=t("tb.reports"), command=self.open_reports)
        file_menu.add_separator()
        file_menu.add_command(label=t("menu.exit"), command=self.destroy)
        tools = tk.Menu(bar, tearoff=False)
        tools.add_command(label=t("tb.forced"), command=lambda: self.open_forced(self.current()))
        tools.add_command(label=t("tb.quarantine"), command=lambda: QuarantineDialog(self))
        tools.add_separator()
        tools.add_command(label=t("menu.settings"), command=lambda: SettingsDialog(self))
        help_menu = tk.Menu(bar, tearoff=False)
        help_menu.add_command(label=t("menu.open_log"), command=lambda: winapi.open_in_explorer(str(default_base() / "logs")))
        help_menu.add_command(label=t("menu.about"), command=lambda: messagebox.showinfo(
            APP_NAME, t("about.text", version=__version__), parent=self))
        bar.add_cascade(label=t("menu.file"), menu=file_menu)
        bar.add_cascade(label=t("menu.tools"), menu=tools)
        bar.add_cascade(label=t("menu.help"), menu=help_menu)
        self.config(menu=bar)

    def _header(self) -> None:
        head = ttk.Frame(self, padding=(20, 14, 20, 4))
        head.pack(fill="x")
        ttk.Label(head, text="danidUn", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text=t("app.subtitle"), style="Muted.TLabel").pack(side="left", padx=(12, 0), pady=(10, 0))
        admin = winapi.is_admin()
        if not admin and winapi.IS_WINDOWS:
            ttk.Button(head, text=t("admin.restart"), style="Link.TButton", command=self.restart_admin).pack(side="right")
        ttk.Label(head, text=t("admin.yes" if admin else "admin.no"),
                  style="BadgeAdmin.TLabel" if admin else "Badge.TLabel").pack(side="right", padx=8)

    def _toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(20, 8))
        bar.pack(fill="x")
        ttk.Button(bar, text=t("tb.uninstall"), style="Accent.TButton", command=self.uninstall).pack(side="left")
        ttk.Button(bar, text=t("tb.forced"), command=lambda: self.open_forced(self.current())).pack(side="left", padx=6)
        ttk.Button(bar, text=t("tb.scan"), command=self.scan_only).pack(side="left")
        ttk.Button(bar, text=t("tb.refresh"), command=self.refresh).pack(side="right")
        ttk.Button(bar, text=t("tb.reports"), command=self.open_reports).pack(side="right", padx=6)
        ttk.Button(bar, text=t("tb.quarantine"), command=lambda: QuarantineDialog(self)).pack(side="right")

    def _filters(self) -> None:
        bar = ttk.Frame(self, padding=(20, 4))
        bar.pack(fill="x")
        ttk.Label(bar, text=t("search")).pack(side="left")
        self.search = tk.StringVar()
        self.search_entry = ttk.Entry(bar, textvariable=self.search, width=40)
        self.search_entry.pack(side="left", padx=8, fill="x", expand=True)
        self.search.trace_add("write", lambda *_: self.apply_filter())
        ttk.Label(bar, text=t("filter")).pack(side="left", padx=(12, 6))
        self.filter_labels = {t("filter." + f): f for f in FILTERS}
        self.filter = tk.StringVar(value=t("filter.all"))
        box = ttk.Combobox(bar, textvariable=self.filter, values=list(self.filter_labels), state="readonly", width=18)
        box.pack(side="left")
        box.bind("<<ComboboxSelected>>", lambda _e: self.apply_filter())

    def _table(self) -> None:
        frame = ttk.Frame(self, padding=(20, 8, 20, 0))
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLUMNS], show="tree headings", selectmode="browse")
        self.tree.heading("#0", text=t("col.name"), command=lambda: self.sort_by("name"))
        self.tree.column("#0", width=380, stretch=True)
        for col, key, width in COLUMNS:
            self.tree.heading(col, text=t(key), command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=width, stretch=col == "publisher", anchor="e" if col == "size" else "w")
        self.tree.tag_configure("broken", foreground=theme.WARNING)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_details())
        self.tree.bind("<Double-1>", lambda _e: self.uninstall())
        self.tree.bind("<Button-3>", self._context_menu)
        self.blank_icon = tk.PhotoImage(width=16, height=16)

    def _details(self) -> None:
        card = ttk.Frame(self, style="Card.TFrame", padding=12)
        card.pack(fill="x", padx=20, pady=10)
        self.detail_vars = {}
        for row, key in enumerate(("detail.location", "detail.command", "detail.key", "detail.status")):
            ttk.Label(card, text=t(key), style="CardMuted.TLabel", width=14).grid(row=row, column=0, sticky="nw")
            var = tk.StringVar()
            ttk.Label(card, textvariable=var, style="Card.TLabel", wraplength=900).grid(row=row, column=1, sticky="w")
            self.detail_vars[key] = var
        self.open_btn = ttk.Button(card, text=t("detail.open_folder"), command=self.open_folder)
        self.open_btn.grid(row=0, column=2, rowspan=2, sticky="ne")
        card.columnconfigure(1, weight=1)

    def _statusbar(self) -> None:
        bar = ttk.Frame(self, padding=(20, 0, 20, 10))
        bar.pack(fill="x")
        self.status = tk.StringVar()
        ttk.Label(bar, textvariable=self.status, style="Muted.TLabel").pack(side="left")
        self.busy_bar = ttk.Progressbar(bar, mode="indeterminate", length=160)

    def _busy(self, on: bool) -> None:
        if on:
            self.busy_bar.pack(side="right")
            self.busy_bar.start(12)
        else:
            self.busy_bar.stop()
            self.busy_bar.pack_forget()

    # ------------------------------------------------------------------ data
    def all_programs(self) -> list[Program]:
        return self.win32 + self.store

    def refresh(self) -> None:
        self.status.set(t("status.loading"))
        self._busy(True)
        self.dispatcher.run(self.runtime.load_programs, self._loaded, self._load_failed)

    def _loaded(self, programs: list[Program]) -> None:
        self.win32 = programs
        self._busy(False)
        self.apply_filter()
        if self.settings.show_store_apps:
            self.status.set(t("status.loading_store"))
            self._busy(True)
            self.dispatcher.run(self.runtime.load_store_apps, self._store_loaded, self._load_failed)
        else:
            self.store = []
            self.apply_filter()

    def _store_loaded(self, programs: list[Program]) -> None:
        self.store = programs
        self._busy(False)
        self.apply_filter()

    def _load_failed(self, exc: Exception) -> None:
        self._busy(False)
        messagebox.showerror(t("err.title"), str(exc), parent=self)

    def _matches(self, p: Program, kind: str) -> bool:
        return {
            "all": True, "win32": p.source == Source.WIN32, "msi": p.source == Source.MSI,
            "store": p.source == Source.STORE, "user": p.scope == "user" and p.source != Source.STORE,
            "broken": p.is_broken or bool(p.status),
        }[kind]

    def apply_filter(self) -> None:
        needle = self.search.get().casefold().strip()
        kind = self.filter_labels.get(self.filter.get(), "all")
        items = [p for p in self.all_programs()
                 if self._matches(p, kind) and needle in f"{p.name} {p.publisher}".casefold()]
        key = {
            "name": lambda p: p.name.casefold(), "publisher": lambda p: p.publisher.casefold(),
            "version": lambda p: p.version, "size": lambda p: p.size_kb, "date": lambda p: p.install_date,
            "type": lambda p: p.source.value,
        }[self.sort_key]
        self.visible = sorted(items, key=key, reverse=self.sort_reverse)
        self.tree.delete(*self.tree.get_children())
        for index, p in enumerate(self.visible):
            image = self.icon_images.get(p.display_icon) or self.blank_icon
            kind_label = t("type." + p.source.value) + ("" if p.source == Source.STORE else f" · {p.architecture}")
            self.tree.insert("", "end", iid=str(index), text=("⚠ " if p.is_broken else "") + p.name, image=image,
                             values=(p.publisher, p.version, human_size(p.size_kb * 1024), p.install_date, kind_label),
                             tags=("broken",) if p.is_broken else ())
        self.status.set(t("status.count", n=len(self.all_programs()), shown=len(self.visible)))
        self._load_icons()

    def sort_by(self, key: str) -> None:
        self.sort_reverse = not self.sort_reverse if self.sort_key == key else False
        self.sort_key = key
        self.apply_filter()

    def _load_icons(self) -> None:
        wanted = {p.display_icon for p in self.visible if p.display_icon} - set(self.icon_images) - self.icon_pending
        if not wanted or not winapi.IS_WINDOWS:
            return
        self.icon_pending |= wanted

        def work():
            for source in wanted:
                data = icons.icon_png(source)
                self.dispatcher.post(self._icon_ready, source, data)

        self.dispatcher.run(work)

    def _icon_ready(self, source: str, data: bytes | None) -> None:
        self.icon_pending.discard(source)
        if not data:
            self.icon_images[source] = self.blank_icon
            return
        try:
            image = tk.PhotoImage(data=base64.b64encode(data))
        except tk.TclError:
            image = self.blank_icon
        self.icon_images[source] = image
        for index, p in enumerate(self.visible):
            if p.display_icon == source and self.tree.exists(str(index)):
                self.tree.item(str(index), image=image)

    # ------------------------------------------------------------------ selection
    def current(self) -> Program | None:
        sel = self.tree.selection()
        return self.visible[int(sel[0])] if sel else None

    def show_details(self) -> None:
        p = self.current()
        if not p:
            return
        loc = p.install_location + (f"  {t('detail.inferred')}" if p.location_inferred else "")
        command = p.uninstall_string or (f"Remove-AppxPackage {p.package_full_name}" if p.source == Source.STORE else "—")
        key = f"{p.hive}\\{p.key_path}" + (" [32-bit]" if p.view == 32 and p.hive == "HKLM" else "") if p.key_path else \
            (p.package_full_name or "—")
        status = "; ".join(t("state." + s.value) for s in p.status) or t("detail.ok")
        self.detail_vars["detail.location"].set(loc or "—")
        self.detail_vars["detail.command"].set(command)
        self.detail_vars["detail.key"].set(key)
        self.detail_vars["detail.status"].set(status)

    def _context_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=t("tb.uninstall"), command=self.uninstall)
        menu.add_command(label=t("tb.forced"), command=lambda: self.open_forced(self.current()))
        menu.add_command(label=t("tb.scan"), command=self.scan_only)
        menu.add_separator()
        menu.add_command(label=t("detail.open_folder"), command=self.open_folder)
        menu.add_command(label=t("ctx.copy_name"), command=self._copy_name)
        menu.tk_popup(event.x_root, event.y_root)

    def _copy_name(self) -> None:
        p = self.current()
        if p:
            self.clipboard_clear()
            self.clipboard_append(p.name)

    # ------------------------------------------------------------------ actions
    def _require(self) -> Program | None:
        p = self.current()
        if p is None:
            messagebox.showinfo(APP_NAME, t("status.select_first"), parent=self)
        return p

    def uninstall(self) -> None:
        p = self._require()
        if p:
            self.open_wizard(p, "uninstall")

    def scan_only(self) -> None:
        p = self._require()
        if p:
            self.open_wizard(p, "scan")

    def open_forced(self, selected: Program | None) -> None:
        ForcedDialog(self, selected)

    def open_wizard(self, program: Program, mode: str) -> None:
        Wizard(self, program, mode)

    def open_folder(self) -> None:
        p = self.current()
        if p and p.install_location:
            winapi.open_in_explorer(p.install_location)

    def open_reports(self) -> None:
        folder = reports_dir()
        folder.mkdir(parents=True, exist_ok=True)
        winapi.open_in_explorer(str(folder))

    def restart_admin(self) -> None:
        if winapi.relaunch_as_admin():
            self.destroy()
