"""Guided workflow: prepare → (restore point) → uninstaller → verify → scan → review → quarantine → report."""
from __future__ import annotations

import logging
import os
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .. import uninstaller, winapi
from ..config import reports_dir
from ..i18n import t
from ..models import Program, Source
from ..paths import human_size
from ..reports import OperationReport
from ..scanner import AppIdentity, ScanMode, run_scan
from ..uninstaller import UninstallPlan, UnsupportedCommand
from . import theme
from .results import LeftoverView

log = logging.getLogger(__name__)
MODES = (ScanMode.SAFE, ScanMode.MODERATE, ScanMode.ADVANCED)


class Wizard(tk.Toplevel):
    def __init__(self, app, program: Program, mode: str) -> None:
        super().__init__(app)
        self.app = app
        self.program = program
        self.mode = mode  # uninstall | forced | scan
        self.cancel = threading.Event()
        self.busy = False
        self.report = OperationReport(mode, program)
        self.started = False
        self.result = None
        self.plan: UninstallPlan | None = None
        self.plan_error = ""
        self.bundled = uninstaller.find_bundled_uninstallers(program.install_location) \
            if mode == "forced" and program.install_location else []

        self.title(t("wiz.title." + mode, name=program.name))
        self.geometry("980x680")
        self.minsize(760, 520)
        self.configure(bg=theme.BG)
        self.transient(app)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.body = ttk.Frame(self, padding=18)
        self.body.pack(fill="both", expand=True)

        self.quiet = tk.BooleanVar(value=False)
        self.restore_point = tk.BooleanVar(value=app.settings.create_restore_point and winapi.is_admin())
        self.scan_mode = tk.IntVar(value=int(ScanMode[app.settings.scan_mode]) if app.settings.scan_mode in
                                   ScanMode.__members__ else int(ScanMode.MODERATE))
        self.run_bundled = tk.StringVar(value="")
        if mode == "uninstall":
            self._make_plan()
        self.show_prepare()

    # ------------------------------------------------------------------ helpers
    def _clear(self) -> None:
        for child in self.body.winfo_children():
            child.destroy()

    def _header(self, subtitle: str = "") -> None:
        ttk.Label(self.body, text=self.program.name, style="H2.TLabel").pack(anchor="w")
        bits = [b for b in (self.program.publisher, self.program.version, self.program.install_location) if b]
        ttk.Label(self.body, text="  ·  ".join(bits) or subtitle, style="Muted.TLabel").pack(anchor="w", pady=(2, 10))

    def _make_plan(self) -> None:
        try:
            self.plan = uninstaller.build_plan(self.program, quiet=self.quiet.get())
            self.plan_error = ""
        except UnsupportedCommand as exc:
            self.plan, self.plan_error = None, t(str(exc))
        except ValueError as exc:
            self.plan, self.plan_error = None, str(exc)

    # ------------------------------------------------------------------ page 1
    def show_prepare(self) -> None:
        self._clear()
        self._header()
        warnings = list(self.program.flags)
        if self.program.source == Source.STORE and self.program.publisher.casefold().startswith("microsoft"):
            warnings.append("store_microsoft")
        if not winapi.is_admin() and (self.program.hive == "HKLM" or self.mode == "forced"):
            warnings.append("not_admin")
        for st in self.program.status:
            ttk.Label(self.body, text="⚠ " + t("state." + st.value), style="Warn.TLabel").pack(anchor="w")
        for flag in warnings:
            ttk.Label(self.body, text="⚠ " + t("flag." + flag), style="Warn.TLabel", wraplength=900).pack(anchor="w")

        if self.mode == "uninstall":
            box = ttk.Frame(self.body, style="Card.TFrame", padding=12)
            box.pack(fill="x", pady=12)
            if self.plan:
                ttk.Label(box, text=t("wiz.command"), style="CardMuted.TLabel").pack(anchor="w")
                ttk.Label(box, text=self.plan.command_line, style="Card.TLabel", wraplength=880,
                          font=("Consolas", 10)).pack(anchor="w", pady=(4, 0))
                for note in self.plan.notes:
                    ttk.Label(box, text=t(note), style="CardMuted.TLabel").pack(anchor="w")
            else:
                ttk.Label(box, text=t("wiz.unsupported", reason=self.plan_error), style="Card.TLabel",
                          wraplength=880, foreground=theme.DANGER).pack(anchor="w")
            if self.program.quiet_uninstall_string or self.program.source == Source.MSI:
                ttk.Checkbutton(self.body, text=t("wiz.quiet"), variable=self.quiet,
                                command=lambda: (self._make_plan(), self.show_prepare())).pack(anchor="w")
        elif self.mode == "forced":
            ttk.Label(self.body, text=t("wiz.forced.info"), wraplength=900).pack(anchor="w", pady=(8, 8))
            if self.bundled:
                ttk.Label(self.body, text=t("wiz.bundled"), style="Muted.TLabel").pack(anchor="w")
                ttk.Radiobutton(self.body, text="—", value="", variable=self.run_bundled).pack(anchor="w", padx=12)
                for path in self.bundled:
                    ttk.Radiobutton(self.body, text=path, value=path, variable=self.run_bundled).pack(anchor="w", padx=12)

        if self.mode != "scan":
            admin = winapi.is_admin()
            ttk.Checkbutton(self.body, text=t("wiz.restore_point" if admin else "wiz.restore_point_admin"),
                            variable=self.restore_point, state="normal" if admin else "disabled").pack(anchor="w", pady=(8, 0))

        frame = ttk.LabelFrame(self.body, text=t("wiz.mode"), padding=10)
        frame.pack(fill="x", pady=14)
        for mode in MODES:
            name = mode.name.lower()
            row = ttk.Frame(frame)
            row.pack(fill="x", anchor="w")
            ttk.Radiobutton(row, text=t("mode." + name), value=int(mode), variable=self.scan_mode, width=14).pack(side="left")
            ttk.Label(row, text=t(f"mode.{name}.desc"), style="Muted.TLabel").pack(side="left")

        buttons = ttk.Frame(self.body)
        buttons.pack(fill="x", side="bottom")
        ttk.Button(buttons, text=t("cancel"), command=self.close).pack(side="right")
        can_start = self.mode != "uninstall" or self.plan is not None
        ttk.Button(buttons, text=t("wiz.start"), style="Accent.TButton", command=self.start,
                   state="normal" if can_start else "disabled").pack(side="right", padx=8)
        if self.mode == "uninstall" and self.plan is None:
            ttk.Button(buttons, text=t("tb.forced"), command=self._switch_to_forced).pack(side="right")

    def _switch_to_forced(self) -> None:
        self.destroy()
        self.app.open_forced(self.program)

    # ------------------------------------------------------------------ page 2
    def start(self) -> None:
        self.started = True
        self.busy = True
        self._clear()
        self._header()
        self.progress = ttk.Progressbar(self.body, mode="indeterminate")
        self.progress.pack(fill="x", pady=(4, 10))
        self.progress.start(12)
        self.log_box = theme.text_widget(self.body, height=20, font=("Consolas", 10))
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")
        options = {"restore_point": self.restore_point.get(), "mode": ScanMode(self.scan_mode.get()),
                   "bundled": self.run_bundled.get()}
        self.app.dispatcher.run(lambda: self._work(options), self._scan_done, self._failed)

    def log(self, text: str) -> None:
        self.app.dispatcher.post(self._append, text)

    def _append(self, text: str) -> None:
        if not self.winfo_exists():
            return
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _work(self, options: dict):
        rt = self.app.runtime
        programs = self.app.all_programs()
        self.log(t("step.identity"))
        identity = AppIdentity.build(self.program, rt.others(self.program, programs))

        if options["restore_point"] and self.mode != "scan":
            self.log(t("step.restore_point"))
            ok, msg = rt.sysops.create_restore_point(f"{self.program.name}")
            self.report.restore_point = {"ok": ok, "message": msg}
            self.log(t("step.restore_ok") if ok else t("step.restore_fail", msg=msg))

        plan = None
        if self.mode == "uninstall":
            plan = self.plan
        elif self.mode == "forced" and options["bundled"]:
            plan = UninstallPlan(self.program, "exe", options["bundled"])
        if plan is not None:
            self.report.plan = plan.to_dict()
            self.log(t("step.run"))
            last: list[str] = []

            def tick(names):
                if names != last and names:
                    last[:] = names
                    self.log(t("step.waiting", names=", ".join(names)))

            run = uninstaller.execute(plan, cancel=self.cancel, on_tick=tick)
            self.report.run = run.to_dict()
            self.log(t("step.run_done", outcome=t("outcome." + run.outcome), code=run.exit_code))
            if run.error:
                self.log(run.error)
            self.log(t("step.verify"))
            fresh = rt.load_programs()
            still = rt.still_installed(self.program, fresh)
            folder = rt.folder_exists(self.program)
            self.report.verification = {
                ("package_removed" if self.program.source == Source.STORE else "entry_removed"): not still,
                **({"folder_removed": not folder} if folder is not None else {}),
            }
            if still and self.mode == "uninstall":
                go_on = self.app.dispatcher.ask(lambda: messagebox.askyesno(
                    self.title(), t("ask.still_installed", name=self.program.name), parent=self))
                if not go_on:
                    return None
            programs = fresh + [p for p in programs if p.source == Source.STORE]

        if self.cancel.is_set():
            return None
        ctx = rt.context(self.program, programs)

        def progress(stage, index, total):
            if stage != "done":
                self.log(t("step.scan", stage=t("cat." + stage)))

        result = run_scan(identity, ctx, options["mode"], progress=progress, cancel=self.cancel)
        self.log(t("step.scan_done", n=len(result.leftovers), s=result.elapsed))
        self.report.scan = result.to_dict()
        return result

    def _failed(self, exc: Exception) -> None:
        self.busy = False
        if self.winfo_exists():
            self.progress.stop()
            self._append(f"{t('err.title')}: {exc}")
            ttk.Button(self.body, text=t("close"), command=self.close).pack(anchor="e", pady=8)

    # ------------------------------------------------------------------ page 3
    def _scan_done(self, result) -> None:
        self.busy = False
        if not self.winfo_exists():
            return
        self.progress.stop()
        if result is None:
            ttk.Button(self.body, text=t("close"), command=self.close).pack(anchor="e", pady=8)
            return
        self.result = result
        self._clear()
        self._header()
        ttk.Label(self.body, text=t("res.header") if result.leftovers else t("res.none")).pack(anchor="w")
        if result.hidden_below_threshold:
            ttk.Label(self.body, text=t("res.hidden", n=result.hidden_below_threshold),
                      style="Muted.TLabel").pack(anchor="w")
        self.summary = tk.StringVar()
        self.view = LeftoverView(self.body, on_change=self._summary)
        self.view.pack(fill="both", expand=True, pady=10)
        ttk.Label(self.body, textvariable=self.summary, style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        bar = ttk.Frame(self.body)
        bar.pack(fill="x")
        ttk.Button(bar, text=t("wiz.finish"), command=self.close).pack(side="right")
        self.remove_btn = ttk.Button(bar, text=t("res.remove"), style="Danger.TButton", command=self.remove)
        self.remove_btn.pack(side="right", padx=8)
        ttk.Button(bar, text=t("res.select_high"), command=lambda: self.view.select_recommended()).pack(side="left")
        ttk.Button(bar, text=t("res.select_none"), command=lambda: self.view.select_none()).pack(side="left", padx=8)
        self.view.load(result.leftovers)

    def _summary(self, total: int, selected: int, size: int) -> None:
        self.summary.set(t("res.summary", total=total, sel=selected, size=human_size(size) or "0 B"))
        if hasattr(self, "remove_btn"):
            self.remove_btn.configure(state="normal" if selected else "disabled")

    def remove(self) -> None:
        items = self.view.selected()
        if not items or self.busy:
            return
        preview = "\n".join("• " + lo.display for lo in items[:10]) + ("\n…" if len(items) > 10 else "")
        if not messagebox.askyesno(t("res.remove"), t("res.confirm", n=len(items), preview=preview), parent=self):
            return
        self.busy = True
        self.remove_btn.configure(state="disabled")
        rt = self.app.runtime

        def work():
            programs = rt.load_programs() + [p for p in self.app.all_programs() if p.source == Source.STORE]
            policy = rt.policy(self.program, programs)
            return rt.quarantine.remove(self.program.name, items, policy)

        self.app.dispatcher.run(work, self._removed, self._remove_failed)

    def _removed(self, session) -> None:
        self.busy = False
        self.report.removal = {"session": str(session.path), "items": [i.to_dict() for i in session.items]}
        counts = {k: sum(1 for i in session.items if i.status == k) for k in ("removed", "partial", "failed", "skipped")}
        self.view.mark_results([(i.leftover, i.status) for i in session.items])
        msg = t("res.done", ok=counts["removed"], partial=counts["partial"], failed=counts["failed"],
                skipped=counts["skipped"])
        problems = [f"• {i.leftover.display}: {t(i.error.split(':', 1)[0]) if i.error.startswith('protect.') else i.error}"
                    for i in session.items if i.status in ("failed", "skipped")][:8]
        if counts["partial"]:
            problems.append(t("res.locked"))
        messagebox.showinfo(t("res.remove"), msg + ("\n\n" + "\n".join(problems) if problems else ""), parent=self)

    def _remove_failed(self, exc: Exception) -> None:
        self.busy = False
        self.remove_btn.configure(state="normal")
        messagebox.showerror(t("err.title"), str(exc), parent=self)

    # ------------------------------------------------------------------ close
    def close(self) -> None:
        if self.busy:
            self.cancel.set()  # stops waiting/scanning; never kills a running uninstaller
            return
        if self.started:
            try:
                _json, html = self.report.save(reports_dir(), t)
                if messagebox.askyesno(t("wiz.finish"), t("report.saved", path=html) + "\n\n" + t("report.open") + "?",
                                       parent=self):
                    winapi.open_in_explorer(str(html))
            except OSError as exc:
                log.warning("could not save report: %s", exc)
            self.app.refresh()
        self.destroy()


def open_path(path: str) -> None:
    if os.path.exists(path):
        winapi.open_in_explorer(path)
