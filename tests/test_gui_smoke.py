"""End-to-end GUI smoke test against the fake registry (skipped when Tk/display is unavailable)."""
import gc
import os
import time
from pathlib import Path

import pytest

from conftest import touch

tk = pytest.importorskip("tkinter")


def test_gui_end_to_end(folders, reg, tmp_path, monkeypatch):
    from tkinter import messagebox

    import danidun.runtime as rtmod
    from danidun.config import Settings
    from danidun.gui.app import MainWindow
    from danidun.gui.dialogs import QuarantineDialog
    from danidun.gui.wizard import Wizard
    from danidun.registry import HKCU, HKLM
    from fakes import FakeSysOps

    monkeypatch.setenv("LOCALAPPDATA", folders.local_appdata)
    monkeypatch.setattr(rtmod, "own_dirs", lambda: [str(tmp_path / "danidUn-data")])
    dialogs = []
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: dialogs.append(a) or True)
    monkeypatch.setattr(messagebox, "showinfo", lambda *a, **k: dialogs.append(a))
    monkeypatch.setattr(messagebox, "showerror", lambda *a, **k: pytest.fail(f"error dialog: {a}"))

    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    install = os.path.join(folders.program_files, "Acme Photo Studio")
    touch(os.path.join(install, "acmephoto.exe"))
    touch(os.path.join(folders.appdata, "Acme Photo Studio", "settings.ini"))
    reg.add_key(HKLM, uninstall + r"\AcmePS", {"DisplayName": "Acme Photo Studio 2.1", "InstallLocation": install,
                                               "UninstallString": os.path.join(install, "unins000.exe")})
    reg.add_key(HKCU, uninstall + r"\Bad", {"DisplayName": "Bad Tool", "UninstallString": "cmd.exe /c del x"})
    reg.add_key(HKCU, r"SOFTWARE\Acme Photo Studio", {"x": 1})

    runtime = rtmod.Runtime(registry=reg, sysops=FakeSysOps(), folders=folders)
    runtime.quarantine.base = Path(tmp_path, "q")
    gc.disable()  # pumping with update() instead of mainloop(): keep Tk finalizers on this thread
    try:
        app = MainWindow(runtime, Settings(show_store_apps=False))
    except tk.TclError as exc:  # no display / Tcl not installed on this machine
        gc.enable()
        pytest.skip(f"Tk unavailable: {exc}")

    def until(cond, timeout=15.0):
        end = time.time() + timeout
        while time.time() < end and not cond():
            app.update()
            time.sleep(0.02)
        return cond()

    try:
        assert until(lambda: len(app.tree.get_children()) == 2)
        bad = next(p for p in app.visible if p.name == "Bad Tool")
        w = Wizard(app, bad, "uninstall")
        assert w.plan is None and "interpreter" in w.plan_error
        w.destroy()

        acme = next(p for p in app.visible if p.name.startswith("Acme"))
        w = Wizard(app, acme, "scan")
        w.start()
        assert until(lambda: hasattr(w, "view"))
        selected = w.view.selected()
        assert {lo.display for lo in selected} >= {install, r"HKCU\SOFTWARE\Acme Photo Studio"}
        w.remove()
        assert until(lambda: bool(w.view.done))
        assert not os.path.exists(install)
        w.close()

        q = QuarantineDialog(app)
        q.tree.selection_set("0")
        q._restore()
        assert until(lambda: os.path.exists(install))
    finally:
        app.destroy()
        gc.enable()
