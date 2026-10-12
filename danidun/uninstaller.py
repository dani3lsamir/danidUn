"""Builds a validated uninstall plan from registry data and runs it."""
from __future__ import annotations

import logging
import ntpath
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from . import appx, winapi
from .cmdline import parse_command, quote_arg
from .models import Program, Source
from .registry import system32
from .textutil import GUID_RE, find_guid

log = logging.getLogger(__name__)

# Executables that would interpret arbitrary code from an attacker-controlled registry value.
DISALLOWED = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "bash.exe", "wsl.exe", "conhost.exe", "explorer.exe", "msbuild.exe", "installutil.exe",
    "certutil.exe", "bitsadmin.exe", "schtasks.exe", "sc.exe", "reg.exe", "net.exe", "net1.exe", "wmic.exe",
    "forfiles.exe", "pcalua.exe", "msdt.exe", "hh.exe", "control.exe", "regasm.exe", "regsvcs.exe",
    "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe", "curl.exe", "ftp.exe",
}


class UnsupportedCommand(ValueError):
    """The registered uninstall command cannot be executed safely."""


@dataclass
class UninstallPlan:
    program: Program
    kind: str                  # msi | exe | store
    executable: str
    arguments: str = ""        # raw argument string handed to the executable (no shell)
    quiet: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def command_line(self) -> str:
        return (quote_arg(self.executable) + (" " + self.arguments if self.arguments else "")).strip()

    def to_dict(self) -> dict:
        return {"kind": self.kind, "executable": self.executable, "arguments": self.arguments,
                "quiet": self.quiet, "notes": self.notes}


def build_plan(program: Program, quiet: bool = False, exists: Callable[[str], bool] = os.path.isfile) -> UninstallPlan:
    if program.source == Source.STORE:
        cmd = appx.removal_command(program.package_full_name)
        return UninstallPlan(program, "store", cmd[0], " ".join(quote_arg(a) for a in cmd[1:]))

    if program.no_remove:
        raise UnsupportedCommand("err.no_remove")

    raw = program.quiet_uninstall_string if quiet and program.quiet_uninstall_string else program.uninstall_string
    product = program.product_code or (find_guid(raw) if "msiexec" in raw.casefold() else "")
    if product and GUID_RE.fullmatch(product):
        args = f"/x {product}" + (" /passive /norestart" if quiet else "")
        return UninstallPlan(program, "msi", system32("msiexec.exe"), args, quiet)

    if not raw.strip():
        raise UnsupportedCommand("err.no_command")
    parsed = parse_command(raw, exists=exists)
    exe = parsed.executable
    base = ntpath.basename(exe).casefold()
    if base in DISALLOWED or (base + ".exe") in DISALLOWED:
        raise UnsupportedCommand("err.disallowed_interpreter")
    if not base.endswith(".exe"):
        raise UnsupportedCommand("err.not_exe")
    if not parsed.resolved:
        raise UnsupportedCommand("err.uninstaller_missing")
    if not (os.path.isabs(exe) or ntpath.isabs(exe)):
        raise UnsupportedCommand("err.relative_path")
    plan = UninstallPlan(program, "exe", exe, parsed.arguments, quiet and bool(program.quiet_uninstall_string))
    if quiet and not program.quiet_uninstall_string:
        plan.notes.append("note.no_quiet_string")
    return plan


@dataclass
class RunResult:
    exit_code: int | None
    outcome: str  # success | reboot | cancelled | not_installed | failed | busy | unknown
    elevated: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {"exit_code": self.exit_code, "outcome": self.outcome, "elevated": self.elevated, "error": self.error}


def interpret(kind: str, code: int | None) -> str:
    if code is None:
        return "unknown"
    if kind == "msi":
        return {0: "success", 1605: "not_installed", 1614: "success", 1602: "cancelled", 1223: "cancelled",
                3010: "reboot", 1641: "reboot", 1618: "busy"}.get(code, "failed")
    if code == 0:
        return "success"
    if code in (1223, 1602):
        return "cancelled"
    if code in (3010, 1641):
        return "reboot"
    return "failed"


def execute(plan: UninstallPlan, cancel=None, on_tick=None) -> RunResult:
    """Launch the uninstaller (no shell) and wait for it and every child process."""
    if not winapi.IS_WINDOWS:
        return RunResult(None, "unknown", error="Windows required")
    baseline = set(winapi.process_snapshot())
    elevated = False
    try:
        proc = subprocess.Popen(plan.command_line, shell=False, cwd=os.path.dirname(plan.executable) or None)
        pid, poll = proc.pid, proc.poll
    except OSError as exc:
        if getattr(exc, "winerror", None) != winapi.ERROR_ELEVATION_REQUIRED:
            return RunResult(None, "failed", error=str(exc))
        try:
            ep = winapi.ElevatedProcess(plan.executable, plan.arguments, os.path.dirname(plan.executable) or None)
        except OSError as exc2:
            outcome = "cancelled" if exc2.errno == winapi.ERROR_CANCELLED else "failed"
            return RunResult(None, outcome, error=str(exc2))
        pid, poll, elevated = ep.pid, ep.poll, True
    log.info("uninstaller started pid=%s elevated=%s: %s", pid, elevated, plan.command_line)
    code = winapi.wait_for_tree(pid, poll, baseline, cancel=cancel, on_tick=on_tick)
    log.info("uninstaller finished code=%s", code)
    return RunResult(code, interpret(plan.kind, code), elevated)


def find_bundled_uninstallers(folder: str, limit: int = 10) -> list[str]:
    """Uninstallers shipped inside an install folder (used by forced uninstall)."""
    pattern = re.compile(r"^(unins\d{3}|uninstall\w*|uninst\w*|remove\w*)\.exe$", re.I)
    found = []
    try:
        for entry in os.scandir(folder):
            if entry.is_file() and pattern.match(entry.name):
                found.append(entry.path)
    except OSError:
        return []
    return sorted(found)[:limit]
