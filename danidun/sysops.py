"""Operations performed through built-in Windows tools with fixed, validated arguments.
No shell is ever involved; every argument is passed as a separate list item."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Protocol

from .registry import system32

SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,256}$")
TASK_PATH_RE = re.compile(r"^\\[^\"<>|*?\x00-\x1f]{1,400}$")
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class SystemOps(Protocol):
    def stop_service(self, name: str) -> None: ...
    def delete_service(self, name: str) -> None: ...
    def export_task(self, task_path: str, dest: Path) -> None: ...
    def delete_task(self, task_path: str) -> None: ...
    def create_task(self, task_path: str, xml_file: Path) -> None: ...
    def create_restore_point(self, description: str) -> tuple[bool, str]: ...


def _run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, creationflags=_NO_WINDOW)


def _check(result: subprocess.CompletedProcess, what: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{what}: {(result.stderr or result.stdout or '').strip() or result.returncode}")


class WinSystemOps:
    def stop_service(self, name: str) -> None:
        if not SERVICE_NAME_RE.match(name):
            raise ValueError("invalid service name")
        _run([system32("sc.exe"), "stop", name], timeout=60)  # may already be stopped

    def delete_service(self, name: str) -> None:
        if not SERVICE_NAME_RE.match(name):
            raise ValueError("invalid service name")
        _check(_run([system32("sc.exe"), "delete", name]), "sc delete")

    def export_task(self, task_path: str, dest: Path) -> None:
        if not TASK_PATH_RE.match(task_path):
            raise ValueError("invalid task path")
        result = subprocess.run([system32("schtasks.exe"), "/Query", "/TN", task_path, "/XML"],
                                capture_output=True, timeout=60, creationflags=_NO_WINDOW)
        if result.returncode != 0 or not result.stdout:
            raise RuntimeError("schtasks /Query failed")
        Path(dest).write_bytes(result.stdout)

    def delete_task(self, task_path: str) -> None:
        if not TASK_PATH_RE.match(task_path):
            raise ValueError("invalid task path")
        _check(_run([system32("schtasks.exe"), "/Delete", "/TN", task_path, "/F"]), "schtasks /Delete")

    def create_task(self, task_path: str, xml_file: Path) -> None:
        if not TASK_PATH_RE.match(task_path):
            raise ValueError("invalid task path")
        _check(_run([system32("schtasks.exe"), "/Create", "/TN", task_path, "/XML", str(xml_file), "/F"]),
               "schtasks /Create")

    def create_restore_point(self, description: str) -> tuple[bool, str]:
        safe = re.sub(r"[^A-Za-z0-9 ._\-]", "", description)[:60] or "danidUn"
        ps = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell",
                          "v1.0", "powershell.exe")
        script = (f"Checkpoint-Computer -Description 'danidUn: {safe}' "
                  "-RestorePointType APPLICATION_UNINSTALL -ErrorAction Stop -WarningVariable w; "
                  "if ($w) { Write-Output ('WARN:' + $w[0]) }")
        try:
            result = _run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                          timeout=600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        text = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            return False, text or "Checkpoint-Computer failed"
        if "WARN:" in text:  # Windows throttles restore points to one per 24h by default
            return False, text.split("WARN:", 1)[1].strip()
        return True, ""
