"""Registry access behind a small interface so the engine can be tested off Windows."""
from __future__ import annotations

import datetime as dt
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

HKLM = "HKLM"
HKCU = "HKCU"
VIEW_64 = 64
VIEW_32 = 32

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11


@dataclass
class RegValue:
    name: str
    data: object
    type: int


Values = dict  # lower-cased value name -> RegValue ("" is the default value)


def join(*parts: str) -> str:
    return "\\".join(p.strip("\\") for p in parts if p)


def get_str(values: Values, name: str) -> str:
    v = values.get(name.casefold())
    if v is None or v.data is None:
        return ""
    if isinstance(v.data, (list, tuple)):
        return "\n".join(str(x) for x in v.data)
    if isinstance(v.data, bytes):
        return ""
    return str(v.data).strip("\x00").strip()


def get_int(values: Values, name: str) -> int | None:
    v = values.get(name.casefold())
    if v is None:
        return None
    try:
        return int(v.data)
    except (TypeError, ValueError):
        return None


def display_path(hive: str, path: str, view: int) -> str:
    text = join(hive, path)
    return text + (" [32-bit]" if hive == HKLM and view == VIEW_32 else "")


class RegistryBackend(Protocol):
    def subkeys(self, hive: str, path: str, view: int = VIEW_64) -> list[str]: ...
    def values(self, hive: str, path: str, view: int = VIEW_64) -> Values: ...
    def key_exists(self, hive: str, path: str, view: int = VIEW_64) -> bool: ...
    def last_write(self, hive: str, path: str, view: int = VIEW_64) -> dt.datetime | None: ...
    def export_key(self, hive: str, path: str, view: int, dest: Path) -> None: ...
    def import_file(self, src: Path, view: int) -> None: ...
    def delete_tree(self, hive: str, path: str, view: int) -> None: ...
    def delete_value(self, hive: str, path: str, view: int, name: str) -> None: ...
    def set_value(self, hive: str, path: str, view: int, name: str, type_: int, data: object) -> None: ...


def system32(name: str) -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", name)


class WinRegistry:
    """winreg-based implementation (Windows only)."""

    def __init__(self) -> None:
        import winreg  # noqa: PLC0415 - Windows-only import
        self.w = winreg
        self._hives = {HKLM: winreg.HKEY_LOCAL_MACHINE, HKCU: winreg.HKEY_CURRENT_USER}

    def _flag(self, view: int) -> int:
        return self.w.KEY_WOW64_32KEY if view == VIEW_32 else self.w.KEY_WOW64_64KEY

    def _open(self, hive: str, path: str, view: int, access: int | None = None):
        access = self.w.KEY_READ if access is None else access
        return self.w.OpenKey(self._hives[hive], path, 0, access | self._flag(view))

    def subkeys(self, hive, path, view=VIEW_64):
        try:
            with self._open(hive, path, view) as k:
                out = []
                i = 0
                while True:
                    try:
                        out.append(self.w.EnumKey(k, i))
                    except OSError:
                        return out
                    i += 1
        except OSError:
            return []

    def values(self, hive, path, view=VIEW_64):
        try:
            with self._open(hive, path, view) as k:
                out = {}
                i = 0
                while True:
                    try:
                        name, data, type_ = self.w.EnumValue(k, i)
                    except OSError:
                        return out
                    out[name.casefold()] = RegValue(name, data, type_)
                    i += 1
        except OSError:
            return {}

    def key_exists(self, hive, path, view=VIEW_64):
        try:
            with self._open(hive, path, view):
                return True
        except OSError:
            return False

    def last_write(self, hive, path, view=VIEW_64):
        try:
            with self._open(hive, path, view) as k:
                ticks = self.w.QueryInfoKey(k)[2]
            return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ticks // 10)
        except (OSError, OverflowError):
            return None

    def _reg_exe(self, *args: str) -> None:
        result = subprocess.run([system32("reg.exe"), *args], capture_output=True, text=True,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=120)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "reg.exe failed").strip())

    def export_key(self, hive, path, view, dest):
        self._reg_exe("export", join(hive, path), str(dest), "/y", "/reg:32" if view == VIEW_32 else "/reg:64")
        if not Path(dest).is_file():
            raise RuntimeError("registry export produced no file")

    def import_file(self, src, view):
        self._reg_exe("import", str(src), "/reg:32" if view == VIEW_32 else "/reg:64")

    def delete_tree(self, hive, path, view):
        for child in self.subkeys(hive, path, view):
            self.delete_tree(hive, join(path, child), view)
        self.w.DeleteKeyEx(self._hives[hive], path, self._flag(view), 0)

    def delete_value(self, hive, path, view, name):
        with self._open(hive, path, view, self.w.KEY_SET_VALUE) as k:
            self.w.DeleteValue(k, name)

    def set_value(self, hive, path, view, name, type_, data):
        with self.w.CreateKeyEx(self._hives[hive], path, 0, self.w.KEY_SET_VALUE | self._flag(view)) as k:
            self.w.SetValueEx(k, name, 0, type_, data)
