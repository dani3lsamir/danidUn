"""Thin ctypes wrappers around documented Win32 APIs. Every function degrades
gracefully (returns a neutral value) when not running on Windows."""
from __future__ import annotations

import ctypes
import os
import sys
import time
from dataclasses import dataclass

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    from ctypes import wintypes

    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ole32 = ctypes.WinDLL("ole32")
    _version = ctypes.WinDLL("version")


# ---------------------------------------------------------------- privileges

def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin() -> bool:
    """Restart danidUn elevated through the standard UAC prompt."""
    if not IS_WINDOWS:
        return False
    from .cmdline import quote_arg  # noqa: PLC0415
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, ""
    else:
        exe, params = sys.executable, "-m danidun"
    params = " ".join([params] + [quote_arg(a) for a in sys.argv[1:]]).strip()
    _shell32.ShellExecuteW.restype = wintypes.HINSTANCE
    rc = _shell32.ShellExecuteW(None, "runas", exe, params, os.getcwd(), 1)
    return (rc or 0) > 32


def ui_language() -> str:
    """Two-letter UI language of the current user ('es', 'en', ...)."""
    if IS_WINDOWS:
        try:
            langid = _kernel32.GetUserDefaultUILanguage()
            return {0x0A: "es", 0x09: "en"}.get(langid & 0x3FF, "en")
        except OSError:
            pass
    lang = os.environ.get("LANG", "en")
    return "es" if lang.lower().startswith("es") else "en"


# ---------------------------------------------------------------- known folders

_FOLDER_IDS = {
    "desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
}


def known_folder(name: str) -> str:
    if not IS_WINDOWS or name not in _FOLDER_IDS:
        return ""

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    guid = GUID()
    if _ole32.CLSIDFromString(_FOLDER_IDS[name], ctypes.byref(guid)) != 0:
        return ""
    out = ctypes.c_wchar_p()
    _shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD,
                                              wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
    if _shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0:
        return ""
    try:
        return out.value or ""
    finally:
        _ole32.CoTaskMemFree(out)


# ---------------------------------------------------------------- processes

@dataclass(frozen=True)
class ProcInfo:
    pid: int
    parent: int
    name: str


def process_snapshot() -> dict[int, ProcInfo]:
    if not IS_WINDOWS:
        return {}

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = _kernel32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return {}
    out: dict[int, ProcInfo] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = _kernel32.Process32FirstW(wintypes.HANDLE(snap), ctypes.byref(entry))
        while ok:
            out[entry.th32ProcessID] = ProcInfo(entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile)
            ok = _kernel32.Process32NextW(wintypes.HANDLE(snap), ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(wintypes.HANDLE(snap))
    return out


ERROR_ELEVATION_REQUIRED = 740
ERROR_CANCELLED = 1223


class ElevatedProcess:
    """Process started through ShellExecuteEx with the 'runas' verb."""

    def __init__(self, executable: str, parameters: str, cwd: str | None = None) -> None:
        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                        ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                        ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                        ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                        ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                        ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                        ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040 | 0x00000400  # SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
        info.lpVerb = "runas"
        info.lpFile = executable
        info.lpParameters = parameters or None
        info.lpDirectory = cwd
        info.nShow = 1
        if not _shell32.ShellExecuteExW(ctypes.byref(info)):
            err = ctypes.get_last_error()
            raise OSError(err, "ShellExecuteEx failed" if err != ERROR_CANCELLED else "UAC prompt cancelled")
        if not info.hProcess:
            raise OSError(0, "No process handle returned")
        self._handle = info.hProcess
        _kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
        self.pid = _kernel32.GetProcessId(self._handle)

    def poll(self) -> int | None:
        code = wintypes.DWORD()
        _kernel32.GetExitCodeProcess(wintypes.HANDLE(self._handle), ctypes.byref(code))
        if code.value == 259:  # STILL_ACTIVE
            return None
        _kernel32.CloseHandle(wintypes.HANDLE(self._handle))
        self._handle = None
        self.returncode = code.value
        return code.value


def wait_for_tree(root_pid: int, root_poll, baseline: set[int], cancel=None,
                  on_tick=None, interval: float = 0.5, timeout: float | None = None) -> int | None:
    """Wait for a process *and* every child it spawned.

    NSIS/Inno uninstallers copy themselves to %TEMP% and exit immediately, so waiting on
    the first process alone is not enough. We track all processes whose parent is a
    tracked PID and that did not exist before the launch.
    """
    tracked = {root_pid}
    exit_code: int | None = None
    start = time.monotonic()
    while True:
        if exit_code is None:
            exit_code = root_poll()
        snap = process_snapshot()
        for info in snap.values():
            if info.parent in tracked and info.pid not in baseline:
                tracked.add(info.pid)
        alive = [p for p in tracked if p in snap and p != os.getpid()]
        if exit_code is not None and not alive:
            return exit_code
        if not IS_WINDOWS and exit_code is not None:
            return exit_code
        if cancel is not None and cancel.is_set():
            return exit_code
        if timeout is not None and time.monotonic() - start > timeout:
            return exit_code
        if on_tick:
            on_tick(sorted(snap[p].name for p in alive if p in snap))
        time.sleep(interval)


# ---------------------------------------------------------------- version info

def file_version_info(path: str) -> dict[str, str]:
    """ProductName / CompanyName / FileDescription from an executable's resources."""
    if not IS_WINDOWS or not os.path.isfile(path):
        return {}
    try:
        size = _version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return {}
        buf = ctypes.create_string_buffer(size)
        if not _version.GetFileVersionInfoW(path, 0, size, buf):
            return {}
        ptr = ctypes.c_void_p()
        length = wintypes.UINT()
        if not _version.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(length)):
            return {}
        if length.value < 4:
            return {}
        lang, codepage = ctypes.cast(ptr, ctypes.POINTER(wintypes.WORD * 2)).contents
        out = {}
        for key in ("ProductName", "CompanyName", "FileDescription", "ProductVersion"):
            sub = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{key}"
            if _version.VerQueryValueW(buf, sub, ctypes.byref(ptr), ctypes.byref(length)) and length.value:
                out[key] = ctypes.wstring_at(ptr, length.value - 1).strip()
        return out
    except (OSError, ValueError):
        return {}


def open_in_explorer(path: str) -> None:
    if IS_WINDOWS and os.path.exists(path):
        os.startfile(path)  # noqa: S606 - opens a folder/file the user chose
