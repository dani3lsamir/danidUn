"""Read-only checks against the real Windows APIs (run on the Windows CI runner)."""
import ctypes
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


def _real_argv(cmd: str) -> list[str]:
    from ctypes import wintypes
    shell32 = ctypes.WinDLL("shell32")
    kernel32 = ctypes.WinDLL("kernel32")
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    n = ctypes.c_int()
    ptr = shell32.CommandLineToArgvW(cmd, ctypes.byref(n))
    try:
        return [ptr[i] for i in range(n.value)]
    finally:
        kernel32.LocalFree(ctypes.cast(ptr, ctypes.c_void_p))


@pytest.mark.parametrize("cmd", [
    r'"C:\Program Files\App\unins000.exe" /SILENT',
    r'C:\x\u.exe /S "a b" c\\"d e\" f',
    r'a.exe "a\"b" c\d "" x',
    r'MsiExec.exe /X{11111111-2222-3333-4444-555555555555}',
    r'"C:\a b\c.exe" "trailing\\"',
])
def test_split_args_matches_commandlinetoargvw(cmd):
    from danidun.cmdline import split_args
    assert split_args(cmd) == _real_argv(cmd)


def test_real_inventory_and_folders():
    from danidun.inventory import read_programs
    from danidun.paths import KnownFolders
    from danidun.registry import HKLM, WinRegistry
    reg = WinRegistry()
    assert reg.subkeys(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    programs = read_programs(reg)
    assert all(p.name for p in programs)
    f = KnownFolders.from_system()
    assert f.windows and f.program_files and f.appdata and f.desktop_user


def test_real_scan_is_safe():
    """A scan for a made-up program on a real system must find nothing removable."""
    from danidun.models import Program
    from danidun.runtime import Runtime
    from danidun.scanner import AppIdentity, ScanMode, run_scan
    rt = Runtime()
    programs = rt.load_programs()
    target = Program("Zqx Nonexistent Fixture Program", publisher="Zqx Labs Fixture")
    result = run_scan(AppIdentity.build(target, programs), rt.context(target, programs), ScanMode.ADVANCED)
    assert [lo.display for lo in result.leftovers] == []


def test_protection_of_real_folders():
    from danidun.runtime import Runtime
    rt = Runtime()
    policy = rt.policy(None, rt.load_programs())
    f = rt.folders
    for path in (f.windows, f.program_files, f.appdata, f.local_appdata, f.user_profile, "C:\\"):
        assert policy.path_protection(path), path
