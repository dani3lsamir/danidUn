"""Enumerates installed applications from the documented Uninstall registry keys."""
from __future__ import annotations

import logging
import ntpath
import os
import re
from typing import Callable

from .cmdline import parse_command
from .models import Program, Source, Status
from .paths import is_within, norm, path_from_icon
from .registry import HKCU, HKLM, VIEW_32, VIEW_64, RegistryBackend, get_int, get_str, join
from .textutil import GUID_RE, find_guid, normalize, pack_guid

log = logging.getLogger(__name__)

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
SOURCES = ((HKLM, VIEW_64, "machine"), (HKLM, VIEW_32, "machine"), (HKCU, VIEW_64, "user"))
HIDDEN_RELEASE_TYPES = {"update", "hotfix", "security update", "service pack"}

SECURITY_VENDORS = (
    "avast", "avg technologies", "avira", "bitdefender", "eset", "kaspersky", "mcafee", "norton",
    "nortonlifelock", "gen digital", "symantec", "sophos", "trend micro", "malwarebytes", "panda security",
    "f-secure", "withsecure", "webroot", "comodo", "crowdstrike", "sentinelone", "g data", "emsisoft",
    "zonealarm", "check point", "bullguard", "totalav", "surfshark antivirus", "quick heal",
)
SHARED_RUNTIMES = re.compile(
    r"visual c\+\+.*redistributable|\.net (framework|runtime|desktop runtime|core)|asp\.net core|"
    r"directx|webview2|java\(tm\)|java \d+|jre|jdk|vcredist|universal crt|windows sdk|"
    r"microsoft visual studio tools|python \d+\.\d+.*(core|standard library|executables)|"
    r"vulkan run ?time|openal|physx|xna framework|gamebar|edge update|windows app runtime",
    re.I,
)


def _iso_date(raw: str) -> str:
    raw = raw.strip()
    if re.fullmatch(r"\d{8}", raw):
        return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"
    m = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", raw)
    if m:
        return f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d}"
    return ""


def _infer_location(display_icon: str, exe: str, windows_dir: str) -> str:
    for candidate in (path_from_icon(display_icon), exe):
        if not candidate or not os.path.isabs(candidate):
            continue
        folder = os.path.dirname(candidate)
        low = norm(folder).casefold()
        if not folder or (windows_dir and is_within(folder, windows_dir)):
            continue
        if any(x in low for x in ("package cache", "\\installer", "\\temp", "installshield installation information")):
            continue
        if os.path.dirname(norm(folder)) == norm(folder):  # drive root
            continue
        return folder
    return ""


def classify_flags(p: Program) -> list[str]:
    flags = []
    text = f"{p.name} {p.publisher}".casefold()
    if any(v in text for v in SECURITY_VENDORS) or re.search(r"anti-?virus|antimalware|internet security|endpoint protection", text):
        flags.append("security_software")
    if SHARED_RUNTIMES.search(p.name):
        flags.append("shared_runtime")
    if normalize(p.publisher).startswith("microsoft"):
        flags.append("microsoft")
    return flags


def msi_registered(reg: RegistryBackend, product_code: str) -> bool:
    try:
        packed = pack_guid(product_code)
    except ValueError:
        return True
    checks = (
        (HKLM, r"SOFTWARE\Classes\Installer\Products"),
        (HKCU, r"SOFTWARE\Microsoft\Installer\Products"),
        (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"),
    )
    return any(reg.key_exists(h, join(p, packed), VIEW_64) for h, p in checks)


def read_programs(reg: RegistryBackend, *, exists: Callable[[str], bool] = os.path.exists,
                  windows_dir: str = "", is_64bit_os: bool = True, include_hidden: bool = False) -> list[Program]:
    windows_dir = windows_dir or os.environ.get("SystemRoot", r"C:\Windows")
    found: dict[tuple, Program] = {}
    for hive, view, scope in SOURCES:
        if view == VIEW_32 and not is_64bit_os:
            continue
        for sub in reg.subkeys(hive, UNINSTALL_KEY, view):
            key_path = join(UNINSTALL_KEY, sub)
            try:
                vals = reg.values(hive, key_path, view)
            except OSError:
                continue
            name = get_str(vals, "DisplayName")
            if not name:
                continue
            if not include_hidden and (
                get_int(vals, "SystemComponent") == 1
                or get_str(vals, "ParentKeyName")
                or get_str(vals, "ReleaseType").casefold() in HIDDEN_RELEASE_TYPES
            ):
                continue
            p = _program_from_values(reg, hive, view, scope, sub, key_path, vals, exists, windows_dir)
            identity = (normalize(p.name), p.version.casefold(), p.uninstall_string.casefold(), p.hive)
            found.setdefault(identity, p)
    return sorted(found.values(), key=lambda p: p.name.casefold())


def _program_from_values(reg, hive, view, scope, sub, key_path, vals, exists, windows_dir) -> Program:
    uninstall = get_str(vals, "UninstallString")
    windows_installer = get_int(vals, "WindowsInstaller") == 1
    product_code = ""
    if GUID_RE.fullmatch(sub) and (windows_installer or "msiexec" in uninstall.casefold()):
        product_code = sub.upper()
    elif "msiexec" in uninstall.casefold():
        product_code = find_guid(uninstall)
    p = Program(
        name=get_str(vals, "DisplayName"),
        version=get_str(vals, "DisplayVersion"),
        publisher=get_str(vals, "Publisher"),
        install_location=get_str(vals, "InstallLocation").strip('"'),
        uninstall_string=uninstall,
        quiet_uninstall_string=get_str(vals, "QuietUninstallString"),
        modify_path=get_str(vals, "ModifyPath"),
        display_icon=get_str(vals, "DisplayIcon"),
        install_date=_iso_date(get_str(vals, "InstallDate")),
        size_kb=get_int(vals, "EstimatedSize") or 0,
        source=Source.MSI if product_code else Source.WIN32,
        scope=scope, hive=hive, view=view, key_path=key_path, key_name=sub,
        product_code=product_code,
        no_remove=get_int(vals, "NoRemove") == 1,
    )
    if not p.install_date:
        stamp = reg.last_write(hive, key_path, view)
        if stamp:
            p.install_date = stamp.date().isoformat()

    parsed = parse_command(uninstall, exists=exists) if uninstall else None
    if not p.install_location:
        p.install_location = _infer_location(p.display_icon, parsed.executable if parsed else "", windows_dir)
        p.location_inferred = bool(p.install_location)

    if p.product_code:
        if not msi_registered(reg, p.product_code):
            p.status.append(Status.MSI_UNREGISTERED)
    elif not uninstall:
        p.status.append(Status.NO_UNINSTALLER)
    elif parsed and not parsed.resolved and ntpath.isabs(parsed.executable):
        p.status.append(Status.UNINSTALLER_MISSING)
    if p.install_location and not p.location_inferred and not exists(p.install_location):
        p.status.append(Status.LOCATION_MISSING)
    p.flags = classify_flags(p)
    return p


def find_program_entry(reg: RegistryBackend, program: Program) -> bool:
    """True when the program's uninstall key still exists (used after an uninstall)."""
    if program.source == Source.STORE or not program.key_path:
        return False
    return reg.key_exists(program.hive, program.key_path, program.view)


def list_all(reg: RegistryBackend, include_store: bool = True, store_loader=None) -> list[Program]:
    import platform  # noqa: PLC0415
    is64 = platform.machine().endswith("64") or "PROGRAMFILES(X86)" in {k.upper() for k in os.environ}
    programs = read_programs(reg, is_64bit_os=is64)
    if include_store and store_loader is not None:
        try:
            programs.extend(store_loader())
        except Exception:  # noqa: BLE001 - Store listing is best effort
            log.exception("Store app enumeration failed")
    return sorted(programs, key=lambda p: p.name.casefold())
