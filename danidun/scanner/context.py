"""Shared scan context and the application identity used as evidence source."""
from __future__ import annotations

import ntpath
import os
import re
from dataclasses import dataclass, field
from enum import IntEnum

from ..models import Confidence, Program, Source
from ..paths import KnownFolders, is_reparse_point, path_from_icon
from ..registry import HKCU, HKLM, VIEW_32, VIEW_64, RegistryBackend
from ..safety import SafetyPolicy
from ..textutil import STRONG_NAME_LEN, is_specific, name_variants, normalize, publisher_variants


class ScanMode(IntEnum):
    SAFE = 1      # high confidence only
    MODERATE = 2  # + medium confidence, file associations, MSI registrations
    ADVANCED = 3  # + low confidence, partial matches, deep registry walk


MIN_CONFIDENCE = {ScanMode.SAFE: Confidence.HIGH, ScanMode.MODERATE: Confidence.MEDIUM,
                  ScanMode.ADVANCED: Confidence.LOW}

GENERIC_EXES = {
    "uninstall.exe", "uninst.exe", "uninstaller.exe", "setup.exe", "install.exe", "installer.exe",
    "update.exe", "updater.exe", "autoupdate.exe", "helper.exe", "launcher.exe", "crashreporter.exe",
    "crashpad_handler.exe", "elevate.exe", "elevation_service.exe", "notification_helper.exe",
    "python.exe", "pythonw.exe", "java.exe", "javaw.exe", "node.exe", "cmd.exe", "rundll32.exe",
    "msiexec.exe", "vcredist_x64.exe", "vcredist_x86.exe", "vc_redist.x64.exe", "vc_redist.x86.exe",
    "dxsetup.exe", "unitycrashhandler64.exe", "unitycrashhandler32.exe", "qtwebengineprocess.exe",
    "cefsharp.browsersubprocess.exe", "7z.exe", "7za.exe", "curl.exe", "git.exe", "wget.exe",
    "service.exe", "server.exe", "client.exe", "app.exe", "main.exe", "start.exe", "run.exe",
}
_UNINS_RE = re.compile(r"^(unins\d{3}|uninst\w*|au_|un_a|un_)\.exe$", re.I)


def views_for(hive: str) -> tuple[int, ...]:
    return (VIEW_64, VIEW_32) if hive == HKLM else (VIEW_64,)


HIVES = (HKCU, HKLM)


@dataclass
class AppIdentity:
    display_name: str
    names: list[str]
    primary: str
    publishers: list[str]
    install_dirs: list[str]
    exe_names: set[str]
    product_code: str = ""
    package_family: str = ""
    uninstall_keys: list[tuple[str, int, str]] = field(default_factory=list)
    publisher_shared: bool = False
    flags: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, program: Program, other_programs: list[Program] = (), extra_dirs=(), extra_exes=(),
              max_entries: int = 400) -> "AppIdentity":
        names = name_variants(program.name, program.publisher)
        dirs: list[str] = []
        for d in [program.install_location, *extra_dirs]:
            d = (d or "").strip().strip('"').rstrip("\\/")
            if d and os.path.isabs(d) and d not in dirs:
                dirs.append(d)
        for d in list(dirs):
            base = normalize(os.path.basename(d))
            if is_specific(base) and base not in names and _related(base, names):
                names.append(base)
        exes = {e.casefold() for e in extra_exes if e}
        icon = path_from_icon(program.display_icon)
        if icon.casefold().endswith(".exe"):
            exes.add(ntpath.basename(icon).casefold())
        for d in dirs:
            exes |= collect_exes(d, max_entries)
        exes = {e for e in exes if e not in GENERIC_EXES and not _UNINS_RE.match(e)
                and is_specific(normalize(e[:-4]))}
        pubs = publisher_variants(program.publisher)
        pub_norm = normalize(program.publisher)
        shared = bool(pub_norm) and any(
            normalize(o.publisher) == pub_norm and normalize(o.name) != normalize(program.name)
            for o in other_programs)
        keys = []
        if program.key_path and program.source != Source.STORE:
            keys.append((program.hive, program.view, program.key_path))
        return cls(
            display_name=program.name, names=names, primary=names[0] if names else "",
            publishers=[p for p in pubs if p not in names], install_dirs=dirs, exe_names=exes,
            product_code=program.product_code, package_family=program.package_family_name,
            uninstall_keys=keys, publisher_shared=shared, flags=list(program.flags),
        )

    def match_name(self, raw: str) -> tuple[str, str]:
        """('exact'|'partial'|'', matched-name)."""
        n = normalize(raw)
        if not n:
            return "", ""
        if n in self.names:
            return "exact", n
        for name in self.names:
            if len(name) >= STRONG_NAME_LEN and name in n:
                return "partial", name
        return "", ""

    def is_publisher(self, raw: str) -> bool:
        return normalize(raw) in self.publishers

    def to_dict(self) -> dict:
        return {"display_name": self.display_name, "names": self.names, "publishers": self.publishers,
                "install_dirs": self.install_dirs, "exe_names": sorted(self.exe_names),
                "product_code": self.product_code, "package_family": self.package_family}


def _related(base: str, names: list[str]) -> bool:
    """Accept the install folder name as an extra name only if it resembles the app name."""
    return any(base in n or n in base for n in names) if names else True


def collect_exes(directory: str, max_entries: int = 400, max_depth: int = 2) -> set[str]:
    out: set[str] = set()
    seen = 0
    stack = [(directory, 0)]
    while stack and seen < max_entries:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    seen += 1
                    if seen > max_entries:
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if depth < max_depth and not is_reparse_point(entry.path):
                                stack.append((entry.path, depth + 1))
                        elif entry.name.casefold().endswith(".exe"):
                            out.add(entry.name.casefold())
                    except OSError:
                        continue
        except OSError:
            continue
    return out


@dataclass
class ScanContext:
    registry: RegistryBackend
    folders: KnownFolders
    policy: SafetyPolicy
    other_programs: list[Program] = field(default_factory=list)
    max_registry_keys: int = 60000
