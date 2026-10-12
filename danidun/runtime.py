"""Wires the real Windows backends together for the GUI."""
from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import appx, inventory
from .models import Program
from .paths import KnownFolders, is_within, norm
from .quarantine import Quarantine, default_base
from .registry import WinRegistry
from .safety import SafetyPolicy
from .scanner import ScanContext
from .sysops import WinSystemOps


def own_dirs() -> list[str]:
    dirs = [str(default_base())]
    if getattr(sys, "frozen", False):
        dirs.append(os.path.dirname(sys.executable))
    else:
        dirs.append(str(Path(__file__).resolve().parent.parent))
    return dirs


@dataclass
class Runtime:
    registry: WinRegistry = field(default_factory=WinRegistry)
    sysops: WinSystemOps = field(default_factory=WinSystemOps)
    folders: KnownFolders = field(default_factory=KnownFolders.from_system)

    def __post_init__(self) -> None:
        self.quarantine = Quarantine(self.registry, self.sysops)

    def load_programs(self) -> list[Program]:
        is64 = platform.machine().endswith("64") or bool(os.environ.get("ProgramFiles(x86)"))
        return inventory.read_programs(self.registry, windows_dir=self.folders.windows, is_64bit_os=is64)

    @staticmethod
    def load_store_apps() -> list[Program]:
        return appx.list_store_apps()

    def others(self, target: Program | None, programs: list[Program]) -> list[Program]:
        """All programs except the target (and entries that point at the very same uninstall key)."""
        if target is None:
            return list(programs)
        out = []
        for p in programs:
            if p.uid == target.uid:
                continue
            if target.key_path and p.key_path == target.key_path and p.hive == target.hive:
                continue
            out.append(p)
        return out

    def policy(self, target: Program | None, programs: list[Program]) -> SafetyPolicy:
        others = self.others(target, programs)
        # Another registered entry sharing the target's exact folder is usually a component of the same
        # product (e.g. a second MSI). It still protects that folder, which is the conservative choice.
        return SafetyPolicy(self.folders, others, own_dirs(),
                            allowed_packages_family=target.package_family_name if target else "")

    def context(self, target: Program, programs: list[Program]) -> ScanContext:
        policy = self.policy(target, programs)
        return ScanContext(self.registry, self.folders, policy, policy.other_programs)

    def still_installed(self, program: Program, programs: list[Program]) -> bool:
        if program.source.value == "store":
            return appx.package_installed(program.package_full_name)
        if inventory.find_program_entry(self.registry, program):
            return True
        return False

    @staticmethod
    def folder_exists(program: Program) -> bool | None:
        loc = program.install_location
        if not loc:
            return None
        return os.path.isdir(loc)


def same_location(a: str, b: str) -> bool:
    return bool(a and b) and norm(a) == norm(b)


__all__ = ["Runtime", "same_location", "is_within"]
