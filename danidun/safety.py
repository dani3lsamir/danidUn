"""Protection rules. Every removal is re-validated here immediately before it happens.

Philosophy: an allow-list for registry locations, a deny-list plus "belongs to another
installed program" checks for the filesystem, and hard blocks for drivers, Windows
components and anything reached through a junction or symlink.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .cmdline import expand_env
from .models import Program, Source
from .paths import KnownFolders, is_reparse_point, is_within, norm, references_dir

# Folder names directly under Program Files / ProgramData / AppData that are shared or part of Windows.
PROTECTED_CHILD_NAMES = {n.casefold() for n in (
    "Common Files", "Microsoft", "Microsoft Shared", "Microsoft.NET", "Windows Defender",
    "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player",
    "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices",
    "Windows Security", "Windows Sidebar", "WindowsApps", "WindowsPowerShell", "ModifiableWindowsApps",
    "Internet Explorer", "Reference Assemblies", "MSBuild", "dotnet", "Windows Kits", "Package Cache",
    "Uninstall Information", "Microsoft Update Health Tools", "Packages", "Temp", "Programs",
    "Application Data", "Desktop", "Documents", "Start Menu", "Templates", "regid.1991-06.com.microsoft",
    "ssh", "USOShared", "USOPrivate", "SoftwareDistribution", "Comms", "ConnectedDevicesPlatform",
    "D3DSCache", "PlaceholderTileLogoFolder", "Publishers", "VirtualStore", "CrashDumps", "NVIDIA",
    "NVIDIA Corporation", "Intel", "AMD", "Realtek", "Package Management", "Google", "Mozilla",
    "Adobe", "Apple", "Oracle", "Java", "Python", "Steam", "Epic Games",
    # shared children of Common Files
    "System", "Services", "SpeechEngines", "DESIGNER", "VSTO", "InstallShield", "Macrovision Shared",
    "Wise Installation Wizard", "Apple Application Support", "Adobe AIR", "Oracle", "Intel Corporation",
    "Native Instruments", "Avid", "VST2", "VST3", "Steinberg", "LogiShrd", "Logishrd",
)}

# Registry top-level SOFTWARE children that are never removed as a whole.
PROTECTED_SOFTWARE_CHILDREN = {n.casefold() for n in (
    "Microsoft", "Classes", "Policies", "Clients", "WOW6432Node", "ODBC", "RegisteredApplications",
    "DefaultUserEnvironment", "Khronos", "Intel", "NVIDIA Corporation", "AMD", "ATI Technologies",
    "Realtek", "Dolby", "Wow6432Node", "Partner", "OEM", "Google", "Mozilla", "Apple Inc.", "Adobe",
    "JavaSoft", "Python", "Oracle", "Valve", "Wine", "WinRAR", "7-Zip",
)}
# Publisher-level keys above: their *children* can still be removed when they match the app.
VENDOR_PARENT_OK = {n.casefold() for n in (
    "Google", "Mozilla", "Apple Inc.", "Adobe", "Oracle", "Valve", "Python", "JavaSoft",
)}

PROTECTED_CLASSES = {n.casefold() for n in (
    "*", "AllFilesystemObjects", "AppID", "Applications", "CLSID", "Directory", "Drive", "exefile",
    "Folder", "Installer", "Interface", "lnkfile", "Local Settings", "MIME", "Network", "Printers",
    "PROTOCOLS", "SystemFileAssociations", "TypeLib", "Unknown", "batfile", "cmdfile", "comfile",
    "dllfile", "htmlfile", "http", "https", "inifile", "jsfile", "mailto", "regedit", "scrfile",
    "txtfile", "VBSFile", "WSFFile", "Wow6432Node", "DesktopBackground", "Extensions",
    "ActivatableClasses", "PackagedCom",
)}

CRITICAL_SERVICES = {n.casefold() for n in (
    "WinDefend", "WdNisSvc", "Sense", "mpssvc", "BFE", "EventLog", "RpcSs", "DcomLaunch", "LSM",
    "Winmgmt", "wuauserv", "TrustedInstaller", "msiserver", "Schedule", "CryptSvc", "Dhcp", "Dnscache",
    "nsi", "Power", "ProfSvc", "SamSs", "Themes", "AudioSrv", "Audiosrv", "PlugPlay",
)}

REG_UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
_ALLOWED_REGISTRY_PATTERNS = [re.compile(p, re.I) for p in (
    r"^SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$",
    r"^SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\App Paths\\[^\\]+\.exe$",
    r"^SOFTWARE\\(?:WOW6432Node\\)?Classes\\Applications\\[^\\]+\.exe$",
    r"^SOFTWARE\\Classes\\Installer\\(?:Products|Features)\\[0-9A-F]{32}$",
    r"^SOFTWARE\\Classes\\Installer\\UpgradeCodes\\[0-9A-F]{32}$",
    r"^SOFTWARE\\Microsoft\\Installer\\(?:Products|Features)\\[0-9A-F]{32}$",
    r"^SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-[0-9-]+\\Products\\[0-9A-F]{32}$",
    r"^SYSTEM\\CurrentControlSet\\Services\\[^\\]+$",
)]
_ALLOWED_VALUE_PARENTS = [re.compile(p, re.I) for p in (
    r"^SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?$",
    r"^SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\(?:Run|Run32|StartupFolder)$",
    r"^SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache$",
    r"^SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store$",
    r"^SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers$",
)]
_NEVER_VALUE_PARENTS = [re.compile(p, re.I) for p in (
    r"SharedDLLs$", r"\\Session Manager", r"\\Winlogon", r"\\Image File Execution Options",
)]


@dataclass
class SafetyPolicy:
    folders: KnownFolders
    other_programs: list[Program] = field(default_factory=list)
    own_dirs: list[str] = field(default_factory=list)
    allowed_packages_family: str = ""  # Store family of the target (its Packages folder is allowed)

    def __post_init__(self) -> None:
        f = self.folders
        self._roots = [p for p in f.all_paths() if p]
        self._roots += [d for d in self.own_dirs if d]
        self._system_dirs = [p for p in (f.windows,) if p]
        roots_with_children = [f.program_files, f.program_files_x86, f.program_data, f.appdata,
                               f.local_appdata, f.local_low, f.common_files, f.common_files_x86,
                               f.documents, os.path.join(f.local_appdata, "Programs") if f.local_appdata else ""]
        self._shared_parents = [r for r in roots_with_children if r]
        ms_dirs = []
        for base in (f.program_data, f.appdata, f.local_appdata):
            if base:
                ms_dirs.append(os.path.join(base, "Microsoft"))
        if f.local_appdata:
            ms_dirs.append(os.path.join(f.local_appdata, "Packages"))
        if f.program_files:
            ms_dirs.append(os.path.join(f.program_files, "WindowsApps"))
        self._deny_trees = ms_dirs
        self._start_menus = [p for p in (f.start_menu_user, f.start_menu_common, f.quick_launch) if p]
        self._other_dirs: list[tuple[str, str]] = []
        for p in self.other_programs:
            loc = p.install_location
            if loc and os.path.isabs(loc) and not self._is_root_like(loc):
                self._other_dirs.append((loc, p.name))

    # ------------------------------------------------------------ filesystem
    def _is_root_like(self, path: str) -> bool:
        n = norm(path)
        if not n or os.path.dirname(n) == n:
            return True
        return any(norm(r) == n for r in self._roots)

    def path_protection(self, path: str, check_disk: bool = True) -> str:
        """Return a reason string when ``path`` must not be removed, else ''."""
        if not path or not os.path.isabs(path):
            return "protect.not_absolute"
        n = norm(path)
        if os.path.dirname(n) == n:
            return "protect.drive_root"
        for root in self._roots:
            if is_within(root, path):  # path is a known folder or one of its parents
                return "protect.system_folder"
        for d in self._system_dirs:
            if is_within(path, d):
                return "protect.windows"
        in_start_menu = any(is_within(path, s) for s in self._start_menus)
        for d in self._deny_trees:
            if is_within(path, d) and not in_start_menu:
                if self.allowed_packages_family and self.folders.local_appdata and is_within(
                        path, os.path.join(self.folders.local_appdata, "Packages", self.allowed_packages_family)):
                    continue
                return "protect.shared_location"
        for parent in self._shared_parents:
            if norm(os.path.dirname(n)) == norm(parent) and os.path.basename(n).casefold() in PROTECTED_CHILD_NAMES:
                return "protect.shared_location"
        for loc, name in self._other_dirs:
            if is_within(path, loc) or is_within(loc, path):
                return "protect.other_app:" + name
        for own in self.own_dirs:
            if own and (is_within(path, own) or is_within(own, path)):
                return "protect.danidun"
        if check_disk and os.path.lexists(path) and is_reparse_point(path):
            return "protect.reparse_point"
        return ""

    def text_belongs_to_other(self, text: str) -> str:
        for loc, name in self._other_dirs:
            if references_dir(text, loc):
                return "protect.other_app:" + name
        return ""

    # ------------------------------------------------------------ registry
    @staticmethod
    def _strip_wow(path: str) -> str:
        return re.sub(r"^SOFTWARE\\WOW6432Node\\", r"SOFTWARE\\", path, flags=re.I)

    def registry_key_protection(self, hive: str, path: str) -> str:
        if hive not in ("HKLM", "HKCU"):
            return "protect.registry"
        p = path.strip("\\")
        if any(r.match(p) for r in _ALLOWED_REGISTRY_PATTERNS):
            if p.upper().startswith("SYSTEM\\"):
                return "protect.registry_service_key"  # services are removed via the SCM only
            return ""
        parts = self._strip_wow(p).split("\\")
        if len(parts) >= 3 and parts[0].casefold() == "software" and parts[1].casefold() == "classes":
            return "" if self._class_allowed(parts[2], len(parts)) else "protect.registry"
        if len(parts) < 2 or parts[0].casefold() != "software":
            return "protect.registry"
        top = parts[1].casefold()
        if top in PROTECTED_SOFTWARE_CHILDREN:
            if len(parts) >= 3 and top in VENDOR_PARENT_OK:
                return ""
            return "protect.registry"
        return ""

    @staticmethod
    def _class_allowed(name: str, depth: int) -> bool:
        if depth != 3 or name.startswith(".") or name.startswith("{"):
            return False
        return name.casefold() not in PROTECTED_CLASSES

    def registry_value_protection(self, hive: str, parent: str, value_name: str | None) -> str:
        if hive not in ("HKLM", "HKCU"):
            return "protect.registry"
        p = parent.strip("\\")
        if any(r.search(p) for r in _NEVER_VALUE_PARENTS):
            return "protect.registry"
        if any(r.match(p) for r in _ALLOWED_VALUE_PARENTS):
            return ""
        # Values inside an application's own key are fine when the key itself would be.
        if value_name and not self.registry_key_protection(hive, p) and len(p.split("\\")) >= 3:
            return ""
        return "protect.registry"

    # ------------------------------------------------------------ services / tasks
    def service_protection(self, name: str, image_path: str, service_type: int | None) -> str:
        if name.casefold() in CRITICAL_SERVICES:
            return "protect.critical_service"
        if service_type is not None and service_type & 0x0B:  # kernel / fs driver / recognizer
            return "protect.driver"
        image = expand_env(image_path or "")
        low = image.casefold()
        if not image:
            return "protect.windows"
        if low.startswith(("\\systemroot\\", "system32\\", "\\??\\c:\\windows", "%systemroot%")):
            return "protect.windows"
        for windows in {self.folders.windows, os.environ.get("SystemRoot", ""), os.environ.get("windir", "")}:
            if windows and references_dir(image, windows):
                return "protect.windows"
        return self.text_belongs_to_other(image)

    @staticmethod
    def task_protection(task_path: str, command: str) -> str:
        if task_path.casefold().startswith("\\microsoft\\"):
            return "protect.windows"
        if not re.fullmatch(r"\\[^\"<>|*?\x00-\x1f]+", task_path or ""):
            return "protect.invalid_name"
        return ""


def program_warning_flags(program: Program) -> list[str]:
    flags = list(program.flags)
    if program.source == Source.STORE and program.publisher.casefold().startswith("microsoft"):
        flags.append("store_microsoft")
    return flags
