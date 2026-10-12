"""Path comparison helpers and the set of well-known Windows folders."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field, fields

from .cmdline import expand_env


def norm(path: str) -> str:
    """Comparable form of a filesystem path (case-insensitive on Windows)."""
    if not path:
        return ""
    p = expand_env(path.strip().strip('"'))
    if os.sep == "\\":
        p = p.replace("/", "\\")
        if p.startswith("\\\\?\\"):
            p = p[4:]
    p = os.path.normpath(p)
    return os.path.normcase(p).rstrip("\\/") or os.path.normcase(p)


def is_within(child: str, parent: str) -> bool:
    """True when ``child`` equals ``parent`` or lies beneath it."""
    c, p = norm(child), norm(parent)
    if not c or not p:
        return False
    return c == p or c.startswith(p.rstrip(os.sep) + os.sep)


def references_dir(text: str, directory: str) -> bool:
    """True when free text (a command line, a value) points inside ``directory``."""
    if not text or not directory:
        return False
    hay = expand_env(text).casefold()
    if os.sep == "\\":
        hay = hay.replace("/", "\\")
    needle = norm(directory).casefold()
    if not needle or len(needle) < 4:
        return False
    idx = hay.find(needle)
    while idx != -1:
        end = idx + len(needle)
        before_ok = idx == 0 or not hay[idx - 1].isalnum()
        after_ok = end == len(hay) or hay[end] in (os.sep, '"', "'", ",", ";", " ", "\x00")
        if before_ok and after_ok:
            return True
        idx = hay.find(needle, idx + 1)
    return False


def is_reparse_point(path: str) -> bool:
    """Junctions and symlinks are never followed nor deleted. Unknown state => True."""
    try:
        st = os.lstat(path)
    except OSError:
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return True
    return stat.S_ISLNK(st.st_mode)


def path_from_icon(display_icon: str) -> str:
    """'"C:\\x\\app.exe",0' -> 'C:\\x\\app.exe'."""
    text = (display_icon or "").strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 0 else text[1:]
    if "," in text:
        head, _, tail = text.rpartition(",")
        if tail.strip().lstrip("-").isdigit():
            return head.strip()
    return text


def folder_size(path: str, limit: int = 50000) -> int:
    """Total size of a folder without following reparse points (bounded)."""
    total = 0
    seen = 0
    stack = [path]
    while stack and seen < limit:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    seen += 1
                    try:
                        if entry.is_symlink() or is_reparse_point(entry.path):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def human_size(num: int) -> str:
    if not num:
        return ""
    size = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(num)


@dataclass
class KnownFolders:
    windows: str = ""
    program_files: str = ""
    program_files_x86: str = ""
    common_files: str = ""
    common_files_x86: str = ""
    program_data: str = ""
    appdata: str = ""
    local_appdata: str = ""
    local_low: str = ""
    user_profile: str = ""
    users_root: str = ""
    public: str = ""
    temp: str = ""
    documents: str = ""
    desktop_user: str = ""
    desktop_public: str = ""
    start_menu_user: str = ""
    start_menu_common: str = ""
    startup_user: str = ""
    startup_common: str = ""
    quick_launch: str = ""
    tasks_dir: str = ""
    extra_protected: list[str] = field(default_factory=list)

    def all_paths(self) -> list[str]:
        out = []
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, str) and value:
                out.append(value)
            elif isinstance(value, list):
                out.extend(v for v in value if v)
        return out

    @classmethod
    def from_system(cls) -> "KnownFolders":
        env = os.environ
        windows = env.get("SystemRoot") or env.get("windir") or r"C:\Windows"
        profile = env.get("USERPROFILE", "")
        appdata = env.get("APPDATA", "")
        program_data = env.get("ProgramData", "")
        start_user = os.path.join(appdata, r"Microsoft\Windows\Start Menu") if appdata else ""
        start_common = os.path.join(program_data, r"Microsoft\Windows\Start Menu") if program_data else ""
        from . import winapi  # noqa: PLC0415 - avoid import cycle at module load
        return cls(
            windows=windows,
            program_files=env.get("ProgramW6432") or env.get("ProgramFiles", ""),
            program_files_x86=env.get("ProgramFiles(x86)", ""),
            common_files=env.get("CommonProgramW6432") or env.get("CommonProgramFiles", ""),
            common_files_x86=env.get("CommonProgramFiles(x86)", ""),
            program_data=program_data,
            appdata=appdata,
            local_appdata=env.get("LOCALAPPDATA", ""),
            local_low=os.path.join(profile, "AppData", "LocalLow") if profile else "",
            user_profile=profile,
            users_root=os.path.dirname(profile) if profile else "",
            public=env.get("PUBLIC", ""),
            temp=env.get("TEMP", ""),
            documents=winapi.known_folder("documents") or (os.path.join(profile, "Documents") if profile else ""),
            desktop_user=winapi.known_folder("desktop") or (os.path.join(profile, "Desktop") if profile else ""),
            desktop_public=os.path.join(env.get("PUBLIC", ""), "Desktop") if env.get("PUBLIC") else "",
            start_menu_user=start_user,
            start_menu_common=start_common,
            startup_user=os.path.join(start_user, "Programs", "Startup") if start_user else "",
            startup_common=os.path.join(start_common, "Programs", "Startup") if start_common else "",
            quick_launch=os.path.join(appdata, r"Microsoft\Internet Explorer\Quick Launch") if appdata else "",
            tasks_dir=os.path.join(windows, "System32", "Tasks"),
        )
