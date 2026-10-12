"""Start menu, desktop, startup-folder and taskbar shortcuts."""
from __future__ import annotations

import ntpath
import os

from ..lnk import read_lnk, read_url
from ..models import Category, Kind, Leftover
from ..paths import is_reparse_point, is_within, references_dir
from .context import AppIdentity, ScanContext, ScanMode

PROTECTED_START_FOLDERS = {n.casefold() for n in (
    "Accessories", "Administrative Tools", "Maintenance", "Startup", "System Tools", "Windows PowerShell",
    "Windows Accessories", "Windows Administrative Tools", "Windows Ease of Access", "Windows System",
    "Windows Tools", "Accessibility",
)}


def _shortcut_evidence(lo: Leftover, identity: AppIdentity, path: str) -> None:
    info = read_lnk(path) if path.casefold().endswith(".lnk") else read_url(path)
    target = info.get("target", "")
    icon = info.get("icon", "")
    in_dir = any(references_dir(target, d) or references_dir(icon, d) for d in identity.install_dirs)
    if in_dir:
        lo.add("references_install_dir", target or icon)
    base = ntpath.basename(target).casefold()
    if base and base in identity.exe_names:
        lo.add("exe_name", base)
    if target and os.path.isabs(target) and not os.path.exists(target):
        lo.add("target_missing", target)
    elif target and os.path.exists(target) and not in_dir:
        lo.add("target_elsewhere", target)
    stem = os.path.splitext(os.path.basename(path))[0]
    kind, matched = identity.match_name(stem)
    if kind == "exact":
        lo.add("exact_name" if len(matched) >= 6 else "exact_short_name", stem)
        if matched == identity.primary:
            lo.add("primary_name")
    elif kind == "partial":
        lo.add("partial_name", f"{stem} ~ {matched}")
    lo.note = target


def scan_shortcuts(identity: AppIdentity, ctx: ScanContext, mode: ScanMode) -> list[Leftover]:
    f = ctx.folders
    startup_dirs = [d for d in (f.startup_user, f.startup_common) if d]
    roots = [
        os.path.join(f.start_menu_user, "Programs") if f.start_menu_user else "",
        os.path.join(f.start_menu_common, "Programs") if f.start_menu_common else "",
        f.desktop_user, f.desktop_public, f.quick_launch, *startup_dirs,
    ]
    out: list[Leftover] = []
    seen: set[str] = set()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for current, dirs, files in _walk(root, max_depth=4):
            category = Category.STARTUP if any(is_within(current, s) for s in startup_dirs) else Category.SHORTCUTS
            for name in files:
                if not name.casefold().endswith((".lnk", ".url")):
                    continue
                full = os.path.join(current, name)
                if full.casefold() in seen:
                    continue
                seen.add(full.casefold())
                lo = Leftover(Kind.FILE, full, category)
                _shortcut_evidence(lo, identity, full)
                if any(e.signal not in ("target_elsewhere", "target_missing") for e in lo.evidence):
                    out.append(lo)
            if root in (f.desktop_user, f.desktop_public):
                dirs[:] = []  # never descend into the user's desktop folders
            else:
                for d in dirs:
                    if d.casefold() in PROTECTED_START_FOLDERS:
                        continue
                    kind, matched = identity.match_name(d)
                    if kind == "exact":
                        lo = Leftover(Kind.FOLDER, os.path.join(current, d), Category.SHORTCUTS)
                        lo.add("exact_name" if len(matched) >= 6 else "exact_short_name", d)
                        if matched == identity.primary:
                            lo.add("primary_name")
                        out.append(lo)
    _mark_app_only_folders(out)
    return out


def _mark_app_only_folders(items: list[Leftover]) -> None:
    """A start-menu folder whose shortcuts all point into the install folder is the app's own."""
    files = [i for i in items if i.kind == Kind.FILE]
    for folder in (i for i in items if i.kind == Kind.FOLDER):
        try:
            entries = [e for e in os.listdir(folder.target)]
        except OSError:
            continue
        inside = [i for i in files if os.path.dirname(i.target).casefold() == folder.target.casefold()]
        strong = [i for i in inside if any(e.signal in ("references_install_dir", "exe_name") for e in i.evidence)]
        if entries and len(strong) == len(entries):
            folder.add("only_app_content")
            folder.add("references_install_dir", "shortcuts")


def _walk(root: str, max_depth: int):
    base_depth = root.rstrip(os.sep).count(os.sep)
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not is_reparse_point(os.path.join(current, d))]
        if current.count(os.sep) - base_depth >= max_depth:
            dirs[:] = []
        yield current, dirs, files
