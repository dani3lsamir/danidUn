"""Filesystem leftovers: install folders, per-user/machine data folders, MSI caches, Store data."""
from __future__ import annotations

import os

from ..models import Category, Kind, Leftover
from ..paths import is_reparse_point, is_within
from .context import AppIdentity, ScanContext, ScanMode, collect_exes


def _dirs(path: str) -> list[os.DirEntry]:
    try:
        with os.scandir(path) as it:
            return [e for e in it if e.is_dir(follow_symlinks=False) and not is_reparse_point(e.path)]
    except OSError:
        return []


def _entries(path: str) -> list[os.DirEntry]:
    try:
        with os.scandir(path) as it:
            return list(it)
    except OSError:
        return []


def _folder(path: str) -> Leftover:
    return Leftover(Kind.FOLDER, path, Category.FILES)


def _name_evidence(lo: Leftover, identity: AppIdentity, raw: str) -> bool:
    kind, matched = identity.match_name(raw)
    if kind == "exact":
        lo.add("exact_name" if len(matched) >= 6 else "exact_short_name", raw)
        if matched == identity.primary:
            lo.add("primary_name")
        return True
    if kind == "partial":
        lo.add("partial_name", f"{raw} ~ {matched}")
        return True
    return False


def scan_files(identity: AppIdentity, ctx: ScanContext, mode: ScanMode) -> list[Leftover]:
    f = ctx.folders
    out: list[Leftover] = []

    for d in identity.install_dirs:
        if os.path.isdir(d):
            lo = _folder(d).add("install_dir", d)
            base = os.path.basename(d.rstrip("\\/"))
            if not identity.match_name(base)[0] and not identity.is_publisher(base):
                # e.g. a program registered "C:\Games" as its folder: make the user review it.
                lo.add("unrelated_folder_name", base)
            out.append(lo)

    roots: list[tuple[str, str]] = [
        (f.program_files, "pf"), (f.program_files_x86, "pf"), (f.program_data, "data"),
        (f.appdata, "data"), (f.local_appdata, "data"), (f.local_low, "data"),
        (os.path.join(f.local_appdata, "Programs") if f.local_appdata else "", "pf"),
        (f.common_files, "common"), (f.common_files_x86, "common"),
    ]
    if mode >= ScanMode.ADVANCED:
        roots.append((f.documents, "docs"))
    seen_roots = set()
    for root, kind in roots:
        if not root or root.casefold() in seen_roots or not os.path.isdir(root):
            continue
        seen_roots.add(root.casefold())
        for child in _dirs(root):
            lo = _folder(child.path)
            if _name_evidence(lo, identity, child.name):
                _modifiers(lo, identity, kind)
                out.append(lo)
            elif identity.is_publisher(child.name):
                out.extend(_publisher_folder(child.path, identity, kind))

    # Windows Installer / Burn bundle caches named after the ProductCode.
    if identity.product_code and f.program_data:
        cache = os.path.join(f.program_data, "Package Cache")
        for child in _dirs(cache):
            if child.name.upper().startswith(identity.product_code):
                out.append(_folder(child.path).add("product_code", identity.product_code))

    if identity.package_family and f.local_appdata:
        pkg = os.path.join(f.local_appdata, "Packages", identity.package_family)
        if os.path.isdir(pkg):
            out.append(_folder(pkg).add("package_family", identity.package_family))
    return out


def _modifiers(lo: Leftover, identity: AppIdentity, root_kind: str) -> None:
    if root_kind == "common":
        lo.add("common_files")
    elif root_kind == "docs":
        lo.add("user_data")
    if identity.exe_names and not any(is_within(lo.target, d) for d in identity.install_dirs):
        if collect_exes(lo.target, 300) & identity.exe_names:
            lo.add("contains_app_exe")


def _publisher_folder(path: str, identity: AppIdentity, root_kind: str) -> list[Leftover]:
    out: list[Leftover] = []
    entries = _entries(path)
    matched = 0
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False) or is_reparse_point(entry.path):
            continue
        lo = _folder(entry.path)
        if _name_evidence(lo, identity, entry.name):
            lo.add("publisher_parent", os.path.basename(path))
            _modifiers(lo, identity, root_kind)
            out.append(lo)
            if any(e.signal in ("exact_name", "exact_short_name") for e in lo.evidence):
                matched += 1
    if matched == len(entries):  # empty, or only this application's folders inside
        lo = _folder(path).add("publisher_folder", os.path.basename(path)).add("only_app_content")
        if identity.publisher_shared:
            lo.add("shared_publisher")
        if root_kind == "common":
            lo.add("common_files")
        out.append(lo)
    return out
