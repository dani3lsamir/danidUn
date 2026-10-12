"""Registry leftovers: application keys, uninstall entries, App Paths, file associations,
startup values, MSI registrations and (advanced mode) a bounded deep walk."""
from __future__ import annotations

import ntpath
import os

from ..cmdline import parse_command
from ..models import Category, Kind, Leftover
from ..paths import references_dir
from ..registry import HKCU, HKLM, VIEW_64, get_str, join
from ..textutil import pack_guid
from .context import HIVES, AppIdentity, ScanContext, ScanMode, views_for

CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
RUN_KEYS = (join(CV, "Run"), join(CV, "RunOnce"))
STARTUP_APPROVED = join(CV, r"Explorer\StartupApproved\Run")
TRACE_VALUE_KEYS = (
    (HKCU, r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
    (HKCU, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
    (HKCU, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
)
DEEP_SKIP = {"classes", "microsoft", "policies", "wow6432node", "clients", "registeredapplications"}


def _key(hive: str, view: int, path: str, category: Category = Category.REGISTRY) -> Leftover:
    return Leftover(Kind.REG_KEY, path, category, hive=hive, view=view)


def _value(hive: str, view: int, path: str, name: str, category: Category = Category.REGISTRY) -> Leftover:
    return Leftover(Kind.REG_VALUE, path, category, hive=hive, view=view, value_name=name)


def _refs(identity: AppIdentity, text: str) -> str:
    for d in identity.install_dirs:
        if references_dir(text, d):
            return d
    return ""


def _exe_of(command: str) -> str:
    return parse_command(command).executable if command else ""


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


def scan_registry(identity: AppIdentity, ctx: ScanContext, mode: ScanMode) -> list[Leftover]:
    out: list[Leftover] = []
    out += _software_keys(identity, ctx)
    out += _uninstall_entries(identity, ctx)
    out += _app_paths(identity, ctx)
    out += _run_values(identity, ctx)
    if mode >= ScanMode.MODERATE:
        out += _trace_values(identity, ctx)
        out += _msi_registration(identity, ctx)
        out += _classes(identity, ctx)
    if mode >= ScanMode.ADVANCED:
        out += _deep_walk(identity, ctx)
    return out


def _software_keys(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    reg = ctx.registry
    out = []
    for hive in HIVES:
        for view in views_for(hive):
            for child in reg.subkeys(hive, "SOFTWARE", view):
                path = join("SOFTWARE", child)
                lo = _key(hive, view, path)
                if _name_evidence(lo, identity, child):
                    out.append(lo)
                elif identity.is_publisher(child):
                    subs = reg.subkeys(hive, path, view)
                    matched = 0
                    for sub in subs:
                        sub_lo = _key(hive, view, join(path, sub))
                        if _name_evidence(sub_lo, identity, sub):
                            sub_lo.add("publisher_parent", child)
                            out.append(sub_lo)
                            if any(e.signal in ("exact_name", "exact_short_name") for e in sub_lo.evidence):
                                matched += 1
                    values = reg.values(hive, path, view)
                    if matched == len(subs) and not [v for v in values if v]:
                        pub = _key(hive, view, path).add("publisher_folder", child).add("only_app_content")
                        if identity.publisher_shared:
                            pub.add("shared_publisher")
                        out.append(pub)
    return out


def _uninstall_entries(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    out = []
    for hive, view, path in identity.uninstall_keys:
        if ctx.registry.key_exists(hive, path, view):
            out.append(_key(hive, view, path).add("uninstall_entry", path.rsplit("\\", 1)[-1]))
    return out


def _app_paths(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    reg = ctx.registry
    out = []
    base = join(CV, "App Paths")
    for hive in HIVES:
        for view in views_for(hive):
            for sub in reg.subkeys(hive, base, view):
                vals = reg.values(hive, join(base, sub), view)
                target = get_str(vals, "") or get_str(vals, "Path")
                lo = _key(hive, view, join(base, sub))
                d = _refs(identity, target)
                if d:
                    lo.add("references_install_dir", target)
                if sub.casefold() in identity.exe_names:
                    lo.add("exe_name", sub)
                    exe = _exe_of(target)
                    if exe and not os.path.exists(exe):
                        lo.add("target_missing", exe)
                if lo.evidence:
                    out.append(lo)
    return out


def _run_values(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    reg = ctx.registry
    out = []
    matched: dict[str, list] = {}
    for hive in HIVES:
        for view in views_for(hive):
            for key in RUN_KEYS:
                for v in reg.values(hive, key, view).values():
                    data = v.data if isinstance(v.data, str) else ""
                    lo = _value(hive, view, key, v.name, Category.STARTUP)
                    if _refs(identity, data):
                        lo.add("references_install_dir", data)
                    exe = _exe_of(data)
                    if exe and ntpath.basename(exe).casefold() in identity.exe_names:
                        lo.add("exe_name", ntpath.basename(exe))
                        if not os.path.exists(exe):
                            lo.add("target_missing", exe)
                    elif exe and os.path.exists(exe) and not _refs(identity, data):
                        lo.add("target_elsewhere", exe)
                    _name_evidence(lo, identity, v.name)
                    if any(e.signal != "target_elsewhere" for e in lo.evidence):
                        out.append(lo)
                        matched[v.name.casefold()] = lo.evidence
    # Task Manager's enable/disable state for the same Run entries carries the same evidence.
    for hive in HIVES:
        for v in reg.values(hive, STARTUP_APPROVED, VIEW_64).values():
            if v.name and v.name.casefold() in matched:
                lo = _value(hive, VIEW_64, STARTUP_APPROVED, v.name, Category.STARTUP)
                lo.evidence = list(matched[v.name.casefold()])
                out.append(lo)
    return out


def _trace_values(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    """MuiCache / AppCompat entries are keyed by the executable path."""
    out = []
    for hive, key in TRACE_VALUE_KEYS:
        for v in ctx.registry.values(hive, key, VIEW_64).values():
            if v.name and _refs(identity, v.name):
                out.append(_value(hive, VIEW_64, key, v.name).add("references_install_dir", v.name))
    return out


def _msi_registration(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    if not identity.product_code:
        return []
    try:
        packed = pack_guid(identity.product_code)
    except ValueError:
        return []
    out = []
    for hive, path in (
        (HKLM, rf"SOFTWARE\Classes\Installer\Products\{packed}"),
        (HKLM, rf"SOFTWARE\Classes\Installer\Features\{packed}"),
        (HKLM, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{packed}"),
        (HKCU, rf"SOFTWARE\Microsoft\Installer\Products\{packed}"),
        (HKCU, rf"SOFTWARE\Microsoft\Installer\Features\{packed}"),
    ):
        if ctx.registry.key_exists(hive, path, VIEW_64):
            out.append(_key(hive, VIEW_64, path).add("product_code", identity.product_code).add("msi_registration"))
    return out


def _classes(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    """ProgIDs and Applications\\<exe> whose open command or icon points into the install folder."""
    reg = ctx.registry
    out = []
    for hive in HIVES:
        base = r"SOFTWARE\Classes"
        for exe in identity.exe_names:
            path = join(base, "Applications", exe)
            if reg.key_exists(hive, path, VIEW_64):
                lo = _key(hive, VIEW_64, path).add("exe_name", exe)
                cmd = get_str(reg.values(hive, join(path, r"shell\open\command"), VIEW_64), "")
                if _refs(identity, cmd):
                    lo.add("references_install_dir", cmd)
                out.append(lo)
        if not identity.install_dirs:
            continue
        budget = ctx.max_registry_keys
        for name in reg.subkeys(hive, base, VIEW_64):
            if name.startswith((".", "{")) or ctx.policy.registry_key_protection(hive, join(base, name)):
                continue
            budget -= 1
            if budget <= 0:
                break
            cmd = get_str(reg.values(hive, join(base, name, r"shell\open\command"), VIEW_64), "")
            icon = get_str(reg.values(hive, join(base, name, "DefaultIcon"), VIEW_64), "")
            hit = cmd if _refs(identity, cmd) else icon if _refs(identity, icon) else ""
            if hit:
                out.append(_key(hive, VIEW_64, join(base, name)).add("references_install_dir", hit))
    return out


def _deep_walk(identity: AppIdentity, ctx: ScanContext) -> list[Leftover]:
    """Bounded walk of SOFTWARE for partially-named keys and values pointing into the install folder."""
    reg = ctx.registry
    out = []
    budget = ctx.max_registry_keys
    for hive in HIVES:
        for view in views_for(hive):
            stack = [(join("SOFTWARE", c), 1, c) for c in reg.subkeys(hive, "SOFTWARE", view)
                     if c.casefold() not in DEEP_SKIP]
            while stack and budget > 0:
                path, depth, vendor = stack.pop()
                budget -= 1
                leaf = path.rsplit("\\", 1)[-1]
                own_vendor = bool(identity.match_name(vendor)[0]) or identity.is_publisher(vendor)
                if depth >= 2:
                    lo = _key(hive, view, path)
                    if _name_evidence(lo, identity, leaf):
                        if identity.is_publisher(vendor):
                            lo.add("publisher_parent", vendor)
                        if not own_vendor:
                            lo.add("foreign_key", vendor)
                        out.append(lo)
                        continue
                if identity.install_dirs:
                    for v in reg.values(hive, path, view).values():
                        if isinstance(v.data, str) and _refs(identity, v.data):
                            lo = _value(hive, view, path, v.name).add("references_install_dir", v.data)
                            if not own_vendor:
                                lo.add("foreign_key", vendor)
                            out.append(lo)
                if depth < 5:
                    stack.extend((join(path, c), depth + 1, vendor) for c in reg.subkeys(hive, path, view))
    return out

