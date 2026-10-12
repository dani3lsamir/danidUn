"""Windows services that belong to the application (drivers are reported but protected)."""
from __future__ import annotations

import ntpath
import os

from ..cmdline import expand_env, parse_command
from ..models import Category, Kind, Leftover
from ..paths import references_dir
from ..registry import HKLM, VIEW_64, get_int, get_str, join
from .context import AppIdentity, ScanContext, ScanMode

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


def scan_services(identity: AppIdentity, ctx: ScanContext, mode: ScanMode) -> list[Leftover]:
    reg = ctx.registry
    out = []
    for name in reg.subkeys(HKLM, SERVICES_KEY, VIEW_64):
        vals = reg.values(HKLM, join(SERVICES_KEY, name), VIEW_64)
        image = get_str(vals, "ImagePath")
        stype = get_int(vals, "Type")
        if stype is None or not image:
            continue
        display = get_str(vals, "DisplayName")
        lo = Leftover(Kind.SERVICE, name, Category.SERVICES, note=f"{display} | {image}".strip(" |"))
        if any(references_dir(image, d) for d in identity.install_dirs):
            lo.add("references_install_dir", image)
        exe = parse_command(expand_env(image)).executable
        if exe and ntpath.basename(exe).casefold() in identity.exe_names:
            lo.add("exe_name", ntpath.basename(exe))
            if not os.path.exists(exe):
                lo.add("target_missing", exe)
        for raw in (name, display):
            kind, matched = identity.match_name(raw) if raw and not raw.startswith("@") else ("", "")
            if kind == "exact":
                lo.add("exact_name" if len(matched) >= 6 else "exact_short_name", raw)
                break
            if kind == "partial":
                lo.add("partial_name", f"{raw} ~ {matched}")
                break
        if not lo.evidence:
            continue
        lo.protected = ctx.policy.service_protection(name, image, stype)
        if not lo.protected and "security_software" in identity.flags:
            lo.protected = "protect.security_software"
        out.append(lo)
    return out
