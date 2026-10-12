"""Runs all scanners, merges evidence per target, scores, applies protection and filters."""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

from ..models import Category, Confidence, Kind, Leftover
from ..paths import folder_size, is_within
from . import scoring
from .context import MIN_CONFIDENCE, AppIdentity, ScanContext, ScanMode
from .files import scan_files
from .registry_scan import scan_registry
from .services import scan_services
from .shortcuts import scan_shortcuts
from .tasks import scan_tasks

log = logging.getLogger(__name__)

STAGES = (
    ("files", scan_files),
    ("registry", scan_registry),
    ("services", scan_services),
    ("tasks", scan_tasks),
    ("shortcuts", scan_shortcuts),
)
CATEGORY_ORDER = [Category.FILES, Category.REGISTRY, Category.SERVICES, Category.TASKS,
                  Category.STARTUP, Category.SHORTCUTS]


@dataclass
class ScanResult:
    identity: AppIdentity
    mode: ScanMode
    leftovers: list[Leftover] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    hidden_below_threshold: int = 0

    def counts(self) -> dict[str, int]:
        out = {c.name: 0 for c in Confidence}
        for lo in self.leftovers:
            out[lo.confidence.name] += 1
        out["PROTECTED"] = sum(1 for lo in self.leftovers if lo.protected)
        return out

    def to_dict(self) -> dict:
        return {"mode": self.mode.name, "elapsed_s": round(self.elapsed, 2), "errors": self.errors,
                "identity": self.identity.to_dict(), "counts": self.counts(),
                "hidden_below_threshold": self.hidden_below_threshold,
                "leftovers": [lo.to_dict() for lo in self.leftovers]}


def run_scan(identity: AppIdentity, ctx: ScanContext, mode: ScanMode = ScanMode.MODERATE,
             progress=None, cancel=None) -> ScanResult:
    start = time.monotonic()
    result = ScanResult(identity, mode)
    merged: dict[str, Leftover] = {}
    for index, (name, fn) in enumerate(STAGES):
        if cancel is not None and cancel.is_set():
            result.errors.append("cancelled")
            break
        if progress:
            progress(name, index, len(STAGES))
        try:
            items = fn(identity, ctx, mode)
        except Exception as exc:  # noqa: BLE001 - one failing stage must not abort the scan
            log.exception("scan stage %s failed", name)
            result.errors.append(f"{name}: {exc}")
            continue
        for item in items:
            existing = merged.get(item.key)
            if existing is None:
                merged[item.key] = item
            else:
                for ev in item.evidence:
                    existing.add(ev.signal, ev.detail)
                existing.protected = existing.protected or item.protected
                existing.note = existing.note or item.note
    finalize(list(merged.values()), ctx, mode, result)
    result.elapsed = time.monotonic() - start
    if progress:
        progress("done", len(STAGES), len(STAGES))
    return result


def protection_for(lo: Leftover, ctx: ScanContext) -> str:
    policy = ctx.policy
    if lo.kind in (Kind.FOLDER, Kind.FILE):
        return policy.path_protection(lo.target)
    if lo.kind == Kind.REG_KEY:
        return policy.registry_key_protection(lo.hive, lo.target)
    if lo.kind == Kind.REG_VALUE:
        reason = policy.registry_value_protection(lo.hive, lo.target, lo.value_name)
        if not reason and lo.category == Category.STARTUP:
            # A Run value that launches another installed application is not ours.
            reason = policy.text_belongs_to_other(lo.note or "")
        return reason
    return lo.protected


def finalize(items: list[Leftover], ctx: ScanContext, mode: ScanMode, result: ScanResult) -> None:
    threshold = MIN_CONFIDENCE[mode]
    kept: list[Leftover] = []
    for lo in items:
        scoring.apply(lo)
        lo.protected = lo.protected or protection_for(lo, ctx)
        if lo.confidence < threshold:
            result.hidden_below_threshold += 1
            continue
        kept.append(lo)
    kept = _collapse_nested(kept)
    for lo in kept:
        if lo.kind == Kind.FOLDER and not lo.protected:
            lo.size = folder_size(lo.target)
        elif lo.kind == Kind.FILE:
            try:
                lo.size = os.path.getsize(lo.target)
            except OSError:
                lo.size = 0
    kept.sort(key=lambda x: (CATEGORY_ORDER.index(x.category), -int(x.confidence), -x.score, x.display.casefold()))
    result.leftovers = kept


def _collapse_nested(items: list[Leftover]) -> list[Leftover]:
    """Drop entries contained in another removable entry of equal or higher confidence."""
    folders = [i for i in items if i.kind == Kind.FOLDER and not i.protected]
    keys = [i for i in items if i.kind == Kind.REG_KEY and not i.protected]
    out = []
    for item in items:
        parent = None
        if item.kind in (Kind.FOLDER, Kind.FILE):
            parent = next((f for f in folders if f is not item and is_within(item.target, f.target)
                           and f.confidence >= item.confidence), None)
        elif item.kind in (Kind.REG_KEY, Kind.REG_VALUE):
            parent = next((k for k in keys if k is not item and k.hive == item.hive and k.view == item.view
                           and _reg_within(item.target, k.target, item.kind == Kind.REG_VALUE)
                           and k.confidence >= item.confidence), None)
        if parent is None:
            out.append(item)
    return out


def _reg_within(child: str, parent: str, is_value: bool) -> bool:
    c, p = child.casefold().strip("\\"), parent.casefold().strip("\\")
    if is_value:
        return c == p or c.startswith(p + "\\")
    return c.startswith(p + "\\")
