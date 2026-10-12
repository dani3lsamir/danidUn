"""Scheduled tasks, read from the task store XML (read-only; removal uses schtasks.exe)."""
from __future__ import annotations

import ntpath
import os
import xml.etree.ElementTree as ET

from ..cmdline import expand_env
from ..models import Category, Kind, Leftover
from ..paths import references_dir
from ..textutil import normalize
from .context import AppIdentity, ScanContext, ScanMode


def read_task(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            data = fh.read(2_000_000)
        root = ET.fromstring(data)
    except (OSError, ET.ParseError, ValueError):
        return {}
    info = {"commands": [], "author": ""}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "Exec":
            cmd = args = ""
            for sub in el:
                stag = sub.tag.rsplit("}", 1)[-1]
                if stag == "Command":
                    cmd = (sub.text or "").strip().strip('"')
                elif stag == "Arguments":
                    args = (sub.text or "").strip()
            info["commands"].append((expand_env(cmd), args))
        elif tag == "Author" and not info["author"]:
            info["author"] = (el.text or "").strip()
    return info


def iter_tasks(tasks_dir: str, limit: int = 5000):
    count = 0
    for current, dirs, files in os.walk(tasks_dir):
        rel = os.path.relpath(current, tasks_dir)
        if rel.split(os.sep)[0].casefold() == "microsoft":
            dirs[:] = []
            continue
        for fname in files:
            count += 1
            if count > limit:
                return
            full = os.path.join(current, fname)
            task_path = "\\" + os.path.relpath(full, tasks_dir).replace(os.sep, "\\")
            yield task_path, full


def scan_tasks(identity: AppIdentity, ctx: ScanContext, mode: ScanMode) -> list[Leftover]:
    tasks_dir = ctx.folders.tasks_dir
    if not tasks_dir or not os.path.isdir(tasks_dir):
        return []
    out = []
    for task_path, full in iter_tasks(tasks_dir):
        info = read_task(full)
        if not info:
            continue
        lo = Leftover(Kind.TASK, task_path, Category.TASKS)
        for cmd, args in info["commands"]:
            if any(references_dir(cmd, d) or references_dir(args, d) for d in identity.install_dirs):
                lo.add("references_install_dir", f"{cmd} {args}".strip())
            base = ntpath.basename(cmd).casefold()
            if base in identity.exe_names:
                lo.add("exe_name", base)
                if os.path.isabs(cmd) and not os.path.exists(cmd):
                    lo.add("target_missing", cmd)
            lo.note = f"{cmd} {args}".strip()
        leaf = task_path.rsplit("\\", 1)[-1]
        kind, matched = identity.match_name(leaf)
        if kind == "exact":
            lo.add("exact_name" if len(matched) >= 6 else "exact_short_name", leaf)
        elif kind == "partial":
            lo.add("partial_name", f"{leaf} ~ {matched}")
        if not lo.evidence:
            continue
        if info["author"] and normalize(info["author"]) in identity.publishers:
            lo.add("author_publisher", info["author"])
        lo.protected = ctx.policy.task_protection(task_path, lo.note)
        out.append(lo)
    return out
