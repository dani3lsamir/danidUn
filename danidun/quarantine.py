"""Reversible removal: everything is backed up into a session folder before it is removed,
and every session can be restored. Each item is re-validated by the safety policy at the
moment of removal *and* at the moment of restore."""
from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .models import Kind, Leftover
from .paths import is_reparse_point, is_within
from .registry import HKLM, VIEW_64, RegistryBackend, join
from .safety import SafetyPolicy
from .sysops import SystemOps
from .textutil import slug

log = logging.getLogger(__name__)
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
ORDER = {Kind.SERVICE: 0, Kind.TASK: 1, Kind.REG_VALUE: 2, Kind.REG_KEY: 3, Kind.FILE: 4, Kind.FOLDER: 5}


def default_base() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "danidUn"


@dataclass
class ItemResult:
    leftover: Leftover
    status: str  # removed | partial | failed | skipped
    backup: str = ""
    value: dict | None = None
    error: str = ""
    locked: list[str] = field(default_factory=list)
    restored: bool = False

    def to_dict(self) -> dict:
        return {"leftover": self.leftover.to_dict(), "status": self.status, "backup": self.backup,
                "value": self.value, "error": self.error, "locked": self.locked[:50], "restored": self.restored}


@dataclass
class Session:
    path: Path
    application: str
    created: str
    items: list[ItemResult] = field(default_factory=list)

    @property
    def removed(self) -> int:
        return sum(1 for i in self.items if i.status in ("removed", "partial"))

    def save(self) -> None:
        data = {"application": self.application, "created": self.created, "format": 1,
                "items": [i.to_dict() for i in self.items]}
        tmp = self.path / "manifest.json.tmp"
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path / "manifest.json")

    @classmethod
    def load(cls, path: Path) -> "Session":
        data = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        s = cls(path, data.get("application", "?"), data.get("created", ""))
        for raw in data.get("items", []):
            s.items.append(ItemResult(Leftover.from_dict(raw["leftover"]), raw.get("status", ""),
                                      raw.get("backup", ""), raw.get("value"), raw.get("error", ""),
                                      raw.get("locked", []), raw.get("restored", False)))
        return s


def _encode_value(data: object) -> object:
    if isinstance(data, bytes):
        return {"b64": base64.b64encode(data).decode("ascii")}
    return data


def _decode_value(data: object) -> object:
    if isinstance(data, dict) and "b64" in data:
        return base64.b64decode(data["b64"])
    return data


def reg_file_keys(path: Path) -> list[str]:
    raw = path.read_bytes()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    return [m.group(1) for m in re.finditer(r"^\[(-?[^\]\r\n]+)\]\s*$", text, re.M)]


_HIVE_ALIASES = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU"}


def _reg_file_confined(path: Path, hive: str, key: str) -> bool:
    """Every key in the .reg file must be the original key or one of its subkeys."""
    keys = reg_file_keys(path)
    if not keys:
        return False
    want = join(hive, key).casefold()
    for k in keys:
        if k.startswith("-"):
            return False
        head, _, rest = k.partition("\\")
        k = join(_HIVE_ALIASES.get(head.upper(), head.upper()), rest).casefold()
        k = re.sub(r"^hklm\\software\\wow6432node\\", r"hklm\\software\\", k)
        if not (k == want or k.startswith(want + "\\")):
            return False
    return True


class Quarantine:
    def __init__(self, registry: RegistryBackend, sysops: SystemOps, base: Path | None = None) -> None:
        self.registry = registry
        self.sysops = sysops
        self.base = (base or default_base()) / "Quarantine"

    # ------------------------------------------------------------------ removal
    def remove(self, application: str, leftovers: list[Leftover], policy: SafetyPolicy,
               progress=None) -> Session:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = self.base / f"{stamp}-{slug(application)}-{uuid.uuid4().hex[:4]}"
        for sub in ("files", "registry", "tasks"):
            (path / sub).mkdir(parents=True, exist_ok=True)
        session = Session(path, application, dt.datetime.now().isoformat(timespec="seconds"))
        session.save()
        items = sorted(leftovers, key=lambda lo: ORDER[lo.kind])
        for index, lo in enumerate(items):
            if progress:
                progress(lo, index, len(items))
            result = self._remove_one(lo, policy, session, index)
            session.items.append(result)
            session.save()  # persist after every item: a crash never loses a backup reference
            log.info("remove %s %s -> %s %s", lo.kind.value, lo.display, result.status, result.error)
        return session

    def _remove_one(self, lo: Leftover, policy: SafetyPolicy, session: Session, n: int) -> ItemResult:
        try:
            reason = self._protection(lo, policy)
            if reason:
                return ItemResult(lo, "skipped", error=reason)
            if lo.kind in (Kind.FOLDER, Kind.FILE):
                return self._move_path(lo, session, n)
            if lo.kind == Kind.REG_KEY:
                if not self.registry.key_exists(lo.hive, lo.target, lo.view):
                    return ItemResult(lo, "skipped", error="missing")
                dest = session.path / "registry" / f"{n:04d}.reg"
                self.registry.export_key(lo.hive, lo.target, lo.view, dest)
                self.registry.delete_tree(lo.hive, lo.target, lo.view)
                return ItemResult(lo, "removed", backup=str(dest.relative_to(session.path)))
            if lo.kind == Kind.REG_VALUE:
                values = self.registry.values(lo.hive, lo.target, lo.view)
                v = values.get((lo.value_name or "").casefold())
                if v is None:
                    return ItemResult(lo, "skipped", error="missing")
                saved = {"name": v.name, "type": v.type, "data": _encode_value(v.data)}
                self.registry.delete_value(lo.hive, lo.target, lo.view, v.name)
                return ItemResult(lo, "removed", value=saved)
            if lo.kind == Kind.SERVICE:
                key = join(SERVICES_KEY, lo.target)
                dest = session.path / "registry" / f"{n:04d}-service.reg"
                self.registry.export_key(HKLM, key, VIEW_64, dest)
                self.sysops.stop_service(lo.target)
                self.sysops.delete_service(lo.target)
                return ItemResult(lo, "removed", backup=str(dest.relative_to(session.path)))
            if lo.kind == Kind.TASK:
                dest = session.path / "tasks" / f"{n:04d}.xml"
                self.sysops.export_task(lo.target, dest)
                self.sysops.delete_task(lo.target)
                return ItemResult(lo, "removed", backup=str(dest.relative_to(session.path)))
            return ItemResult(lo, "skipped", error="unknown kind")
        except PermissionError as exc:
            return ItemResult(lo, "failed", error=f"access_denied: {exc}")
        except Exception as exc:  # noqa: BLE001 - reported to the user per item
            return ItemResult(lo, "failed", error=str(exc))

    @staticmethod
    def _protection(lo: Leftover, policy: SafetyPolicy) -> str:
        if lo.protected:
            return lo.protected
        if lo.kind in (Kind.FOLDER, Kind.FILE):
            return policy.path_protection(lo.target)
        if lo.kind == Kind.REG_KEY:
            return policy.registry_key_protection(lo.hive, lo.target)
        if lo.kind == Kind.REG_VALUE:
            return policy.registry_value_protection(lo.hive, lo.target, lo.value_name)
        if lo.kind == Kind.TASK:
            return policy.task_protection(lo.target, lo.note)
        return ""

    def _move_path(self, lo: Leftover, session: Session, n: int) -> ItemResult:
        src = lo.target
        if not os.path.lexists(src):
            return ItemResult(lo, "skipped", error="missing")
        if is_reparse_point(src):
            return ItemResult(lo, "skipped", error="protect.reparse_point")
        rel = Path("files") / f"{n:04d}-{slug(os.path.basename(src), 60)}"
        dest = session.path / rel
        try:
            os.rename(src, dest)  # same volume: atomic and keeps ACLs
            return ItemResult(lo, "removed", backup=str(rel))
        except OSError:
            pass
        if os.path.isfile(src):
            shutil.copy2(src, dest)
            os.remove(src)
            return ItemResult(lo, "removed", backup=str(rel))
        # Cross-volume or partially locked folder: copy everything, then delete what we can.
        # Reparse points (junctions/symlinks) are neither followed nor removed.
        shutil.copytree(src, dest, ignore=_ignore_reparse)
        locked: list[str] = []
        _delete_tree_safely(src, locked)
        status = "partial" if locked or os.path.exists(src) else "removed"
        return ItemResult(lo, status, backup=str(rel), locked=locked)

    # ------------------------------------------------------------------ sessions
    def sessions(self) -> list[Session]:
        out = []
        if not self.base.is_dir():
            return out
        for p in sorted(self.base.iterdir(), reverse=True):
            if (p / "manifest.json").is_file():
                try:
                    out.append(Session.load(p))
                except (OSError, ValueError, KeyError):
                    log.warning("unreadable quarantine session %s", p)
        return out

    def purge(self, session: Session) -> None:
        if not is_within(str(session.path), str(self.base)) or session.path.resolve() == self.base.resolve():
            raise RuntimeError("refusing to delete outside the quarantine folder")
        shutil.rmtree(session.path)

    # ------------------------------------------------------------------ restore
    def restore(self, session: Session, policy: SafetyPolicy) -> tuple[int, list[str]]:
        restored, errors = 0, []
        for item in sorted(session.items, key=lambda i: -ORDER[i.leftover.kind]):
            if item.restored or item.status not in ("removed", "partial"):
                continue
            lo = item.leftover
            try:
                self._restore_one(item, session, policy)
                item.restored = True
                restored += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{lo.display}: {exc}")
            session.save()
        return restored, errors

    def _backup_path(self, session: Session, rel: str) -> Path:
        p = (session.path / rel)
        if not rel or not is_within(str(p), str(session.path)) or is_reparse_point(str(p)):
            raise RuntimeError("backup outside session")
        return p

    def _restore_one(self, item: ItemResult, session: Session, policy: SafetyPolicy) -> None:
        lo = item.leftover
        if lo.kind in (Kind.FOLDER, Kind.FILE):
            reason = policy.path_protection(lo.target, check_disk=False)
            if reason and not reason.startswith("protect.other_app"):
                raise RuntimeError(reason)
            src = self._backup_path(session, item.backup)
            if item.status == "partial" and os.path.isdir(lo.target):
                _merge_back(src, lo.target)
                return
            if os.path.lexists(lo.target):
                raise RuntimeError("target_exists")
            os.makedirs(os.path.dirname(lo.target), exist_ok=True)
            shutil.move(str(src), lo.target)
        elif lo.kind == Kind.REG_KEY:
            if policy.registry_key_protection(lo.hive, lo.target):
                raise RuntimeError("protect.registry")
            src = self._backup_path(session, item.backup)
            if not _reg_file_confined(src, lo.hive, lo.target):
                raise RuntimeError("reg_file_mismatch")
            self.registry.import_file(src, lo.view)
        elif lo.kind == Kind.REG_VALUE:
            if policy.registry_value_protection(lo.hive, lo.target, lo.value_name) or not item.value:
                raise RuntimeError("protect.registry")
            v = item.value
            self.registry.set_value(lo.hive, lo.target, lo.view, v["name"], int(v["type"]), _decode_value(v["data"]))
        elif lo.kind == Kind.SERVICE:
            src = self._backup_path(session, item.backup)
            if not _reg_file_confined(src, HKLM, join(SERVICES_KEY, lo.target)):
                raise RuntimeError("reg_file_mismatch")
            self.registry.import_file(src, VIEW_64)  # registered again by the SCM after a reboot
        elif lo.kind == Kind.TASK:
            src = self._backup_path(session, item.backup)
            self.sysops.create_task(lo.target, src)


def _ignore_reparse(directory: str, names: list[str]) -> list[str]:
    return [n for n in names if is_reparse_point(os.path.join(directory, n))]


def _delete_tree_safely(path: str, locked: list[str]) -> None:
    try:
        entries = list(os.scandir(path))
    except OSError:
        locked.append(path)
        return
    for entry in entries:
        if is_reparse_point(entry.path):
            locked.append(entry.path)  # left in place on purpose
            continue
        if entry.is_dir(follow_symlinks=False):
            _delete_tree_safely(entry.path, locked)
            continue
        try:
            os.chmod(entry.path, 0o666)
            os.remove(entry.path)
        except OSError:
            locked.append(entry.path)
    try:
        os.rmdir(path)
    except OSError:
        pass


def _merge_back(src: Path, target: str) -> None:
    for current, _dirs, files in os.walk(src):
        rel = os.path.relpath(current, src)
        dest_dir = os.path.join(target, rel) if rel != "." else target
        os.makedirs(dest_dir, exist_ok=True)
        for name in files:
            dest = os.path.join(dest_dir, name)
            if not os.path.exists(dest):
                shutil.copy2(os.path.join(current, name), dest)
