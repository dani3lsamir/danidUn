"""In-memory registry and system operations for tests."""
from __future__ import annotations

import json
from pathlib import Path

from danidun.registry import HKLM, VIEW_32, VIEW_64, RegValue, join


class FakeRegistry:
    def __init__(self) -> None:
        # (hive, view) -> {lower path: (original path, {lower name: RegValue})}
        self.keys: dict[tuple[str, int], dict[str, tuple[str, dict]]] = {}

    def _view(self, hive: str, view: int) -> int:
        return view if hive == HKLM else VIEW_64

    def _store(self, hive: str, view: int) -> dict:
        return self.keys.setdefault((hive, self._view(hive, view)), {})

    def add_key(self, hive: str, path: str, values: dict | None = None, view: int = VIEW_64) -> None:
        store = self._store(hive, view)
        parts = path.split("\\")
        for i in range(1, len(parts) + 1):
            sub = "\\".join(parts[:i])
            store.setdefault(sub.casefold(), (sub, {}))
        vals = store[path.casefold()][1]
        for name, data in (values or {}).items():
            type_ = 4 if isinstance(data, int) else 1
            vals[name.casefold()] = RegValue(name, data, type_)

    # backend protocol --------------------------------------------------------
    def subkeys(self, hive, path, view=VIEW_64):
        store = self._store(hive, view)
        prefix = path.casefold() + "\\"
        out = []
        for low, (orig, _vals) in store.items():
            if low.startswith(prefix) and "\\" not in low[len(prefix):]:
                out.append(orig.rsplit("\\", 1)[-1])
        return sorted(out)

    def values(self, hive, path, view=VIEW_64):
        entry = self._store(hive, view).get(path.casefold())
        return dict(entry[1]) if entry else {}

    def key_exists(self, hive, path, view=VIEW_64):
        return path.casefold() in self._store(hive, view)

    def last_write(self, hive, path, view=VIEW_64):
        return None

    def export_key(self, hive, path, view, dest: Path):
        store = self._store(hive, view)
        prefix = path.casefold()
        lines = ["Windows Registry Editor Version 5.00", ""]
        dump = {}
        for low, (orig, vals) in store.items():
            if low == prefix or low.startswith(prefix + "\\"):
                hive_long = "HKEY_LOCAL_MACHINE" if hive == HKLM else "HKEY_CURRENT_USER"
                lines.append(f"[{hive_long}\\{orig}]")
                dump[orig] = {v.name: [v.data, v.type] for v in vals.values()}
        text = "\r\n".join(lines) + "\r\n;" + json.dumps({"hive": hive, "keys": dump})
        Path(dest).write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))

    def import_file(self, src: Path, view):
        text = Path(src).read_bytes()[2:].decode("utf-16-le")
        payload = json.loads(text.rsplit(";", 1)[1])
        for path, vals in payload["keys"].items():
            self.add_key(payload["hive"], path, view=view)
            store = self._store(payload["hive"], view)[path.casefold()][1]
            for name, (data, type_) in vals.items():
                store[name.casefold()] = RegValue(name, data, type_)

    def delete_tree(self, hive, path, view):
        store = self._store(hive, view)
        prefix = path.casefold()
        for low in [k for k in store if k == prefix or k.startswith(prefix + "\\")]:
            del store[low]

    def delete_value(self, hive, path, view, name):
        del self._store(hive, view)[path.casefold()][1][name.casefold()]

    def set_value(self, hive, path, view, name, type_, data):
        self.add_key(hive, path, view=view)
        self._store(hive, view)[path.casefold()][1][name.casefold()] = RegValue(name, data, type_)


class FakeSysOps:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.tasks: dict[str, bytes] = {}

    def stop_service(self, name):
        self.calls.append(("stop", name))

    def delete_service(self, name):
        self.calls.append(("delete_service", name))

    def export_task(self, task_path, dest):
        Path(dest).write_bytes(self.tasks.get(task_path, b"<Task/>"))

    def delete_task(self, task_path):
        self.calls.append(("delete_task", task_path))

    def create_task(self, task_path, xml_file):
        self.calls.append(("create_task", task_path))

    def create_restore_point(self, description):
        return True, ""


__all__ = ["FakeRegistry", "FakeSysOps", "join", "VIEW_32"]
