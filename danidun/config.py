"""User settings and logging (stored under %LOCALAPPDATA%\\danidUn)."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from .quarantine import default_base


@dataclass
class Settings:
    language: str = ""          # '' = follow Windows
    scan_mode: str = "MODERATE"  # SAFE | MODERATE | ADVANCED
    create_restore_point: bool = True
    show_store_apps: bool = True
    show_protected: bool = True

    @classmethod
    def load(cls, base: Path | None = None) -> "Settings":
        path = (base or default_base()) / "settings.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        except (OSError, ValueError, TypeError):
            return cls()

    def save(self, base: Path | None = None) -> None:
        folder = base or default_base()
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "settings.json").write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def reports_dir() -> Path:
    return default_base() / "Reports"


def setup_logging() -> Path:
    folder = default_base() / "logs"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "danidun.log"
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if os.environ.get("DANIDUN_DEBUG") else logging.INFO)
    root.addHandler(handler)
    return path
