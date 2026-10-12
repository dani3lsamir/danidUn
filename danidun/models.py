"""Core data structures."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum


class Source(str, Enum):
    WIN32 = "win32"
    MSI = "msi"
    STORE = "store"
    FORCED = "forced"  # synthetic entry created by the forced-uninstall workflow


class Status(str, Enum):
    NO_UNINSTALLER = "no_uninstaller"
    UNINSTALLER_MISSING = "uninstaller_missing"
    LOCATION_MISSING = "location_missing"
    MSI_UNREGISTERED = "msi_unregistered"


BROKEN_STATES = {Status.NO_UNINSTALLER, Status.UNINSTALLER_MISSING, Status.MSI_UNREGISTERED}


@dataclass
class Program:
    name: str
    version: str = ""
    publisher: str = ""
    install_location: str = ""
    location_inferred: bool = False
    uninstall_string: str = ""
    quiet_uninstall_string: str = ""
    modify_path: str = ""
    display_icon: str = ""
    install_date: str = ""  # ISO yyyy-mm-dd when known
    size_kb: int = 0
    source: Source = Source.WIN32
    scope: str = "machine"  # machine | user
    hive: str = ""
    view: int = 64
    key_path: str = ""
    key_name: str = ""
    product_code: str = ""
    no_remove: bool = False
    package_full_name: str = ""
    package_family_name: str = ""
    status: list[Status] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # security_software, shared_runtime, ...

    @property
    def uid(self) -> str:
        if self.source == Source.STORE:
            return "store|" + self.package_full_name
        return f"{self.hive}|{self.view}|{self.key_path}|{self.name}"

    @property
    def is_broken(self) -> bool:
        return any(s in BROKEN_STATES for s in self.status)

    @property
    def architecture(self) -> str:
        if self.source == Source.STORE:
            return "Store"
        if self.scope == "user":
            return "user"
        return "32-bit" if self.view == 32 else "64-bit"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = self.source.value
        d["status"] = [s.value for s in self.status]
        return d


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class Kind(str, Enum):
    FOLDER = "folder"
    FILE = "file"
    REG_KEY = "reg_key"
    REG_VALUE = "reg_value"
    SERVICE = "service"
    TASK = "task"


class Category(str, Enum):
    FILES = "files"
    REGISTRY = "registry"
    SERVICES = "services"
    TASKS = "tasks"
    STARTUP = "startup"
    SHORTCUTS = "shortcuts"


@dataclass
class Evidence:
    signal: str
    detail: str = ""


@dataclass
class Leftover:
    kind: Kind
    target: str  # filesystem path, registry key path, service name or task path
    category: Category
    evidence: list[Evidence] = field(default_factory=list)
    hive: str = ""
    view: int = 0
    value_name: str | None = None
    size: int = 0
    score: int = 0
    confidence: Confidence = Confidence.LOW
    protected: str = ""  # non-empty => shown for transparency, never removable
    note: str = ""

    @property
    def key(self) -> str:
        base = self.target.casefold()
        if self.kind in (Kind.REG_KEY, Kind.REG_VALUE):
            base = f"{self.hive}|{self.view}|{base}|{(self.value_name or '').casefold()}"
        return f"{self.kind.value}|{base}"

    @property
    def display(self) -> str:
        if self.kind == Kind.REG_KEY:
            return f"{self.hive}\\{self.target}" + (" [32-bit]" if self.view == 32 and self.hive == "HKLM" else "")
        if self.kind == Kind.REG_VALUE:
            name = self.value_name or "(default)"
            return f"{self.hive}\\{self.target}  →  {name}" + (" [32-bit]" if self.view == 32 and self.hive == "HKLM" else "")
        return self.target

    @property
    def selectable(self) -> bool:
        return not self.protected

    def add(self, signal: str, detail: str = "") -> "Leftover":
        if not any(e.signal == signal for e in self.evidence):
            self.evidence.append(Evidence(signal, detail))
        return self

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value, "target": self.target, "category": self.category.value,
            "hive": self.hive, "view": self.view, "value_name": self.value_name, "size": self.size,
            "score": self.score, "confidence": self.confidence.name, "protected": self.protected,
            "note": self.note, "evidence": [asdict(e) for e in self.evidence], "display": self.display,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Leftover":
        return cls(kind=Kind(d["kind"]), target=d["target"], category=Category(d["category"]),
                   evidence=[Evidence(**e) for e in d.get("evidence", [])], hive=d.get("hive", ""),
                   view=d.get("view", 0), value_name=d.get("value_name"), size=d.get("size", 0),
                   score=d.get("score", 0), confidence=Confidence[d.get("confidence", "LOW")],
                   protected=d.get("protected", ""), note=d.get("note", ""))
