"""Name normalisation and identity helpers shared by inventory and scanner."""
from __future__ import annotations

import re
import unicodedata

# Normalised words that never identify a single application on their own.
GENERIC_NAMES = frozenset("""
windows microsoft system system32 syswow64 common commonfiles programfiles programfilesx86
programdata appdata local locallow roaming users user public default desktop documents temp tmp
update updater updates runtime runtimes software bin data app apps application applications
uninstall uninstaller uninst setup install installer installers config configuration cache caches
log logs settings plugin plugins tool tools utilities utility driver drivers service services help
docs doc resources resource package packages shared lib libs library libraries backup backups
launcher client server player editor viewer manager studio browser game games module modules
extension extensions addon addons profile profiles storage support media music pictures videos
downloads security defender helper agent host core base main sdk kit toolkit redist
redistributable vcredist x64 x86 amd64 arm64 64bit 32bit free pro lite portable beta test demo new
old home userdata localstorage crashreports crashpad crashdumps dumps reports report fonts font
assembly assemblies framework components component startmenu programs startup quicklaunch
internetexplorer windowsapps microsoftshared net dotnet google apple intel nvidia amd adobe
oracle java python node npm git github origin
""".split())

_COMPANY_SUFFIX = re.compile(
    r"[,\s]+(?:inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|ag|s\.?\s?a|"
    r"s\.?\s?l|b\.?\s?v|srl|oy|ab|as|pty|plc|kg|sas|sarl|technologies|technology|software|"
    r"systems|labs|group|international|foundation|project|team|development|studios?)\.?\s*$",
    re.I,
)
_PARENS = re.compile(r"\s*[\(\[][^\)\]]*[\)\]]")
_ARCH = re.compile(r"(?<![a-z0-9])(?:x64|x86|amd64|arm64|64[- ]?bits?|32[- ]?bits?|win64|win32)(?![a-z0-9])", re.I)
_VERSION_TAIL = re.compile(r"[\s_\-]+(?:v(?:ersion)?\.?\s*)?\d+(?:[.\-_]\d+){0,4}[a-z]?\s*$", re.I)
_LANG_TAIL = re.compile(r"[\s_\-]+[a-z]{2}-[a-z]{2}\s*$", re.I)
GUID_RE = re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", re.I)

STRONG_NAME_LEN = 6
MIN_NAME_LEN = 4


def normalize(text: str) -> str:
    """Lower-case, accent-free, alphanumeric-only form used for comparisons."""
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", text.casefold())


def is_specific(norm: str, min_len: int = MIN_NAME_LEN) -> bool:
    """True when a normalised name is long and specific enough to identify an app."""
    return len(norm) >= min_len and norm not in GENERIC_NAMES and not norm.isdigit()


def strip_decorations(name: str) -> str:
    """Remove version numbers, architecture tags, locales and parenthesised notes."""
    s = _PARENS.sub("", name or "")
    s = _ARCH.sub(" ", s)
    for _ in range(3):
        new = _LANG_TAIL.sub("", _VERSION_TAIL.sub("", s)).strip(" -_.,")
        if new == s:
            break
        s = new
    return re.sub(r"\s{2,}", " ", s).strip(" -_.,")


def publisher_forms(publisher: str) -> list[str]:
    """Raw publisher spellings without legal suffixes, e.g. 'Mozilla Corporation' -> 'Mozilla'."""
    forms: list[str] = []
    current = (publisher or "").strip().strip(".")
    while current and current not in forms:
        forms.append(current)
        current = _COMPANY_SUFFIX.sub("", current).strip(" ,.")
    return forms


def publisher_variants(publisher: str) -> list[str]:
    out: list[str] = []
    for form in publisher_forms(publisher):
        n = normalize(form)
        if is_specific(n, 3) and n not in out:
            out.append(n)
    return out


def name_variants(name: str, publisher: str = "") -> list[str]:
    """Normalised identifying names; the first entry is the primary (cleaned display) name."""
    out: list[str] = []

    def add(raw: str) -> None:
        n = normalize(raw)
        if is_specific(n) and n not in out:
            out.append(n)

    cleaned = strip_decorations(name)
    add(cleaned)
    add(name)
    for form in publisher_forms(publisher):
        if cleaned.casefold().startswith(form.casefold() + " "):
            add(cleaned[len(form):])
    return out


def find_guid(text: str) -> str:
    m = GUID_RE.search(text or "")
    return m.group(0).upper() if m else ""


def pack_guid(guid: str) -> str:
    """Convert {XXXXXXXX-...} to the 'packed' form used under Installer\\Products."""
    g = guid.strip("{}").replace("-", "").upper()
    if len(g) != 32 or not re.fullmatch(r"[0-9A-F]{32}", g):
        raise ValueError("invalid GUID")
    parts = [g[0:8][::-1], g[8:12][::-1], g[12:16][::-1]]
    rest = g[16:]
    parts.append("".join(rest[i:i + 2][::-1] for i in range(0, 16, 2)))
    return "".join(parts)


def slug(text: str, limit: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text or "").strip("-.")
    return (s or "app")[:limit]
