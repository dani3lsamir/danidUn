"""Minimal reader for Shell Link (.lnk) files, per the public [MS-SHLLINK] specification."""
from __future__ import annotations

import os
import struct

from .cmdline import expand_env

HAS_ID_LIST = 0x01
HAS_LINK_INFO = 0x02
HAS_NAME = 0x04
HAS_RELATIVE_PATH = 0x08
HAS_WORKING_DIR = 0x10
HAS_ARGUMENTS = 0x20
HAS_ICON_LOCATION = 0x40
IS_UNICODE = 0x80
ENV_BLOCK_SIGNATURE = 0xA0000001
DARWIN_BLOCK_SIGNATURE = 0xA0000006
_ANSI = "mbcs" if os.name == "nt" else "cp1252"


def _cstr(data: bytes, offset: int, wide: bool) -> str:
    if wide:
        end = offset
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode("utf-16-le", errors="replace")
    end = data.find(b"\x00", offset)
    end = len(data) if end == -1 else end
    return data[offset:end].decode(_ANSI, errors="replace")


def parse_lnk(data: bytes) -> dict:
    """Return {'target', 'arguments', 'working_dir', 'icon', 'advertised'} (empty on failure)."""
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        return {}
    flags = struct.unpack_from("<I", data, 0x14)[0]
    pos = 0x4C
    out = {"target": "", "arguments": "", "working_dir": "", "icon": "", "relative": "", "advertised": False}
    try:
        if flags & HAS_ID_LIST:
            size = struct.unpack_from("<H", data, pos)[0]
            pos += 2 + size
        if flags & HAS_LINK_INFO:
            info_size, header_size, info_flags, _vol, base_off, _net, suffix_off = struct.unpack_from("<7I", data, pos)
            base = suffix = ""
            if header_size >= 0x24:
                base_u, suffix_u = struct.unpack_from("<2I", data, pos + 28)
                if info_flags & 1 and base_u:
                    base = _cstr(data, pos + base_u, True)
                if suffix_u:
                    suffix = _cstr(data, pos + suffix_u, True)
            if not base and info_flags & 1 and base_off:
                base = _cstr(data, pos + base_off, False)
            if not suffix and suffix_off:
                suffix = _cstr(data, pos + suffix_off, False)
            if base:
                out["target"] = base + suffix if not suffix or base.endswith("\\") else base + "\\" + suffix
            pos += info_size
        wide = bool(flags & IS_UNICODE)
        for flag, key in ((HAS_NAME, None), (HAS_RELATIVE_PATH, "relative"), (HAS_WORKING_DIR, "working_dir"),
                          (HAS_ARGUMENTS, "arguments"), (HAS_ICON_LOCATION, "icon")):
            if flags & flag:
                count = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                nbytes = count * (2 if wide else 1)
                raw = data[pos:pos + nbytes]
                pos += nbytes
                if key:
                    out[key] = raw.decode("utf-16-le" if wide else _ANSI, errors="replace")
        # Extra data blocks
        while pos + 8 <= len(data):
            size, sig = struct.unpack_from("<2I", data, pos)
            if size < 8:
                break
            if sig == ENV_BLOCK_SIGNATURE and size >= 0x314 and not out["target"]:
                unicode_target = data[pos + 8 + 260:pos + 8 + 260 + 520].decode("utf-16-le", errors="replace")
                out["target"] = expand_env(unicode_target.split("\x00", 1)[0])
            elif sig == DARWIN_BLOCK_SIGNATURE:
                out["advertised"] = True
            pos += size
    except struct.error:
        pass
    out["target"] = expand_env(out["target"])
    out["icon"] = expand_env(out["icon"])
    return out


def read_lnk(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            return parse_lnk(fh.read(1_000_000))
    except OSError:
        return {}


def read_url(path: str) -> dict:
    """Internet shortcut (.url) - INI format; we only care about IconFile/URL file targets."""
    out = {"target": "", "icon": ""}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, _, value = line.strip().partition("=")
                if key.casefold() == "url" and value.casefold().startswith("file:///"):
                    out["target"] = value[8:].replace("/", "\\")
                elif key.casefold() == "iconfile":
                    out["icon"] = value
    except OSError:
        pass
    return out
