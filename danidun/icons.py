"""Extract small program icons as PNG bytes (no third-party imaging library needed)."""
from __future__ import annotations

import ctypes
import os
import struct
import zlib

from .paths import path_from_icon
from .winapi import IS_WINDOWS

if IS_WINDOWS:
    from ctypes import wintypes

    _shell32 = ctypes.WinDLL("shell32")
    _user32 = ctypes.WinDLL("user32")
    _gdi32 = ctypes.WinDLL("gdi32")

    class ICONINFO(ctypes.Structure):
        _fields_ = [("fIcon", wintypes.BOOL), ("xHotspot", wintypes.DWORD), ("yHotspot", wintypes.DWORD),
                    ("hbmMask", wintypes.HBITMAP), ("hbmColor", wintypes.HBITMAP)]

    class BITMAP(ctypes.Structure):
        _fields_ = [("bmType", wintypes.LONG), ("bmWidth", wintypes.LONG), ("bmHeight", wintypes.LONG),
                    ("bmWidthBytes", wintypes.LONG), ("bmPlanes", wintypes.WORD), ("bmBitsPixel", wintypes.WORD),
                    ("bmBits", ctypes.c_void_p)]

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]

    _shell32.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.HICON),
                                        ctypes.POINTER(wintypes.HICON), wintypes.UINT]
    _shell32.ExtractIconExW.restype = wintypes.UINT
    _user32.GetIconInfo.argtypes = [wintypes.HICON, ctypes.POINTER(ICONINFO)]
    _user32.DestroyIcon.argtypes = [wintypes.HICON]
    _user32.GetDC.argtypes = [wintypes.HWND]
    _user32.GetDC.restype = wintypes.HDC
    _user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _gdi32.GetObjectW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p]
    _gdi32.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT, ctypes.c_void_p,
                                 ctypes.POINTER(BITMAPINFOHEADER), wintypes.UINT]
    _gdi32.DeleteObject.argtypes = [wintypes.HANDLE]


def png_bytes(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    stride = width * 4
    raw = b"".join(b"\x00" + rgba[y * stride:(y + 1) * stride] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _bits(hdc, hbitmap, width: int, height: int) -> bytes | None:
    header = BITMAPINFOHEADER()
    header.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    header.biWidth = width
    header.biHeight = -height  # top-down
    header.biPlanes = 1
    header.biBitCount = 32
    buf = ctypes.create_string_buffer(width * height * 4)
    if not _gdi32.GetDIBits(hdc, hbitmap, 0, height, buf, ctypes.byref(header), 0):
        return None
    return buf.raw


def icon_png(source: str) -> bytes | None:
    """PNG bytes for the small icon referenced by a DisplayIcon-style string."""
    if not IS_WINDOWS or not source:
        return None
    path = path_from_icon(source)
    index = 0
    tail = source.rsplit(",", 1)
    if len(tail) == 2 and tail[1].strip().lstrip("-").isdigit():
        index = int(tail[1])
    if not os.path.isfile(path):
        return None
    small = wintypes.HICON()
    if _shell32.ExtractIconExW(path, index, None, ctypes.byref(small), 1) == 0 or not small:
        return None
    info = ICONINFO()
    hdc = None
    try:
        if not _user32.GetIconInfo(small, ctypes.byref(info)):
            return None
        bm = BITMAP()
        target = info.hbmColor or info.hbmMask
        if not _gdi32.GetObjectW(target, ctypes.sizeof(bm), ctypes.byref(bm)):
            return None
        width, height = bm.bmWidth, bm.bmHeight if info.hbmColor else bm.bmHeight // 2
        if not (0 < width <= 256 and 0 < height <= 256) or not info.hbmColor:
            return None
        hdc = _user32.GetDC(None)
        color = _bits(hdc, info.hbmColor, width, height)
        if color is None:
            return None
        pixels = bytearray(color)
        has_alpha = any(pixels[i] for i in range(3, len(pixels), 4))
        mask = None if has_alpha else _bits(hdc, info.hbmMask, width, height)
        for i in range(0, len(pixels), 4):
            b, r = pixels[i], pixels[i + 2]
            pixels[i], pixels[i + 2] = r, b
            if not has_alpha:
                pixels[i + 3] = 0 if (mask and mask[i]) else 255
        return png_bytes(width, height, bytes(pixels))
    except OSError:
        return None
    finally:
        if hdc:
            _user32.ReleaseDC(None, hdc)
        for h in (info.hbmColor, info.hbmMask):
            if h:
                _gdi32.DeleteObject(h)
        _user32.DestroyIcon(small)
