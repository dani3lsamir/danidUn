"""Microsoft Store / MSIX packages through the built-in Appx PowerShell module.

Only fixed command strings are executed; package names are validated before they
are ever placed in a command.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET

from .models import Program, Source

log = logging.getLogger(__name__)

PACKAGE_RE = re.compile(r"^[A-Za-z0-9.\-]{1,100}_[A-Za-z0-9.\-]{1,30}_[A-Za-z0-9]{0,10}_[A-Za-z0-9.\-~]{0,60}_[a-z0-9]{13}$")
FAMILY_RE = re.compile(r"^[A-Za-z0-9.\-]{1,100}_[a-z0-9]{13}$")

_LIST_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    "Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and "
    "$_.SignatureKind -ne 'System' -and -not $_.IsResourcePackage } | "
    "Select-Object Name,PackageFullName,PackageFamilyName,Publisher,Version,InstallLocation | "
    "ConvertTo-Json -Compress"
)


def powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _manifest_strings(install_location: str) -> tuple[str, str]:
    """DisplayName and PublisherDisplayName when they are literal (not ms-resource)."""
    path = os.path.join(install_location or "", "AppxManifest.xml")
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return "", ""
    display = publisher = ""
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "DisplayName" and not display and el.text and not el.text.startswith("ms-resource:"):
            display = el.text.strip()
        elif tag == "PublisherDisplayName" and not publisher and el.text and not el.text.startswith("ms-resource:"):
            publisher = el.text.strip()
    return display, publisher


def _pretty(name: str) -> str:
    tail = name.split(".", 1)[-1] if "." in name else name
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", tail)


def parse_packages(text: str, read_manifest=_manifest_strings) -> list[Program]:
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    out = []
    for item in data:
        full = str(item.get("PackageFullName") or "")
        family = str(item.get("PackageFamilyName") or "")
        if not PACKAGE_RE.match(full):
            continue
        location = str(item.get("InstallLocation") or "")
        display, publisher = read_manifest(location)
        version = item.get("Version")
        if isinstance(version, dict):  # older PowerShell serialises System.Version as an object
            version = ".".join(str(version.get(k, 0)) for k in ("Major", "Minor", "Build", "Revision"))
        pub = publisher or re.sub(r"^CN=([^,]+).*$", r"\1", str(item.get("Publisher") or ""))
        out.append(Program(
            name=display or _pretty(str(item.get("Name") or full)),
            version=str(version or ""),
            publisher=pub,
            install_location=location,
            source=Source.STORE,
            scope="user",
            package_full_name=full,
            package_family_name=family if FAMILY_RE.match(family) else "",
        ))
    return out


def list_store_apps(timeout: int = 90) -> list[Program]:
    if os.name != "nt":
        return []
    result = subprocess.run(
        [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _LIST_SCRIPT],
        capture_output=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    text = result.stdout.decode("utf-8", errors="replace")
    try:
        return parse_packages(text)
    except json.JSONDecodeError:
        log.warning("Could not parse Get-AppxPackage output")
        return []


def removal_command(package_full_name: str) -> list[str]:
    if not PACKAGE_RE.match(package_full_name):
        raise ValueError("Invalid package name")
    script = f"Remove-AppxPackage -Package '{package_full_name}' -ErrorAction Stop"
    return [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]


def package_installed(package_full_name: str) -> bool:
    if os.name != "nt" or not PACKAGE_RE.match(package_full_name):
        return False
    script = f"if (Get-AppxPackage | Where-Object PackageFullName -eq '{package_full_name}') {{ 'yes' }}"
    result = subprocess.run([powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=60,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return "yes" in result.stdout
