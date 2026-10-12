"""Forced uninstall: build a target identity for programs whose uninstaller is broken or
missing, from what the user knows (a list entry, a name, an install folder or an executable)."""
from __future__ import annotations

import os
from dataclasses import dataclass, replace

from . import winapi
from .models import Program, Source
from .safety import SafetyPolicy
from .textutil import is_specific, normalize, strip_decorations


class ForcedInputError(ValueError):
    """Message key describing why the input cannot be used."""


@dataclass
class ForcedRequest:
    name: str = ""
    publisher: str = ""
    folder: str = ""
    executable: str = ""
    entry: Program | None = None


def build_forced_program(req: ForcedRequest, policy: SafetyPolicy) -> Program:
    folder = req.folder.strip().strip('"').rstrip("\\/")
    exe = req.executable.strip().strip('"')
    name = req.name.strip()
    publisher = req.publisher.strip()

    if exe:
        if not os.path.isabs(exe) or not os.path.isfile(exe) or not exe.casefold().endswith(".exe"):
            raise ForcedInputError("forced.err_exe")
        info = winapi.file_version_info(exe)
        name = name or info.get("ProductName") or info.get("FileDescription") or os.path.splitext(os.path.basename(exe))[0]
        publisher = publisher or info.get("CompanyName", "")
        folder = folder or os.path.dirname(exe)

    if folder:
        if not os.path.isabs(folder) or not os.path.isdir(folder):
            raise ForcedInputError("forced.err_folder")
        reason = policy.path_protection(folder)
        if reason:
            raise ForcedInputError("forced.err_folder_protected:" + reason)
        name = name or os.path.basename(folder)

    if req.entry is not None:
        base = req.entry
        program = replace(base, status=list(base.status), flags=list(base.flags))
        if folder and not program.install_location:
            program.install_location = folder
        return program

    if not name:
        raise ForcedInputError("forced.err_need_input")
    if not folder and not is_specific(normalize(strip_decorations(name)), 4):
        raise ForcedInputError("forced.err_generic_name")
    program = Program(name=name, publisher=publisher, install_location=folder, source=Source.FORCED,
                      display_icon=exe)
    from .inventory import classify_flags  # noqa: PLC0415
    program.flags = classify_flags(program)
    return program
