import os

import pytest

from conftest import touch
from danidun.forced import ForcedInputError, ForcedRequest, build_forced_program
from danidun.models import Program, Source
from danidun.safety import SafetyPolicy
from danidun.uninstaller import find_bundled_uninstallers


def test_forced_from_folder(folders):
    folder = os.path.join(folders.program_files, "Broken Tool")
    touch(os.path.join(folder, "unins000.exe"))
    touch(os.path.join(folder, "tool.exe"))
    p = build_forced_program(ForcedRequest(folder=folder), SafetyPolicy(folders))
    assert p.name == "Broken Tool" and p.install_location == folder and p.source == Source.FORCED
    assert find_bundled_uninstallers(folder) == [os.path.join(folder, "unins000.exe")]


def test_forced_from_exe(folders):
    exe = touch(os.path.join(folders.local_appdata, "Programs", "Zapper", "zapper.exe"))
    p = build_forced_program(ForcedRequest(executable=exe), SafetyPolicy(folders))
    assert p.name == "zapper" and p.install_location == os.path.dirname(exe)


def test_forced_rejects_protected_folder(folders):
    with pytest.raises(ForcedInputError, match="forced.err_folder_protected"):
        build_forced_program(ForcedRequest(folder=folders.program_files), SafetyPolicy(folders))


def test_forced_rejects_generic_name(folders):
    with pytest.raises(ForcedInputError, match="forced.err_generic_name"):
        build_forced_program(ForcedRequest(name="Setup"), SafetyPolicy(folders))
    with pytest.raises(ForcedInputError, match="forced.err_need_input"):
        build_forced_program(ForcedRequest(), SafetyPolicy(folders))


def test_forced_from_entry_keeps_registry_identity(folders):
    entry = Program("Ghost App", key_path=r"SOFTWARE\x", hive="HKLM", status=[], flags=["microsoft"])
    p = build_forced_program(ForcedRequest(entry=entry), SafetyPolicy(folders))
    assert p.key_path == entry.key_path and p is not entry and p.flags is not entry.flags
