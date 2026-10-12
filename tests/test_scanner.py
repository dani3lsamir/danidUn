import os
import struct

import pytest

from conftest import touch
from danidun.lnk import parse_lnk
from danidun.models import Category, Confidence, Kind, Program
from danidun.registry import HKCU, HKLM, VIEW_32
from danidun.safety import SafetyPolicy
from danidun.scanner import AppIdentity, ScanContext, ScanMode, run_scan

APP = "Acme Photo Studio 2.1"
PUB = "Acme Software Inc."
UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AcmePS"


def make_lnk(target: str) -> bytes:
    header = struct.pack("<I16sI", 0x4C, b"\x01\x14\x02\x00" + b"\x00" * 4 + b"\xc0" + b"\x00" * 6 + b"\x46", 0x02)
    header += b"\x00" * (0x4C - len(header))
    volume = struct.pack("<IIII", 0x11, 3, 0, 0x10) + b"\x00"
    base = target.encode("cp1252") + b"\x00"
    suffix = b"\x00"
    body_off = 0x1C
    base_off = body_off + len(volume)
    suffix_off = base_off + len(base)
    size = suffix_off + len(suffix)
    info = struct.pack("<7I", size, 0x1C, 1, body_off, base_off, 0, suffix_off) + volume + base + suffix
    return header + info


@pytest.fixture
def scenario(folders, reg):
    f = folders
    install = os.path.join(f.program_files, "Acme Photo Studio")
    touch(os.path.join(install, "acmephoto.exe"))
    touch(os.path.join(install, "acmetray.exe"))
    touch(os.path.join(install, "unins000.exe"))
    touch(os.path.join(f.appdata, "Acme", "Acme Photo Studio", "settings.ini"))
    touch(os.path.join(f.local_appdata, "AcmePhotoStudio", "cache.bin"))
    touch(os.path.join(f.local_appdata, "Photo Studio", "x.dat"))
    touch(os.path.join(f.program_data, "Acme Photo Studio Cache", "c.bin"))
    touch(os.path.join(f.common_files, "Acme Photo Studio", "codec.dll"))
    touch(os.path.join(f.documents, "Acme Photo Studio", "my-photo.aps"))
    touch(os.path.join(f.appdata, "Studio", "unrelated.txt"))
    touch(os.path.join(f.appdata, "Acme Photo Studio Fan Club", "notes.txt"))
    os.makedirs(os.path.join(f.program_files, "Other Tool"))

    reg.add_key(HKLM, UNINSTALL, {"DisplayName": APP, "Publisher": PUB, "InstallLocation": install,
                                  "UninstallString": os.path.join(install, "unins000.exe")})
    reg.add_key(HKCU, r"SOFTWARE\Acme\Acme Photo Studio", {"Theme": "dark"})
    reg.add_key(HKLM, r"SOFTWARE\Acme Photo Studio", {"Path": install}, view=VIEW_32)
    reg.add_key(HKLM, r"SOFTWARE\Unrelated Vendor\Something", {"LastFile": os.path.join(install, "x.aps")})
    reg.add_key(HKLM, r"SOFTWARE\Microsoft\Office", {"x": 1})
    reg.add_key(HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                {"AcmePhotoTray": f'"{os.path.join(install, "acmetray.exe")}" /min',
                 "OtherTool": os.path.join(f.program_files, "Other Tool", "o.exe")})
    reg.add_key(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\acmephoto.exe",
                {"": os.path.join(install, "acmephoto.exe")})
    reg.add_key(HKLM, r"SYSTEM\CurrentControlSet\Services\AcmeUpdater",
                {"ImagePath": f'"{os.path.join(install, "acmeupd.exe")}"', "Type": 16, "DisplayName": "Acme Updater"})
    reg.add_key(HKLM, r"SYSTEM\CurrentControlSet\Services\acmeflt",
                {"ImagePath": os.path.join(install, "acmeflt.sys"), "Type": 1})
    reg.add_key(HKLM, r"SYSTEM\CurrentControlSet\Services\Spooler",
                {"ImagePath": os.path.join(f.windows, "System32", "spoolsv.exe"), "Type": 16})

    task_xml = ('<?xml version="1.0" encoding="UTF-8"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                f'<RegistrationInfo><Author>Acme Software Inc.</Author></RegistrationInfo><Actions><Exec><Command>'
                f'{os.path.join(install, "acmeupd.exe")}</Command><Arguments>/check</Arguments></Exec></Actions></Task>')
    touch(os.path.join(f.tasks_dir, "Acme Photo Studio Update"), task_xml.encode())
    touch(os.path.join(f.tasks_dir, "Microsoft", "Windows", "Defrag"), b"<Task/>")

    programs_menu = os.path.join(f.start_menu_common, "Programs", "Acme Photo Studio")
    touch(os.path.join(programs_menu, "Acme Photo Studio.lnk"), make_lnk(os.path.join(install, "acmephoto.exe")))
    touch(os.path.join(f.desktop_user, "Acme Photo Studio.lnk"), make_lnk(os.path.join(install, "acmephoto.exe")))
    touch(os.path.join(f.desktop_user, "Holiday.lnk"), make_lnk(os.path.join(f.documents, "holiday.jpg")))

    program = Program(APP, publisher=PUB, install_location=install, hive=HKLM, view=64, key_path=UNINSTALL)
    other = [Program("Other Tool", install_location=os.path.join(f.program_files, "Other Tool"))]
    identity = AppIdentity.build(program, other)
    policy = SafetyPolicy(f, other)
    ctx = ScanContext(reg, f, policy, other)
    return identity, ctx, install


def by_target(result):
    return {lo.display: lo for lo in result.leftovers}


def test_identity(scenario):
    identity, _ctx, install = scenario
    assert identity.primary == "acmephotostudio"
    assert "photostudio" in identity.names
    assert identity.exe_names == {"acmephoto.exe", "acmetray.exe"}  # unins000.exe is excluded
    assert identity.install_dirs == [install]
    assert "acme" in identity.publishers


def test_full_scan_moderate(scenario, folders):
    identity, ctx, install = scenario
    f = folders
    result = run_scan(identity, ctx, ScanMode.MODERATE)
    items = by_target(result)

    assert items[install].confidence == Confidence.HIGH
    assert items[os.path.join(f.appdata, "Acme", "Acme Photo Studio")].confidence == Confidence.HIGH
    assert items[os.path.join(f.local_appdata, "AcmePhotoStudio")].confidence == Confidence.HIGH
    assert items[os.path.join(f.local_appdata, "Photo Studio")].confidence == Confidence.MEDIUM
    common = items[os.path.join(f.common_files, "Acme Photo Studio")]
    assert common.confidence == Confidence.MEDIUM and not common.protected
    # The empty-but-for-the-app publisher folder is a review item, not auto-selected.
    assert items[os.path.join(f.appdata, "Acme")].confidence == Confidence.MEDIUM

    # Partial name matches and user documents never show in moderate mode.
    assert os.path.join(f.program_data, "Acme Photo Studio Cache") not in items
    assert os.path.join(f.documents, "Acme Photo Studio") not in items
    assert os.path.join(f.appdata, "Studio") not in items
    assert result.hidden_below_threshold >= 1

    assert items[r"HKCU\SOFTWARE\Acme\Acme Photo Studio"].confidence == Confidence.HIGH
    assert items[r"HKLM\SOFTWARE\Acme Photo Studio [32-bit]"].confidence == Confidence.HIGH
    assert items["HKLM\\" + UNINSTALL].confidence == Confidence.HIGH
    app_paths = items[r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\acmephoto.exe"]
    assert app_paths.confidence == Confidence.HIGH and not app_paths.protected
    assert not any("Microsoft\\Office" in k for k in items)

    run = [lo for lo in result.leftovers if lo.kind == Kind.REG_VALUE and lo.value_name == "AcmePhotoTray"]
    assert run and run[0].category == Category.STARTUP and run[0].confidence == Confidence.HIGH
    assert not [lo for lo in result.leftovers if lo.value_name == "OtherTool"]

    svc = items["AcmeUpdater"]
    assert svc.kind == Kind.SERVICE and svc.confidence == Confidence.HIGH and not svc.protected
    assert items["acmeflt"].protected == "protect.driver"
    assert "Spooler" not in items

    task = items["\\Acme Photo Studio Update"]
    assert task.confidence == Confidence.HIGH and not task.protected
    assert not any(k.startswith("\\Microsoft") for k in items)

    desktop = items[os.path.join(f.desktop_user, "Acme Photo Studio.lnk")]
    assert desktop.confidence == Confidence.HIGH
    assert os.path.join(f.desktop_user, "Holiday.lnk") not in items
    menu_folder = items[os.path.join(f.start_menu_common, "Programs", "Acme Photo Studio")]
    assert menu_folder.confidence == Confidence.HIGH
    # The shortcut inside the start-menu folder is covered by the folder itself.
    assert os.path.join(menu_folder.target, "Acme Photo Studio.lnk") not in items


def test_safe_mode_only_high(scenario):
    identity, ctx, _ = scenario
    result = run_scan(identity, ctx, ScanMode.SAFE)
    assert result.leftovers
    assert all(lo.confidence == Confidence.HIGH for lo in result.leftovers)


def test_advanced_mode_adds_low_and_user_data(scenario, folders):
    identity, ctx, install = scenario
    f = folders
    items = by_target(run_scan(identity, ctx, ScanMode.ADVANCED))
    partial = items[os.path.join(f.program_data, "Acme Photo Studio Cache")]
    assert partial.confidence == Confidence.LOW
    fan = items[os.path.join(f.appdata, "Acme Photo Studio Fan Club")]
    assert fan.confidence == Confidence.LOW
    docs = items[os.path.join(f.documents, "Acme Photo Studio")]
    assert docs.confidence == Confidence.MEDIUM  # never auto-selected
    foreign = [lo for lo in items.values() if lo.kind == Kind.REG_VALUE and "Unrelated Vendor" in lo.target]
    assert foreign and foreign[0].confidence == Confidence.MEDIUM


def test_other_app_folder_is_protected(scenario, folders, reg):
    identity, ctx, _ = scenario
    shared = os.path.join(folders.appdata, "Acme", "Shared Engine")
    os.makedirs(shared)
    other = ctx.other_programs + [Program("Acme Engine", install_location=shared)]
    ctx.policy = SafetyPolicy(folders, other)
    items = by_target(run_scan(identity, ctx, ScanMode.ADVANCED))
    pub = items.get(os.path.join(folders.appdata, "Acme"))
    # The publisher folder now contains another program's files: not even proposed.
    assert pub is None or pub.protected.startswith("protect.other_app")


def test_partial_match_alone_is_never_more_than_low(folders, reg):
    os.makedirs(os.path.join(folders.appdata, "SuperWidgetHelperData"))
    program = Program("SuperWidget", publisher="")
    identity = AppIdentity.build(program)
    ctx = ScanContext(reg, folders, SafetyPolicy(folders))
    result = run_scan(identity, ctx, ScanMode.ADVANCED)
    lo = by_target(result)[os.path.join(folders.appdata, "SuperWidgetHelperData")]
    assert lo.confidence == Confidence.LOW


def test_generic_name_finds_nothing_by_name(folders, reg):
    os.makedirs(os.path.join(folders.appdata, "Update"))
    identity = AppIdentity.build(Program("Update"))
    ctx = ScanContext(reg, folders, SafetyPolicy(folders))
    assert run_scan(identity, ctx, ScanMode.ADVANCED).leftovers == []


def test_lnk_parser_roundtrip(tmp_path):
    info = parse_lnk(make_lnk(r"C:\Program Files\Acme\acme.exe"))
    assert info["target"] == r"C:\Program Files\Acme\acme.exe"
    assert parse_lnk(b"garbage") == {}



def test_unrelated_install_folder_needs_review(folders, reg):
    games = os.path.join(folders.user_profile, "Games")
    touch(os.path.join(games, "tetrisx.exe"))
    touch(os.path.join(games, "Other Game", "other.exe"))
    program = Program("Tetris Deluxe", install_location=games)
    ctx = ScanContext(reg, folders, SafetyPolicy(folders))
    lo = by_target(run_scan(AppIdentity.build(program), ctx, ScanMode.MODERATE))[games]
    assert lo.confidence == Confidence.MEDIUM and "unrelated_folder_name" in {e.signal for e in lo.evidence}
