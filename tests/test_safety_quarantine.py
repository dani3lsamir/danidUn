import json
import os

import pytest

from conftest import touch
from danidun.models import Category, Kind, Leftover, Program
from danidun.quarantine import Quarantine, Session
from danidun.registry import HKCU, HKLM
from danidun.reports import OperationReport
from danidun.safety import SafetyPolicy
from fakes import FakeSysOps


@pytest.fixture
def policy(folders):
    return SafetyPolicy(folders, [Program("Other", install_location=os.path.join(folders.program_files, "Other"))])


def test_path_protection(policy, folders):
    f = folders
    assert policy.path_protection(f.program_files) == "protect.system_folder"
    assert policy.path_protection(os.path.dirname(f.program_files)) == "protect.system_folder"
    assert policy.path_protection(f.appdata) == "protect.system_folder"
    assert policy.path_protection(os.path.join(f.windows, "System32", "x")) == "protect.windows"
    assert policy.path_protection(os.path.join(f.program_files, "Common Files")) == "protect.system_folder"
    assert policy.path_protection(os.path.join(f.program_files, "Microsoft.NET")) == "protect.shared_location"
    assert policy.path_protection(os.path.join(f.common_files, "Microsoft Shared")) == "protect.shared_location"
    assert policy.path_protection(os.path.join(f.common_files, "Acme")) == ""
    assert policy.path_protection(os.path.join(f.appdata, "Microsoft", "Teams")) == "protect.shared_location"
    assert policy.path_protection(os.path.join(f.local_appdata, "Packages", "X_abc")) == "protect.shared_location"
    assert policy.path_protection(os.path.join(f.program_files, "Other", "sub")).startswith("protect.other_app")
    assert policy.path_protection(os.path.join(f.program_files, "Mozilla")) == "protect.shared_location"
    assert policy.path_protection(os.path.join(f.program_files, "Acme")) == ""
    assert policy.path_protection(os.path.join(f.start_menu_user, "Programs", "Acme")) == ""
    assert policy.path_protection("relative\\path") == "protect.not_absolute"


def test_symlink_is_protected(policy, folders, tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = os.path.join(folders.appdata, "LinkedApp")
    os.symlink(target, link)
    assert policy.path_protection(link) == "protect.reparse_point"


@pytest.mark.parametrize("hive, path, ok", [
    (HKCU, r"SOFTWARE\Acme\Photo", True),
    (HKLM, r"SOFTWARE\Acme", True),
    (HKLM, r"SOFTWARE", False),
    (HKLM, r"SOFTWARE\Microsoft", False),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Acme", True),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\acme.exe", True),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", False),
    (HKLM, r"SOFTWARE\Classes\CLSID\{0000}", False),
    (HKLM, r"SOFTWARE\Classes\.txt", False),
    (HKLM, r"SOFTWARE\Classes\AcmeFile.Document", True),
    (HKLM, r"SOFTWARE\Classes\Installer\Products\00112233445566778899AABBCCDDEEFF", True),
    (HKLM, r"SOFTWARE\Policies\Acme", False),
    (HKLM, r"SOFTWARE\Google", False),
    (HKLM, r"SOFTWARE\Google\Chrome", True),
    (HKLM, r"SOFTWARE\NVIDIA Corporation\Global", False),
    (HKLM, r"SYSTEM\CurrentControlSet\Services\Acme", False),
    (HKLM, r"SYSTEM\CurrentControlSet\Control", False),
])
def test_registry_key_protection(policy, hive, path, ok):
    assert (policy.registry_key_protection(hive, path) == "") is ok


def test_registry_value_protection(policy):
    assert policy.registry_value_protection(HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Acme") == ""
    assert policy.registry_value_protection(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs", "x")
    assert policy.registry_value_protection(HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager", "x")


def test_service_protection(policy, folders):
    assert policy.service_protection("acme", r"C:\Acme\acme.sys", 1) == "protect.driver"
    assert policy.service_protection("WinDefend", r"C:\x.exe", 16) == "protect.critical_service"
    assert policy.service_protection("x", r"%SystemRoot%\System32\svchost.exe -k netsvcs", 32) == "protect.windows"
    assert policy.service_protection("x", os.path.join(folders.program_files, "Acme", "a.exe"), 16) == ""


def test_quarantine_roundtrip(folders, reg, policy, tmp_path):
    folder = os.path.join(folders.appdata, "AcmeData")
    touch(os.path.join(folder, "a.txt"), b"hello")
    touch(os.path.join(folder, "sub", "b.txt"), b"world")
    shortcut = touch(os.path.join(folders.desktop_user, "Acme.lnk"), b"lnk")
    reg.add_key(HKCU, r"SOFTWARE\Acme\Studio", {"Theme": "dark"})
    reg.add_key(HKCU, r"SOFTWARE\Acme\Studio\Sub", {"N": 3})
    reg.add_key(HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", {"AcmeTray": "C:\\a.exe", "Keep": "y"})
    reg.add_key(HKLM, r"SYSTEM\CurrentControlSet\Services\AcmeSvc", {"ImagePath": "C:\\a.exe", "Type": 16})
    sysops = FakeSysOps()

    items = [
        Leftover(Kind.FOLDER, folder, Category.FILES),
        Leftover(Kind.FILE, shortcut, Category.SHORTCUTS),
        Leftover(Kind.REG_KEY, r"SOFTWARE\Acme\Studio", Category.REGISTRY, hive=HKCU, view=64),
        Leftover(Kind.REG_VALUE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Category.STARTUP,
                 hive=HKCU, view=64, value_name="AcmeTray"),
        Leftover(Kind.SERVICE, "AcmeSvc", Category.SERVICES),
        Leftover(Kind.TASK, "\\Acme Update", Category.TASKS),
        Leftover(Kind.FOLDER, folders.program_files, Category.FILES),  # must be refused
    ]
    q = Quarantine(reg, sysops, base=tmp_path / "dn")
    session = q.remove("Acme Studio", items, policy)
    status = {r.leftover.target: r.status for r in session.items}
    assert status[folders.program_files] == "skipped"
    assert all(s == "removed" for t, s in status.items() if t != folders.program_files), status
    assert os.path.isdir(folders.program_files)
    assert not os.path.exists(folder) and not os.path.exists(shortcut)
    assert not reg.key_exists(HKCU, r"SOFTWARE\Acme\Studio")
    assert "acmetray" not in reg.values(HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    assert ("delete_service", "AcmeSvc") in sysops.calls and ("delete_task", "\\Acme Update") in sysops.calls

    loaded = q.sessions()[0]
    assert loaded.application == "Acme Studio" and loaded.removed == 6
    restored, errors = q.restore(loaded, policy)
    assert errors == [] and restored == 6
    assert open(os.path.join(folder, "sub", "b.txt"), "rb").read() == b"world"
    assert os.path.exists(shortcut)
    assert reg.values(HKCU, r"SOFTWARE\Acme\Studio\Sub")["n"].data == 3
    assert reg.values(HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")["acmetray"].data == "C:\\a.exe"
    assert ("create_task", "\\Acme Update") in sysops.calls
    # Restoring twice is a no-op.
    assert q.restore(Session.load(loaded.path), policy) == (0, [])


def test_restore_refuses_tampered_manifest(folders, reg, policy, tmp_path):
    reg.add_key(HKCU, r"SOFTWARE\Acme\Studio", {"Theme": "dark"})
    q = Quarantine(reg, FakeSysOps(), base=tmp_path / "dn")
    session = q.remove("Acme", [Leftover(Kind.REG_KEY, r"SOFTWARE\Acme\Studio", Category.REGISTRY, hive=HKCU, view=64)], policy)
    manifest = session.path / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["items"][0]["leftover"]["target"] = r"SOFTWARE\Acme\Other"  # .reg contents no longer match
    data["items"].append({**data["items"][0], "backup": "../../../../outside.reg",
                          "leftover": {**data["items"][0]["leftover"], "target": r"SOFTWARE\Acme\Studio"}})
    manifest.write_text(json.dumps(data), encoding="utf-8")
    restored, errors = q.restore(Session.load(session.path), policy)
    assert restored == 0 and len(errors) == 2


def test_restore_does_not_overwrite(folders, reg, policy, tmp_path):
    folder = os.path.join(folders.appdata, "AcmeData")
    touch(os.path.join(folder, "a.txt"))
    q = Quarantine(reg, FakeSysOps(), base=tmp_path / "dn")
    session = q.remove("Acme", [Leftover(Kind.FOLDER, folder, Category.FILES)], policy)
    touch(os.path.join(folder, "new.txt"))
    restored, errors = q.restore(session, policy)
    assert restored == 0 and "target_exists" in errors[0]


def test_purge_only_inside_quarantine(folders, reg, policy, tmp_path):
    q = Quarantine(reg, FakeSysOps(), base=tmp_path / "dn")
    session = q.remove("Acme", [], policy)
    q.purge(session)
    assert not session.path.exists()
    with pytest.raises(RuntimeError):
        q.purge(Session(tmp_path, "x", ""))


def test_report_written(tmp_path):
    rep = OperationReport("uninstall", Program("Acme <script>", publisher="Acme"))
    rep.notes.append("note & <b>")
    json_path, html_path = rep.save(tmp_path)
    assert json.loads(json_path.read_text(encoding="utf-8"))["program"]["name"] == "Acme <script>"
    html = html_path.read_text(encoding="utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_service_revalidated_at_removal(folders, reg, policy, tmp_path):
    # The scan saw a normal service, but by removal time it has become a kernel driver.
    reg.add_key(HKLM, r"SYSTEM\CurrentControlSet\Services\AcmeSvc", {"ImagePath": "C:\\a.sys", "Type": 1})
    sysops = FakeSysOps()
    q = Quarantine(reg, sysops, base=tmp_path / "dn")
    session = q.remove("Acme", [Leftover(Kind.SERVICE, "AcmeSvc", Category.SERVICES)], policy)
    assert session.items[0].status == "skipped" and session.items[0].error == "protect.driver"
    assert sysops.calls == []
