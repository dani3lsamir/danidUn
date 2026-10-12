import os

import pytest

from conftest import touch
from danidun import appx
from danidun.inventory import UNINSTALL_KEY, read_programs
from danidun.models import Program, Source, Status
from danidun.registry import HKCU, HKLM, VIEW_32, join
from danidun.uninstaller import UnsupportedCommand, build_plan, interpret

GUID = "{11111111-2222-3333-4444-555555555555}"


def _entry(reg, hive, sub, view=64, **values):
    reg.add_key(hive, join(UNINSTALL_KEY, sub), values, view=view)


def test_read_programs_all_sources(reg, tmp_path):
    exe = touch(str(tmp_path / "App" / "uninst.exe"))
    _entry(reg, HKLM, "App", DisplayName="Example App 1.2", Publisher="Example Ltd",
           UninstallString=f'"{exe}" /S', InstallLocation=str(tmp_path / "App"), InstallDate="20240131")
    _entry(reg, HKLM, GUID, view=VIEW_32, DisplayName="Old MSI Tool", WindowsInstaller=1,
           UninstallString=f"MsiExec.exe /I{GUID}")
    _entry(reg, HKCU, "UserApp", DisplayName="User App", UninstallString=r"C:\gone\u.exe")
    _entry(reg, HKLM, "Hidden", DisplayName="Hidden", SystemComponent=1, UninstallString="x")
    _entry(reg, HKLM, "KB123", DisplayName="Update for X", ParentKeyName="X", UninstallString="x")
    _entry(reg, HKLM, "NoName", UninstallString="x")

    progs = {p.name: p for p in read_programs(reg, windows_dir=str(tmp_path / "Windows"))}
    assert set(progs) == {"Example App 1.2", "Old MSI Tool", "User App"}

    app = progs["Example App 1.2"]
    assert app.install_date == "2024-01-31" and app.source == Source.WIN32 and not app.status
    assert app.architecture == "64-bit"

    msi = progs["Old MSI Tool"]
    assert msi.source == Source.MSI and msi.product_code == GUID and msi.view == VIEW_32
    assert Status.MSI_UNREGISTERED in msi.status and msi.is_broken

    user = progs["User App"]
    assert user.scope == "user" and Status.UNINSTALLER_MISSING in user.status


def test_inferred_location_from_icon(reg, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path / "SomeTemp"))
    monkeypatch.setenv("TMP", str(tmp_path / "SomeTemp"))
    exe = touch(str(tmp_path / "Tool" / "tool.exe"))
    _entry(reg, HKLM, "Tool", DisplayName="Tool Thing", DisplayIcon=f"{exe},0", UninstallString=f'"{exe}" --remove')
    p = read_programs(reg, windows_dir=str(tmp_path / "Windows"))[0]
    assert p.install_location == str(tmp_path / "Tool") and p.location_inferred


def test_security_and_runtime_flags(reg):
    _entry(reg, HKLM, "AV", DisplayName="Avast Free Antivirus", Publisher="Avast Software", UninstallString="x")
    _entry(reg, HKLM, "VC", DisplayName="Microsoft Visual C++ 2015-2022 Redistributable (x64)",
           Publisher="Microsoft Corporation", UninstallString="x")
    progs = {p.name: p for p in read_programs(reg)}
    assert "security_software" in progs["Avast Free Antivirus"].flags
    vc = progs["Microsoft Visual C++ 2015-2022 Redistributable (x64)"]
    assert "shared_runtime" in vc.flags and "microsoft" in vc.flags


def test_plan_msi_is_rebuilt_from_product_code():
    p = Program("X", uninstall_string=f"MsiExec.exe /I{GUID} && calc.exe", product_code=GUID, source=Source.MSI)
    plan = build_plan(p)
    assert plan.kind == "msi" and plan.executable.lower().endswith("msiexec.exe")
    assert plan.arguments == f"/x {GUID}"
    assert "calc" not in plan.command_line
    assert build_plan(p, quiet=True).arguments.endswith("/passive /norestart")


def test_plan_exe_keeps_raw_arguments(tmp_path):
    exe = touch(str(tmp_path / "My App" / "uninst.exe"))
    p = Program("X", uninstall_string=f"{exe} /S _?={tmp_path / 'My App'}")
    plan = build_plan(p)
    assert plan.executable == exe and plan.arguments == f"/S _?={tmp_path / 'My App'}"
    assert plan.command_line.startswith('"')


@pytest.mark.parametrize("cmd, key", [
    (r"cmd.exe /c del C:\x", "err.disallowed_interpreter"),
    (r"C:\Windows\System32\rundll32.exe setupapi,InstallHinfSection", "err.disallowed_interpreter"),
    (r"powershell -c evil", "err.disallowed_interpreter"),
    (r"C:\x\script.bat", "err.not_exe"),
    ("", "err.no_command"),
])
def test_plan_rejects_unsafe(cmd, key):
    with pytest.raises(UnsupportedCommand) as err:
        build_plan(Program("X", uninstall_string=cmd), exists=lambda p: " " not in p)
    assert str(err.value) == key


def test_plan_missing_uninstaller():
    with pytest.raises(UnsupportedCommand, match="err.uninstaller_missing"):
        build_plan(Program("X", uninstall_string=r"C:\gone\unins000.exe"), exists=lambda _p: False)


def test_interpret_codes():
    assert interpret("msi", 0) == "success"
    assert interpret("msi", 3010) == "reboot"
    assert interpret("msi", 1602) == "cancelled"
    assert interpret("msi", 1605) == "not_installed"
    assert interpret("exe", 2) == "failed"


def test_appx_parse_and_validate():
    text = ('[{"Name":"Contoso.Notes","PackageFullName":"Contoso.Notes_1.2.3.0_x64__abcdefghijklm",'
            '"PackageFamilyName":"Contoso.Notes_abcdefghijklm","Publisher":"CN=Contoso, O=Contoso",'
            '"Version":"1.2.3.0","InstallLocation":"C:\\\\nowhere"},'
            '{"Name":"Bad","PackageFullName":"Bad\'; rm -rf"}]')
    apps = appx.parse_packages(text, read_manifest=lambda _l: ("", ""))
    assert len(apps) == 1
    a = apps[0]
    assert a.name == "Notes" and a.publisher == "Contoso" and a.source == Source.STORE
    assert a.package_family_name == "Contoso.Notes_abcdefghijklm"
    assert "Remove-AppxPackage -Package 'Contoso.Notes_1.2.3.0_x64__abcdefghijklm'" in appx.removal_command(a.package_full_name)[-1]
    with pytest.raises(ValueError):
        appx.removal_command("x'; Remove-Item C:\\ -Recurse; '")


def test_appx_single_object_json():
    text = ('{"Name":"A.B","PackageFullName":"A.B_1.0.0.0_neutral__abcdefghijklm","PackageFamilyName":"A.B_abcdefghijklm",'
            '"Publisher":"CN=A","Version":{"Major":1,"Minor":0,"Build":0,"Revision":0},"InstallLocation":""}')
    apps = appx.parse_packages(text, read_manifest=lambda _l: ("Nice Name", "Pub"))
    assert apps[0].name == "Nice Name" and apps[0].version == "1.0.0.0"


def test_no_remove_rejected():
    with pytest.raises(UnsupportedCommand, match="err.no_remove"):
        build_plan(Program("X", uninstall_string="x.exe", no_remove=True))


def test_env_in_uninstall_string(tmp_path, monkeypatch):
    exe = touch(str(tmp_path / "PF" / "App" / "u.exe"))
    monkeypatch.setenv("MYPF", str(tmp_path / "PF"))
    plan = build_plan(Program("X", uninstall_string="%MYPF%" + os.sep + "App" + os.sep + "u.exe /S"))
    assert plan.executable == exe


def test_location_in_temp_is_not_inferred(reg, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setenv("TMP", str(tmp_path))
    exe = touch(str(tmp_path / "Temperature Tool" / "au_.exe"))
    _entry(reg, HKLM, "T", DisplayName="Thing", UninstallString=f'"{exe}"')
    assert read_programs(reg, windows_dir=str(tmp_path / "Windows"))[0].install_location == ""
