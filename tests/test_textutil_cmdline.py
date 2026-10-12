import pytest

from danidun.cmdline import expand_env, parse_command, quote_arg, split_args
from danidun.textutil import is_specific, name_variants, normalize, pack_guid, publisher_variants, strip_decorations


@pytest.mark.parametrize("raw, expected", [
    ("Mozilla Firefox (x64 en-US)", "Mozilla Firefox"),
    ("7-Zip 23.01 (x64)", "7-Zip"),
    ("Audacity 3.4.2", "Audacity"),
    ("VLC media player", "VLC media player"),
    ("Notepad++ (64-bit x64)", "Notepad++"),
    ("Some App v2.1", "Some App"),
])
def test_strip_decorations(raw, expected):
    assert strip_decorations(raw) == expected


def test_name_variants_strip_publisher_prefix():
    names = name_variants("Mozilla Firefox (x64 en-US)", "Mozilla Corporation")
    assert names[0] == "mozillafirefox"
    assert "firefox" in names


def test_generic_names_rejected():
    assert name_variants("Update", "") == []
    assert not is_specific(normalize("Program Files"))
    assert not is_specific("abc")


def test_normalize_accents():
    assert normalize("Énergie Café") == "energiecafe"


def test_publisher_variants():
    assert publisher_variants("Mozilla Corporation") == ["mozillacorporation", "mozilla"]
    assert "videolan" in publisher_variants("VideoLAN")


def test_pack_guid():
    # Documented example: {12345678-ABCD-EF01-2345-6789ABCDEF01}
    assert pack_guid("{12345678-ABCD-EF01-2345-6789ABCDEF01}") == "87654321DCBA10FE32547698BADCFE10"
    with pytest.raises(ValueError):
        pack_guid("nope")


def test_split_args_matches_windows_rules():
    assert split_args(r'"C:\Program Files\a.exe" /S "x y" a\\"b') == [r"C:\Program Files\a.exe", "/S", "x y", 'a\\b']
    assert split_args(r'a.exe "a\"b" c\d') == ["a.exe", 'a"b', r"c\d"]
    assert split_args("") == []


def test_quote_roundtrip():
    for arg in ["simple", "with space", 'quote"inside', "trailing\\", r"C:\Program Files\x\\"]:
        assert split_args("x.exe " + quote_arg(arg))[1] == arg


def test_parse_quoted_command():
    p = parse_command('"C:\\Apps\\My App\\unins000.exe" /SILENT', exists=lambda p: True)
    assert p.executable == "C:\\Apps\\My App\\unins000.exe"
    assert p.arguments == "/SILENT"


def test_parse_unquoted_command_prefers_longest_existing():
    files = {r"C:\Program.exe", r"C:\Program Files\App\uninst.exe"}
    p = parse_command(r"C:\Program Files\App\uninst.exe /S _?=C:\Program Files\App", exists=files.__contains__)
    assert p.executable == r"C:\Program Files\App\uninst.exe"
    assert p.arguments == r"/S _?=C:\Program Files\App"
    assert p.resolved


def test_parse_unresolved_command():
    p = parse_command(r"C:\Gone\uninstall.exe /x", exists=lambda _p: False)
    assert not p.resolved and p.executable == r"C:\Gone\uninstall.exe"


def test_expand_env_case_insensitive():
    assert expand_env("%programfiles%\\x %UNKNOWN%", {"ProgramFiles": "C:\\PF"}) == "C:\\PF\\x %UNKNOWN%"
