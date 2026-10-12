import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from danidun.paths import KnownFolders  # noqa: E402
from fakes import FakeRegistry  # noqa: E402


@pytest.fixture
def folders(tmp_path: Path) -> KnownFolders:
    """A miniature Windows layout inside tmp_path."""
    def mk(*parts):
        p = tmp_path.joinpath(*parts)
        p.mkdir(parents=True, exist_ok=True)
        return str(p)

    user = mk("Users", "alice")
    appdata = mk("Users", "alice", "AppData", "Roaming")
    program_data = mk("ProgramData")
    f = KnownFolders(
        windows=mk("Windows"),
        program_files=mk("Program Files"),
        program_files_x86=mk("Program Files (x86)"),
        common_files=mk("Program Files", "Common Files"),
        common_files_x86=mk("Program Files (x86)", "Common Files"),
        program_data=program_data,
        appdata=appdata,
        local_appdata=mk("Users", "alice", "AppData", "Local"),
        local_low=mk("Users", "alice", "AppData", "LocalLow"),
        user_profile=user,
        users_root=mk("Users"),
        public=mk("Users", "Public"),
        temp=mk("Users", "alice", "AppData", "Local", "Temp"),
        documents=mk("Users", "alice", "Documents"),
        desktop_user=mk("Users", "alice", "Desktop"),
        desktop_public=mk("Users", "Public", "Desktop"),
        start_menu_user=mk("Users", "alice", "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"),
        start_menu_common=mk("ProgramData", "Microsoft", "Windows", "Start Menu"),
        startup_user=mk("Users", "alice", "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        startup_common=mk("ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        quick_launch=mk("Users", "alice", "AppData", "Roaming", "Microsoft", "Internet Explorer", "Quick Launch"),
        tasks_dir=mk("Windows", "System32", "Tasks"),
    )
    return f


@pytest.fixture
def reg() -> FakeRegistry:
    return FakeRegistry()


@pytest.fixture(autouse=True)
def _english():
    from danidun import i18n
    i18n.set_language("en")
    yield


def touch(path: str, content: bytes = b"x") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)
    return path
