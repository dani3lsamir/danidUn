# PyInstaller spec for a single-file, windowed danidUn.exe.
# Build with:  pyinstaller --noconfirm --clean danidUn.spec
block_cipher = None

a = Analysis(
    ["run_danidun.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    excludes=["unittest", "pydoc", "test", "lib2to3", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="danidUn",
    console=False,
    debug=False,
    strip=False,
    upx=False,                # UPX-packed executables trigger antivirus false positives
    version="packaging/version_info.txt",
    uac_admin=False,          # asInvoker: elevate on demand from inside the app
    icon=None,
)
