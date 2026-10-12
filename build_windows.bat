@echo off
rem Builds dist\danidUn.exe. Needs Python 3.10+ (python.org, with the "py" launcher) and
rem Internet access only for this build step; the resulting .exe runs fully offline.
setlocal
cd /d "%~dp0"
if not exist .venv (
  py -3 -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt || exit /b 1
python -m pytest -q tests || (echo Tests failed & exit /b 1)
python -m PyInstaller --noconfirm --clean danidUn.spec || exit /b 1
echo.
echo Built: dist\danidUn.exe
pause
