@echo off
setlocal
cd /d "%~dp0"
py -3 -m venv .venv
if errorlevel 1 exit /b 1
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name danidUn danidun.py
if errorlevel 1 exit /b 1
echo.
echo Archivo generado: dist\danidUn.exe
pause
