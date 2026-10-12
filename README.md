# danidUn 0.3

**danidUn** is a free, offline, open-source uninstaller for Windows 10 and 11. It runs the
application's own uninstaller and then looks for leftovers. Every leftover gets an
evidence-based confidence score. Nothing is removed without your approval, and every removal
can be undone.

No telemetry, no ads, no subscriptions, no cloud services, no AI APIs. Independent project:
it contains no Revo Uninstaller code and does not need Revo to be installed.

> ⚠️ **Status: beta, not yet validated on real Windows machines.** The engine has automated tests
> (on Linux with a simulated registry, and read-only checks on a Windows CI runner). Try it first
> in a virtual machine or after creating a restore point.

## Features

### Installed applications
- Win32 programs from `HKLM` (64-bit and 32-bit views) and `HKCU` (per-user installs).
- MSI products, detected by their ProductCode. Shows when Windows Installer no longer knows a product.
- Microsoft Store / MSIX apps via the built-in Appx module (frameworks and system apps are hidden).
- Broken entries are flagged: missing uninstaller, missing install folder, unregistered MSI.
- Shows name, publisher, version, size, install date, type/architecture and icon. Search,
  filtering (Win32 / MSI / Store / current user / with problems), sortable columns, refresh (F5).

### Standard uninstall (guided)
1. danidUn first collects the app's identity: install folder, executables, registry key and
   ProductCode. It does this *before* the uninstaller deletes them.
2. Optional system restore point.
3. Runs the official uninstaller, **never through a shell**. For MSI, danidUn builds its own
   `msiexec /x {ProductCode}` call and ignores the registered string. Uninstall strings that
   call `cmd`, PowerShell, script hosts, `rundll32`, etc. are refused. Unquoted paths are resolved
   safely, so a planted `C:\Program.exe` cannot hijack them. If an uninstaller needs it, danidUn
   asks for elevation through UAC.
4. Waits for the uninstaller *and every process it spawns*, which covers NSIS/Inno uninstallers
   that copy themselves to `%TEMP%`.
5. Interprets the exit code (MSI codes included) and checks that the entry and folder are gone.
   If the program still looks installed, danidUn asks before continuing.
6. Leftover scan → review → quarantine → HTML + JSON report.

### Deep leftover scanner
Locations: Program Files (both), `ProgramData`, `AppData\Roaming`, `AppData\Local`, `LocalLow`,
`AppData\Local\Programs`, Common Files, Documents (Advanced mode), MSI Package Cache, Store
package data. Registry: `SOFTWARE` keys (both views, HKCU/HKLM), the uninstall entry, App Paths,
`Classes\Applications`, ProgIDs whose open command or icon points to the program, Run/RunOnce
and StartupApproved, MuiCache/AppCompat traces, MSI registrations. Also services, scheduled
tasks, startup-folder entries, and Start menu / desktop / taskbar shortcuts (`.lnk` targets
are parsed).

**Confidence scoring.** Each item collects independent evidence. Examples: it *is* the
registered install folder (+90), it *points into* the install folder (+85), its name is
identical to the app's (+65), it sits under the publisher's folder (+20), other installed
programs share the publisher (−30), it is in Documents (−25), it points to an existing file
elsewhere (−40). The score maps to **High** (≥ 80), **Medium** (≥ 50) or **Low**:

| Mode | Shows |
|------|-------|
| Safe | High only |
| Moderate (default) | High + Medium, file associations, MSI registrations |
| Advanced | Everything, including partial-name matches and a bounded deep registry walk |

Only **High** items are pre-selected. A partial name match on its own can never rise above
Low. You can see the evidence behind every item in the results view.

### Safety layer
- Registry removals follow an **allow-list** of documented application locations; everything
  else is refused.
- Windows, system/user known folders and their parents, shared locations (`Common Files\Microsoft
  Shared`, `ProgramData\Microsoft`, `WindowsApps`, vendor roots such as `Google` or `Mozilla`…),
  and **any folder used by another installed program** are protected.
- Drivers, critical Windows services, svchost-hosted services, `\Microsoft\` scheduled tasks and
  the services of security software are never removed. They are shown with a 🔒 so you know
  they exist.
- Junctions and symbolic links are never followed or deleted.
- Each item is re-validated at the moment of removal *and* at restore time. On restore, `.reg`
  backups must only contain the original key, so a tampered backup cannot write elsewhere.

### Forced uninstall
For programs with a broken or missing uninstaller. Identify the program by **the list entry,
its name (+ publisher), its install folder or its main executable**. Name and publisher are
read from the executable's version resources. If the folder still contains an uninstaller
(`unins000.exe`, `uninstall.exe`…), you can run it first. The scan then includes the orphaned
uninstall entry.

### Quarantine and restore
Removed folders and files are moved (not deleted) to `%LOCALAPPDATA%\danidUn\Quarantine\<session>`.
Before removal, registry keys and services are exported to `.reg` files, registry values are
saved in the session manifest, and scheduled tasks are exported as XML. A whole session can be
restored, or deleted permanently, from **Quarantine**. Locked files are reported (partial
removal) rather than silently skipped.

### Reports and logs
Every operation writes `%LOCALAPPDATA%\danidUn\Reports\*.html` and `*.json`. Activity is logged
to `%LOCALAPPDATA%\danidUn\logs\danidun.log`.

### Interface
Dark Tkinter/ttk interface, ships with Python, no extra dependencies. All long operations run
in background threads. Spanish and English, chosen from the Windows UI language or from
Settings.

## Build `danidUn.exe`

```bat
build_windows.bat
```
Requires Python 3.10+ from python.org (with the `py` launcher) and Internet access **for the
build only**. The script creates a virtual environment, installs pinned PyInstaller/pytest,
runs the tests and produces `dist\danidUn.exe`, which runs fully offline.

The executable runs with the user's own privileges (`asInvoker`). Use **Restart as
administrator** in the window header to remove machine-wide items.

Every push also builds the `.exe` on GitHub Actions (`.github/workflows/build.yml`). Download it
from the run's *Artifacts*.

Run from source: `py -3 run_danidun.py` (or `py -3 -m danidun`).

## Tests

```bash
python -m pytest -q
```
The engine is tested on any OS with an in-memory registry and a simulated Windows folder
tree. Windows-only tests compare the command-line parser with the real `CommandLineToArgvW`
and check the real inventory and protection rules. The GUI smoke test drives the real
interface end to end whenever a display is available.

## Project layout

```
danidun/
  inventory.py   installed programs (registry)       appx.py       Store/MSIX packages
  uninstaller.py validated plans, execution, waiting  cmdline.py    command-line parsing (no shell)
  scanner/       files, registry, services, tasks, shortcuts + scoring and the engine
  safety.py      protection rules                     quarantine.py backup / remove / restore
  forced.py      forced-uninstall identity            reports.py    HTML/JSON reports
  registry.py    winreg backend + interface           winapi.py     ctypes Win32 helpers
  gui/           main window, wizard, results view, dialogs, theme
tests/           unit, scenario, GUI and Windows integration tests
docs/ROADMAP.md  gap analysis and development plan
```

## Resumen en español

danidUn es un desinstalador gratuito y sin conexión para Windows 10/11. Ejecuta el
desinstalador oficial sin pasar por un intérprete de comandos. Después busca residuos en
archivos, registro, servicios, tareas programadas, inicio automático y accesos directos, y
asigna a cada uno una confianza (alta/media/baja) basada en pruebas. Solo se preseleccionan
los de confianza alta. Todo se mueve a una cuarentena restaurable. La desinstalación forzada
permite identificar programas rotos por su entrada, nombre, carpeta o ejecutable. La interfaz
está en español o inglés según el idioma de Windows. Para compilar el `.exe`, ejecuta
`build_windows.bat`.

## License

MIT. See [LICENSE](LICENSE).
