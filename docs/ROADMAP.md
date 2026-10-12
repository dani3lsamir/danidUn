# danidUn – assessment and development plan

## 1. Starting point (v0.2)

v0.2 was a single 500-line Tkinter script:

| Area | v0.2 | Problem |
|------|------|---------|
| Inventory | HKLM/HKCU uninstall keys, both views | Updates and hidden entries not handled. No Store apps, no MSI awareness, no broken-entry detection, no icons, sizes or dates |
| Uninstall | `CommandLineToArgvW`, interpreter denylist, `/I`→`/X` rewrite | Unquoted paths with spaces failed. Waited only for the first process (NSIS/Inno exit immediately). No UAC fallback. Exit codes ignored |
| Leftovers | First-level folders with an *exact* name; `SOFTWARE\<name>` keys | No services, tasks, shortcuts, startup entries, App Paths, file associations or MSI traces. No scoring |
| Safety | Generic-name denylist, reparse-point check | No protection of other programs' folders, shared locations or drivers. The registry check ran *after* the export |
| Quarantine | Folders moved, keys exported | Values, services and tasks not supported. Restore trusted the manifest blindly |
| Tests | none | Windows-only code, not testable |

## 2. What 0.3 delivers

Requested sections A–D are implemented (see README). Architecture decisions:

- **Testability first.** Every Windows dependency sits behind a small interface: registry
  backend, system operations, known folders. The whole engine runs against an in-memory
  registry on any OS, and the Windows CI runner checks the real APIs (read-only).
- **Evidence, not matching.** Scanners only *collect evidence*. Scoring, protection, mode
  filtering and de-duplication happen in one place (`scanner/engine.py`). New scanners
  therefore cannot bypass the safety rules.
- **Allow-list for the registry, deny-list + ownership for the filesystem.**
- **Identity captured before uninstalling.** Executables and paths are collected before the
  uninstaller deletes them, so the scan still recognises traces that point to them.

## 3. Known gaps / next steps (priority order)

### P1 – validation on real systems
1. Run the CI-built `.exe` in clean Windows 10 22H2 and Windows 11 24H2 VMs. Uninstall a corpus
   of real installers (NSIS, Inno Setup, InstallShield, WiX/MSI, Burn bundles, Squirrel,
   ClickOnce, Store apps) and record false positives and negatives. Tune `scanner/scoring.py`
   weights from the results.
2. Code-sign the executable to avoid SmartScreen warnings. Free options: SignPath for OSS, or
   Azure Trusted Signing.
3. A `danidun --scan "<name>" --json` command-line mode for scripted regression runs.

### P2 – uninstall engine
4. Batch uninstall (queue several programs, scan once at the end).
5. Pending-reboot awareness: `PendingFileRenameOperations`, Windows Installer in-progress
   detection, and an offer to delete locked files at reboot (`MoveFileEx` +
   `MOVEFILE_DELAY_UNTIL_REBOOT`, admin only).
6. Squirrel/ClickOnce specifics (`Update.exe --uninstall`, `dfshim`).
7. Per-user installs of *other* user profiles (load `NTUSER.DAT` read-only under `HKU`).
8. Quiet-mode heuristics per installer technology (`/S`, `/VERYSILENT`, `/qn`), opt-in only.

### P3 – scanner depth
9. Windows Firewall rules (`FirewallRules` values with `App=` in the install folder), removed
   through `netsh advfirewall`.
10. COM registrations (`CLSID`/`TypeLib`) whose `InprocServer32`/`LocalServer32` points into the
    install folder. Report only, until the false-positive rate is known.
11. Shell extensions and context-menu handlers, plus `Explorer\FileExts` OpenWithList traces.
12. Event log sources under `SYSTEM\CurrentControlSet\Services\EventLog\Application\<name>`.
13. `Uninstall` entries of the program's own sub-components (same install folder, same
    publisher) offered together.
14. Fast name index of `%ProgramData%` and `%AppData%` subtrees for Advanced mode, with a
    depth/size budget.

### P4 – features beyond uninstalling (Revo-like, all optional)
15. **Installation monitor**: snapshot of registry and filesystem before and after an
    installation, giving an exact trace log per program for perfect future removal. Highest
    long-term value.
16. Startup manager (enable/disable Run entries, startup folder, tasks), reusing the existing
    scanners.
17. Junk-file cleaner limited to well-known caches.
18. Portable-mode settings (`danidUn.ini` beside the `.exe`).
19. Accessibility pass (keyboard navigation in the results tree, high-contrast theme) and
    more languages.

Out of scope by design: telemetry, accounts, cloud lookups, premium tiers, bypassing
licensing, and any dependency on Revo Uninstaller.
