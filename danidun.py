"""danidUn – Windows-only, conservative uninstall + leftover review.
MIT-licensed example; no affiliation with Revo Uninstaller.
"""
from __future__ import annotations

import ctypes
import datetime as dt
import json
import stat
import os
import re
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import uuid
import winreg
from dataclasses import dataclass, asdict
from pathlib import Path
from tkinter import messagebox, ttk

APP_NAME = 'danidUn'
VERSION = '0.2.0'
ROOT_UNINSTALL = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
VIEW_FLAGS = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
DENY = {'windows', 'microsoft', 'system', 'common files', 'program files', 'program files (x86)',
        'appdata', 'programdata', 'users', 'desktop', 'documents', 'temp', 'update', 'runtime',
        'software', 'bin', 'data', 'app', 'application', 'uninstall', 'setup'}

@dataclass
class Program:
    name: str
    version: str
    publisher: str
    location: str
    command: str
    quiet_command: str
    key_path: str
    hive: str
    view: int
    windows_installer: bool

@dataclass
class Candidate:
    kind: str  # Folder | Registry
    target: str
    reason: str
    hive: str = ''
    view: int = 0


def reg_value(k, name):
    try:
        return str(winreg.QueryValueEx(k, name)[0] or '')
    except (OSError, ValueError):
        return ''


def installed_programs():
    found = {}
    for hive, hive_label in ((winreg.HKEY_LOCAL_MACHINE, 'HKLM'), (winreg.HKEY_CURRENT_USER, 'HKCU')):
        for view in VIEW_FLAGS:
            try:
                with winreg.OpenKey(hive, ROOT_UNINSTALL, 0, winreg.KEY_READ | view) as base:
                    for i in range(winreg.QueryInfoKey(base)[0]):
                        try:
                            subname = winreg.EnumKey(base, i)
                            with winreg.OpenKey(base, subname) as k:
                                name = reg_value(k, 'DisplayName').strip()
                                if not name or reg_value(k, 'SystemComponent') == '1':
                                    continue
                                p = Program(name, reg_value(k, 'DisplayVersion'), reg_value(k, 'Publisher'),
                                            reg_value(k, 'InstallLocation'), reg_value(k, 'UninstallString'),
                                            reg_value(k, 'QuietUninstallString'), ROOT_UNINSTALL + '\\' + subname,
                                            hive_label, view, reg_value(k, 'WindowsInstaller') == '1')
                                identity = (p.name.lower(), p.version.lower(), p.publisher.lower(), p.command.lower())
                                found.setdefault(identity, p)
                        except (OSError, PermissionError):
                            continue
            except OSError:
                continue
    return sorted(found.values(), key=lambda p: p.name.casefold())


def normalize(s):
    return re.sub(r'[^a-z0-9]+', '', s.casefold())


def valid_name(name):
    n = normalize(name)
    low = name.casefold().strip()
    reserved = ('microsoft ', 'windows ', 'windows-', 'system ', 'driver ', 'runtime ',
                'visual c++', '.net ', 'security ', 'defender ')
    return len(n) >= 6 and low not in DENY and not low.startswith(reserved)


def program_names(p):
    names = [p.name.strip()]
    # Remove trailing version only (e.g. "Example 2.3.1")
    simplified = re.sub(r'\s+(?:v(?:ersion)?\s*)?\d+(?:\.\d+){0,4}\s*$', '', p.name, flags=re.I).strip()
    if simplified != p.name and valid_name(simplified):
        names.append(simplified)
    location = p.location.strip().strip('"')
    if location:
        basename = Path(location.rstrip('\\/')).name
        if normalize(basename) in {normalize(n) for n in names} and valid_name(basename):
            names.append(basename)
    return {normalize(n) for n in names if valid_name(n)}


def roots_for_scan():
    env = os.environ
    candidates = [env.get('APPDATA'), env.get('LOCALAPPDATA'), env.get('PROGRAMDATA'),
                  env.get('ProgramFiles'), env.get('ProgramFiles(x86)')]
    roots = []
    for raw in candidates:
        if raw:
            path = Path(raw)
            if path.is_dir() and path not in roots:
                roots.append(path)
    return roots


def scan_leftovers(p):
    names = program_names(p)
    if not names:
        return [], 'Nombre demasiado genérico: no se permite buscar residuos automáticamente.'
    found = []
    for root in roots_for_scan():
        try:
            for child in root.iterdir():
                if is_reparse_point(child) or not child.is_dir():
                    continue
                if normalize(child.name) in names:
                    found.append(Candidate('Folder', str(child), f'Carpeta con nombre exacto: {root}'))
        except (PermissionError, OSError):
            continue
    # Only exact app subkeys, never generic publisher keys or the uninstall entry itself.
    publisher = p.publisher.strip()
    safe_publisher = valid_name(publisher)
    for hive, label in ((winreg.HKEY_CURRENT_USER, 'HKCU'), (winreg.HKEY_LOCAL_MACHINE, 'HKLM')):
        for view in VIEW_FLAGS:
            for parent in [r'SOFTWARE'] + (['SOFTWARE\\' + publisher] if safe_publisher and '\\' not in publisher else []):
                try:
                    with winreg.OpenKey(hive, parent, 0, winreg.KEY_READ | view) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            name = winreg.EnumKey(key, i)
                            if normalize(name) in names:
                                found.append(Candidate('Registry', label + '\\' + parent + '\\' + name,
                                                       'Clave con nombre exacto del programa', label, view))
                except (PermissionError, OSError):
                    continue
    unique = {(x.kind, x.target.casefold(), x.view): x for x in found}
    return list(unique.values()), ''


def windows_args(command):
    """Split a Windows command line using the OS parser, not shell=True."""
    shell32 = ctypes.windll.shell32
    kernel32 = ctypes.windll.kernel32
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    length = ctypes.c_int()
    ptr = shell32.CommandLineToArgvW(command, ctypes.byref(length))
    if not ptr:
        raise RuntimeError('No se puede interpretar el comando de desinstalación.')
    try:
        return [ptr[i] for i in range(length.value)]
    finally:
        kernel32.LocalFree(ctypes.cast(ptr, ctypes.c_void_p))


def get_command(p):
    text = p.command.strip()
    if not text:
        raise ValueError('Este programa no publica un comando de desinstalación.')
    args = windows_args(text)
    if not args:
        raise ValueError('Comando de desinstalación vacío.')
    exe = Path(args[0]).name.casefold()
    # MSI registry strings often use /I (maintenance), convert to /X (uninstall).
    if exe in ('msiexec', 'msiexec.exe') or p.windows_installer:
        if exe not in ('msiexec', 'msiexec.exe'):
            return args
        result = ['msiexec.exe']
        for a in args[1:]:
            if a.lower() == '/i':
                result.append('/X')
            elif re.fullmatch(r'/i\{[0-9a-fA-F-]{36}\}', a, re.I):
                result.append('/X' + a[2:])
            else:
                result.append(a)
        return result
    # Do not run shell, cmd /c, powershell or script interpreters from untrusted registry entries.
    disallowed = {'cmd.exe', 'cmd', 'powershell.exe', 'powershell', 'pwsh.exe', 'pwsh',
                  'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe',
                  'mshta.exe', 'bash.exe'}
    if exe in disallowed or not exe.endswith('.exe'):
        raise ValueError('Comando no admitido por seguridad. Desinstala manualmente desde Configuración de Windows.')
    return args


def registry_backup_and_delete(c, backup_dir):
    key_text = c.target
    out = backup_dir / f'registry-{uuid.uuid4().hex[:10]}.reg'
    view_flag = '/reg:64' if c.view == winreg.KEY_WOW64_64KEY else '/reg:32'
    export = subprocess.run(['reg.exe', 'export', key_text, str(out), '/y', view_flag],
                            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if export.returncode != 0 or not out.is_file():
        raise RuntimeError('No fue posible crear el backup del registro; se omitió la eliminación.')
    hive_label, subpath = key_text.split('\\', 1)
    if not (subpath.upper().startswith('SOFTWARE\\') and
            subpath.upper() != 'SOFTWARE\\MICROSOFT'):
        raise RuntimeError('Ruta del registro protegida.')
    hive = winreg.HKEY_CURRENT_USER if hive_label == 'HKCU' else winreg.HKEY_LOCAL_MACHINE
    # The exact target subkey was already confirmed by the scan.
    winreg.DeleteKeyEx(hive, subpath, access=c.view)
    return str(out)


def is_reparse_point(path):
    try:
        return bool(os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, AttributeError):
        return True


def safe_folder(path):
    """Block roots, junctions, symlinks and folders outside known app locations."""
    p = Path(path).absolute()
    if is_reparse_point(p):
        return False
    allowed = roots_for_scan()
    # Only direct children of the configured roots, or validated InstallLocation.
    return any(p.parent == root.absolute() for root in allowed) and valid_name(p.name)


def restore_session(session):
    reportfile = session / 'report.json'
    report = json.loads(reportfile.read_text(encoding='utf-8'))
    restored = 0
    errors = []
    for item in reversed(report.get('results', [])):
        if not item.get('success') or item.get('restored'):
            continue
        c = item['candidate']
        backup = Path(item['backup'])
        try:
            if c['kind'] == 'Folder':
                target = Path(c['target'])
                if target.exists() or not backup.is_dir():
                    raise RuntimeError('El destino ya existe o falta el backup.')
                if not safe_folder(target) or is_reparse_point(backup):
                    raise RuntimeError('Ruta no considerada segura para restaurar.')
                shutil.move(str(backup), str(target))
            elif c['kind'] == 'Registry':
                if not backup.is_file() or backup.suffix.casefold() != '.reg':
                    raise RuntimeError('No se encontró el archivo .reg.')
                result = subprocess.run(['reg.exe', 'import', str(backup),
                                         '/reg:64' if c.get('view') == winreg.KEY_WOW64_64KEY else '/reg:32'], capture_output=True,
                                        text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode:
                    raise RuntimeError(result.stderr or result.stdout or 'Falló reg import.')
            else:
                raise RuntimeError('Tipo de objeto desconocido.')
            item['restored'] = True
            restored += 1
        except Exception as exc:
            errors.append(f"{c['target']}: {exc}")
    reportfile.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    return restored, errors


def quarantine_folder(c, backup_dir):
    source = Path(c.target)
    if not safe_folder(source) or not source.is_dir():
        raise RuntimeError('Ya no existe, o es un enlace simbólico.')
    dest = backup_dir / ('folder-' + uuid.uuid4().hex[:10] + '-' + source.name)
    shutil.move(str(source), str(dest))
    return str(dest)


class Window(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('danidUn — Community Edition v' + VERSION)
        self.geometry('1080x690')
        self.minsize(820, 510)
        self.configure(bg='#121820')
        self.programs = []
        self.visible_programs = []
        self.candidates = []
        self.current = None
        self.busy = False
        self.search = tk.StringVar()
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('Treeview', background='#1c2631', foreground='white', fieldbackground='#1c2631', rowheight=28)
        style.configure('Treeview.Heading', background='#2e3d4a', foreground='white')
        style.map('Treeview', background=[('selected', '#236c83')])
        header = tk.Frame(self, bg='#121820')
        header.pack(fill='x', padx=20, pady=(16, 10))
        tk.Label(header, text='DANIDUN', bg='#121820', fg='#54d0bc', font=('Segoe UI', 19, 'bold')).pack(side='left')
        tk.Button(header, text='Actualizar', command=self.refresh).pack(side='right')
        tk.Button(header, text='Restaurar cuarentena', command=self.restore_dialog).pack(side='right', padx=8)
        searchbar = tk.Frame(self, bg='#121820')
        searchbar.pack(fill='x', padx=20)
        tk.Label(searchbar, text='Buscar:', fg='white', bg='#121820').pack(side='left')
        tk.Entry(searchbar, textvariable=self.search, font=('Segoe UI', 11)).pack(side='left', padx=10, fill='x', expand=True)
        self.search.trace_add('write', lambda *_: self.filter_programs())
        container = tk.Frame(self, bg='#121820')
        container.pack(fill='both', expand=True, padx=20, pady=12)
        cols = ('name', 'version', 'publisher')
        self.tree = ttk.Treeview(container, columns=cols, show='headings', selectmode='browse')
        for col, title, width in [('name', 'Programa', 390), ('version', 'Versión', 140), ('publisher', 'Fabricante', 240)]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, stretch=True)
        scroll = ttk.Scrollbar(container, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.tree.bind('<<TreeviewSelect>>', self.selection_changed)
        actions = tk.Frame(self, bg='#121820')
        actions.pack(fill='x', padx=20, pady=5)
        tk.Button(actions, text='1. Desinstalar', command=self.uninstall, width=20).pack(side='left', padx=(0, 8))
        tk.Button(actions, text='2. Buscar residuos', command=self.scan, width=22).pack(side='left', padx=(0, 8))
        tk.Button(actions, text='Ver / poner en cuarentena', command=self.show_candidates, width=28).pack(side='left')
        tk.Button(actions, text='Desinstalación forzada', command=self.forced_scan, width=22).pack(side='left', padx=8)
        self.info = tk.StringVar(value='Selecciona una aplicación. Ejecuta su desinstalador y luego analiza residuos.')
        tk.Label(self, textvariable=self.info, bg='#121820', fg='#d5e8ec', anchor='w',
                 justify='left', wraplength=1000).pack(fill='x', padx=20, pady=(8, 15))
        self.after(200, self.refresh)

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, 'Selecciona un programa primero.')
            return None
        return self.visible_programs[int(sel[0])]

    def refresh(self):
        try:
            self.programs = installed_programs()
            self.filter_programs()
            self.info.set(f'{len(self.programs)} aplicaciones registradas encontradas. No se incluyen todas las aplicaciones Microsoft Store.')
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def filter_programs(self):
        needle = self.search.get().casefold().strip()
        self.visible_programs = [p for p in self.programs if needle in (p.name + ' ' + p.publisher).casefold()]
        for item in self.tree.get_children():
            self.tree.delete(item)
        for index, p in enumerate(self.visible_programs):
            self.tree.insert('', 'end', iid=str(index), values=(p.name, p.version, p.publisher))

    def selection_changed(self, _evt=None):
        p = self.selected() if self.tree.selection() else None
        if p:
            self.current = p
            self.candidates = []
            self.info.set(f'{p.name} | Ruta: {p.location or "No publicada"} | Desinstalador: {"Sí" if p.command else "No"}')

    def uninstall(self):
        p = self.selected()
        if not p or self.busy:
            return
        try:
            args = get_command(p)
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        if not messagebox.askyesno('Confirmar', f'¿Ejecutar el desinstalador registrado de {p.name}?\n\nCierra primero la aplicación y guarda tu trabajo.\n\n{args[0]}'):
            return
        self.busy = True
        self.info.set('Ejecutando desinstalador. Completa los diálogos de Windows; después busca residuos.')
        def work():
            try:
                proc = subprocess.Popen(args)
                code = proc.wait()
                self.after(0, lambda: self.info.set(f'Desinstalador terminado (código {code}). Selecciona el programa y pulsa «Buscar residuos».'))
                self.after(0, lambda: messagebox.showinfo(APP_NAME, f'El desinstalador terminó con código {code}.\nRevisa que haya completado correctamente y luego busca residuos.'))
            except Exception as exc:
                self.after(0, lambda m=str(exc): messagebox.showerror(APP_NAME, m))
            finally:
                self.after(0, lambda: setattr(self, 'busy', False))
        threading.Thread(target=work, daemon=True).start()

    def scan(self):
        if self.busy:
            return
        # Keep the previously selected program even after its uninstall entry vanishes.
        p = self.visible_programs[int(self.tree.selection()[0])] if self.tree.selection() else self.current
        if not p:
            messagebox.showinfo(APP_NAME, 'Selecciona un programa primero.')
            return
        self.current = p
        self.candidates, warning = scan_leftovers(p)
        self.info.set(f'{len(self.candidates)} candidatos detectados para {p.name}. {warning} Los resultados NO prueban que sea seguro borrarlos.')
        self.show_candidates()

    def forced_scan(self):
        from tkinter import simpledialog
        name = simpledialog.askstring('Desinstalación forzada',
            'Nombre EXACTO de la aplicación (mínimo 6 caracteres).\n'
            'Este modo no ejecuta ningún desinstalador y solo examina coincidencias exactas.\n'
            'No elimina automáticamente nada.', parent=self)
        if name is None:
            return
        name = name.strip()
        if not valid_name(name):
            messagebox.showerror(APP_NAME, 'Nombre demasiado corto o genérico; operación rechazada.')
            return
        self.current = Program(name, '', '', '', '', '', '', '', 0, False)
        self.candidates, warning = scan_leftovers(self.current)
        self.info.set(f'Desinstalación forzada (solo residuos): {len(self.candidates)} candidatos. {warning}')
        self.show_candidates()

    def restore_dialog(self):
        base = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'danidUn' / 'Quarantine'
        sessions = sorted((p for p in base.iterdir() if p.is_dir() and (p/'report.json').is_file()),
                          reverse=True) if base.is_dir() else []
        dlg = tk.Toplevel(self)
        dlg.title('Restaurar cuarentena')
        dlg.geometry('780x420')
        tk.Label(dlg, text='Selecciona una sesión para restaurar sus carpetas y claves del registro.').pack(pady=12)
        lb = tk.Listbox(dlg, font=('Consolas', 10))
        lb.pack(fill='both', expand=True, padx=12)
        for item in sessions:
            lb.insert('end', str(item))
        def restore():
            selection = lb.curselection()
            if not selection:
                return
            session = sessions[selection[0]]
            if not messagebox.askyesno('Confirmar',
                    '¿Restaurar archivos y claves de registro de esta sesión?\n'
                    'No reemplazará carpetas que ya existan.\n' + str(session), parent=dlg):
                return
            try:
                done, errors = restore_session(session)
                messagebox.showinfo(APP_NAME, f'Restaurados: {done}\nErrores: {len(errors)}\n' +
                                    '\n'.join(errors[:5]), parent=dlg)
            except Exception as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=dlg)
        tk.Button(dlg, text='Restaurar selección', command=restore).pack(pady=12)

    def show_candidates(self):
        if not self.current:
            messagebox.showinfo(APP_NAME, 'Selecciona una app y ejecuta «Buscar residuos».')
            return
        dialog = tk.Toplevel(self)
        dialog.title('Revisar residuos — ' + self.current.name)
        dialog.geometry('910x520')
        tk.Label(dialog, text='Selecciona SOLO residuos que reconozcas. La limpieza crea una cuarentena recuperable.',
                 wraplength=850, font=('Segoe UI', 10, 'bold')).pack(pady=12)
        outer = tk.Frame(dialog)
        outer.pack(fill='both', expand=True, padx=15)
        listbox = tk.Listbox(outer, selectmode='extended', font=('Consolas', 10))
        listbox.pack(side='left', fill='both', expand=True)
        bar = tk.Scrollbar(outer, command=listbox.yview)
        bar.pack(side='right', fill='y')
        listbox.config(yscrollcommand=bar.set)
        for c in self.candidates:
            label = f'[{c.kind}] {c.target}' + (' [32-bit]' if c.kind == 'Registry' and c.view == winreg.KEY_WOW64_32KEY else '')
            listbox.insert('end', label)
        def do_clean():
            selected = listbox.curselection()
            if not selected:
                messagebox.showinfo(APP_NAME, 'Selecciona manualmente uno o más residuos.', parent=dialog)
                return
            targets = [self.candidates[i] for i in selected]
            summary = '\n'.join('• ' + x.target for x in targets[:8])
            if not messagebox.askyesno('Confirmación de seguridad',
                    '¿Mover estas carpetas a cuarentena y exportar las claves antes de borrarlas?\n\n'
                    + summary + ('\n...' if len(targets)>8 else '')
                    + '\n\nPuede afectar otras aplicaciones si compartían datos.', parent=dialog):
                return
            base = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'danidUn' / 'Quarantine'
            backup = base / dt.datetime.now().strftime('%Y%m%d-%H%M%S')
            backup.mkdir(parents=True, exist_ok=True)
            report = {'application': self.current.name, 'timestamp': dt.datetime.now().isoformat(), 'results': []}
            ok = 0
            for c in targets:
                try:
                    stored = quarantine_folder(c, backup) if c.kind == 'Folder' else registry_backup_and_delete(c, backup)
                    report['results'].append({'candidate': asdict(c), 'backup': stored, 'success': True})
                    ok += 1
                except Exception as exc:
                    report['results'].append({'candidate': asdict(c), 'error': str(exc), 'success': False})
            (backup / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
            messagebox.showinfo(APP_NAME, f'{ok}/{len(targets)} elementos procesados.\n\nCuarentena y reporte:\n{backup}\n\nConserva estos backups para poder revertir cambios.', parent=dialog)
            dialog.destroy()
            self.candidates, _ = scan_leftovers(self.current)
            self.info.set(f'{ok} elementos procesados. Backup: {backup}')
        tk.Button(dialog, text='Poner elementos seleccionados en cuarentena', command=do_clean).pack(pady=12)
        tk.Label(dialog, text='Advertencia: no se eliminan aplicaciones MSIX/Appx, servicios, tareas o archivos dispersos.',
                 fg='#7a3232').pack(pady=(0, 8))


if __name__ == '__main__':
    if sys.platform != 'win32':
        raise SystemExit('Este programa necesita Windows 10 u 11.')
    Window().mainloop()
