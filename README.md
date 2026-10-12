# danidUn 0.2 (prototipo Windows)

Aplicación **gratuita, offline, con código fuente**, independiente de Revo y REA. Compatible con Windows 10/11. Interfaz Tkinter incluida con Python.

## Funciones implementadas
- Enumera programas Win32 desde HKCU/HKLM (vistas de registro 32/64 bits).
- Filtra aplicaciones por nombre/editor y ejecuta el desinstalador publicado (con confirmación). Soporta modificación de `msiexec /I` a `/X`.
- Encuentra **únicamente carpetas hijas de primer nivel** con coincidencia exacta del nombre de la aplicación en ubicaciones habituales y claves de registro coincidentes. NO es un escáner exhaustivo.
- Permite escanear aplicaciones que ya no figuran en la lista mediante **Desinstalación forzada (solo residuos)**. No remueve servicios, drivers ni archivos dispersos.
- Permite seleccionar manualmente las coincidencias; mueve carpetas a cuarentena y exporta las claves de registro antes de borrarlas.
- Genera `report.json` y tiene pantalla de **restauración** de sesiones en cuarentena. No sobreescribe carpetas existentes.
- Rechaza nombres demasiado genéricos, carpetas raíz y enlaces/reparse points. No realiza eliminación silenciosa.

## Compilar `.exe` en Windows

1. Instalar Python 3.11+ desde python.org (incluir el lanzador `py`).
2. Descomprimir el ZIP completo.
3. Doble clic en `build_windows.bat` con conexión a Internet (instala PyInstaller en un entorno virtual local).
4. El `.exe` estará en `dist\danidUn.exe`. Luego se puede ejecutar offline sin Python.

Para ejecutar desde el código: `py -3 danidun.py`.

## Uso

1. Haz un punto de restauración o snapshot de una VM. Prueba solo con software prescindible.
2. Selecciona un programa y pulsa **Desinstalar**; termina el proceso del instalador.
3. Pulsa **Buscar residuos** (se conserva la última selección aunque desaparezca la entrada de la lista).
4. Comprueba cuidadosamente las rutas y selecciona únicamente las que reconozcas.
5. Pulsa **Poner elementos seleccionados en cuarentena**. Las copias se guardan en `%LOCALAPPDATA%\danidUn\Quarantine`.
6. Para revertir los elementos de una sesión, pulsa **Restaurar cuarentena**. Restaurar claves HKLM podría exigir privilegios de administrador.

## Limitaciones importantes

Este es un **prototipo v0.2**: no equivale a Revo Pro. No detecta todos los residuos, servicios, tareas programadas, Appx/MSIX, asociaciones de archivos ni rastros distribuidos. No monitoriza instalaciones, no implementa Hunter Mode, y no garantiza desinstalación completa de ninguna aplicación. Un programa podría compartir carpetas o claves con otro; revisar resultados es obligatorio. No ejecutar como administrador salvo que sea imprescindible y se entienda el alcance. Los `.reg` guardados son datos sensibles del equipo: almacénalos de forma privada.

**No probado ejecutándose en Windows en este entorno**; solo comprobada la sintaxis con CPython y empaquetamiento del código. La primera prueba real debe hacerse en VM y se requieren pruebas de extremo a extremo antes de confiarle datos importantes.

## Independencia

No depende de REA/Ghidra, de Revo, APIs pagadas, IA o servidores. Es código de ejemplo para desarrollar y ampliar; no contiene código propietario de Revo.
