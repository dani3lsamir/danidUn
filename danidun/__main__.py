"""Entry point: ``python -m danidun`` or the packaged danidUn.exe."""
from __future__ import annotations

import logging
import sys


def main() -> int:
    if sys.platform != "win32":
        print("danidUn requires Windows 10 or 11.", file=sys.stderr)
        return 1
    from . import i18n, winapi
    from .config import Settings, setup_logging

    try:
        # Crisp text on high-DPI screens.
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    setup_logging()
    settings = Settings.load()
    i18n.set_language(settings.language)
    logging.getLogger(__name__).info("danidUn starting (admin=%s)", winapi.is_admin())

    from .gui.app import MainWindow
    from .runtime import Runtime

    MainWindow(Runtime(), settings).mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
