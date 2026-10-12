"""Launcher used by PyInstaller and for running from source: ``py -3 run_danidun.py``."""
import sys

from danidun.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
