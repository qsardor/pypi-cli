#!/usr/bin/env python3
"""Thin entrypoint shim delegating to canonical src/pypi_cli/cli.py."""

import sys
from pathlib import Path

_SRC_DIR = str(Path(__file__).resolve().parent / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from pypi_cli.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
