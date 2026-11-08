"""PyInstaller entry for ``HomeSOC.exe`` (installer/homesoc.spec): ``-m app.main``."""

from __future__ import annotations

import multiprocessing
import os
import sys


def _ensure_stdio() -> None:
    """A windowed (console=False) exe has no stdout/stderr; logging would write to None."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


if __name__ == "__main__":
    multiprocessing.freeze_support()
    _ensure_stdio()
    from app.main import main

    main()
