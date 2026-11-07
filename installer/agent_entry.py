"""PyInstaller entry for ``HomeSOC-Agent.exe`` (installer/homesoc.spec): ``-m agent.main``."""

from __future__ import annotations

import multiprocessing
import os
import sys


def _ensure_stdio() -> None:
    """A windowed (console=False) exe has no stdout/stderr; uvicorn's logging needs them."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


if __name__ == "__main__":
    multiprocessing.freeze_support()  # NFStream starts worker processes
    _ensure_stdio()
    from agent.main import main

    main()
