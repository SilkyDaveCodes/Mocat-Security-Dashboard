# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for HomeSOC (CLAUDE.md §4, §8). Build from the repo root:
#     .venv\Scripts\pyinstaller installer\homesoc.spec
# Output: dist\HomeSOC\ with two executables sharing one _internal\ folder:
#   HomeSOC-Agent.exe  the agent (capture, detectors, firewall, API); uac_admin=True (elevated)
#   HomeSOC.exe        the app (window + tray + toasts); runs as the normal user
# installer\homesoc.iss then packs dist\HomeSOC\ into HomeSOC-Setup.exe.
#
# Bundled: config.yaml, data\allowlist.txt (+ the two other data lists the agent reads),
# models\dga.joblib, models\flow.joblib, app\ui\. At runtime the agent copies them into the
# writable data root %PROGRAMDATA%\HomeSOC (agent/config.py: seed_data_root).
# NEVER bundled (§7, §9): lab\ (fake malware, lab C2, traffic generators), the training
# scripts models\train_*.py, any DGA generator source (baderj, GPL-2.0, training only), tests\.
# tests/test_installer.py parses this file and checks both lists.

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821  (SPECPATH is set by PyInstaller)

AGENT_DATAS = [
    (str(ROOT / "config.yaml"), "."),
    (str(ROOT / "data" / "allowlist.txt"), "data"),
    (str(ROOT / "data" / "test_intel.txt"), "data"),
    (str(ROOT / "data" / "domain_allowlist.txt"), "data"),
    (str(ROOT / "models" / "dga.joblib"), "models"),
    (str(ROOT / "models" / "flow.joblib"), "models"),
]
APP_DATAS = [
    (str(ROOT / "config.yaml"), "."),  # read by the app before the agent seeds the data root
    (str(ROOT / "app" / "ui"), "app/ui"),
]

# Never pulled in, even if something imports them by accident.
EXCLUDES = [
    "lab",
    "tests",
    "models",  # models/train_dga.py, models/train_flow.py (training only)
    "pytest",
    "ruff",
    "tranco",  # used by training only
]

nfstream_datas, nfstream_binaries, nfstream_hidden = collect_all("nfstream")

AGENT_HIDDEN = (
    nfstream_hidden
    + collect_submodules("uvicorn")
    # the joblib models unpickle scikit-learn estimators that nothing imports statically
    + collect_submodules("sklearn", filter=lambda name: ".tests" not in name)
)
APP_HIDDEN = ["pystray._win32"]  # pystray picks its backend at runtime

agent_a = Analysis(  # noqa: F821
    [str(ROOT / "installer" / "agent_entry.py")],
    pathex=[str(ROOT)],
    binaries=nfstream_binaries,
    datas=AGENT_DATAS + nfstream_datas,
    hiddenimports=AGENT_HIDDEN,
    excludes=EXCLUDES + ["webview", "pystray"],
    noarchive=False,
)
agent_pyz = PYZ(agent_a.pure)  # noqa: F821
agent_exe = EXE(  # noqa: F821
    agent_pyz,
    agent_a.scripts,
    [],
    exclude_binaries=True,
    name="HomeSOC-Agent",
    console=False,
    uac_admin=True,
    upx=False,
)

app_a = Analysis(  # noqa: F821
    [str(ROOT / "installer" / "app_entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=APP_DATAS,
    hiddenimports=APP_HIDDEN,
    excludes=EXCLUDES + ["nfstream", "sklearn", "pandas", "uvicorn", "fastapi"],
    noarchive=False,
)
app_pyz = PYZ(app_a.pure)  # noqa: F821
app_exe = EXE(  # noqa: F821
    app_pyz,
    app_a.scripts,
    [],
    exclude_binaries=True,
    name="HomeSOC",
    console=False,
    uac_admin=False,
    upx=False,
)

coll = COLLECT(  # noqa: F821
    agent_exe,
    agent_a.binaries,
    agent_a.datas,
    app_exe,
    app_a.binaries,
    app_a.datas,
    upx=False,
    name="HomeSOC",
)
