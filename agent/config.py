"""Load and validate ``config.yaml`` and ``data/allowlist.txt``.

Pure Python, no Windows-only imports, so it can be tested on any OS (CLAUDE.md §10).

Two roots (both the repo root when running from source, so nothing changes there):

- :data:`BUNDLE_ROOT`: read-only files shipped with the program. Frozen by PyInstaller
  (``installer/homesoc.spec``) this is ``sys._MEIPASS``, inside ``C:\\Program Files\\HomeSOC``.
- :data:`REPO_ROOT`: the data root every relative path in ``config.yaml`` resolves against
  (store, ``data/cache``, evidence, ring pcap, models, allowlists). Frozen this is the writable
  ``%PROGRAMDATA%\\HomeSOC``, shared by the agent (SYSTEM / admin) and the app (normal user);
  :func:`seed_data_root` copies the bundled files there on agent start.
"""

from __future__ import annotations

import filecmp
import logging
import os
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

APP_DIR_NAME = "HomeSOC"
SOURCE_ROOT: Path = Path(__file__).resolve().parent.parent
# Seeded into the data root only when missing: the user may edit them (capture.interface, ...).
SEED_IF_MISSING: tuple[str, ...] = (
    "config.yaml",
    "data/allowlist.txt",
    "data/test_intel.txt",
    "data/domain_allowlist.txt",
)
# Seeded when missing or different, so a reinstall with retrained models takes effect.
SEED_REFRESH: tuple[str, ...] = ("models/dga.joblib", "models/flow.joblib")
SEED_DIRS: tuple[str, ...] = ("data/cache",)


def bundle_root_for(frozen: bool, meipass: str | None, source_root: Path = SOURCE_ROOT) -> Path:
    """Where the shipped read-only files live: ``sys._MEIPASS`` when frozen, else the repo."""
    if frozen and meipass:
        return Path(meipass)
    return source_root


def data_root_for(frozen: bool, env: Mapping[str, str], source_root: Path = SOURCE_ROOT) -> Path:
    """The writable data root: ``%PROGRAMDATA%\\HomeSOC`` when frozen, else the repo root."""
    if not frozen:
        return source_root
    base = env.get("PROGRAMDATA") or env.get("ALLUSERSPROFILE") or r"C:\ProgramData"
    return Path(base) / APP_DIR_NAME


FROZEN: bool = bool(getattr(sys, "frozen", False))
BUNDLE_ROOT: Path = bundle_root_for(FROZEN, getattr(sys, "_MEIPASS", None))
REPO_ROOT: Path = data_root_for(FROZEN, os.environ)
DEFAULT_CONFIG_PATH: Path = REPO_ROOT / "config.yaml"
DEFAULT_ALLOWLIST_PATH: Path = REPO_ROOT / "data" / "allowlist.txt"
DEFAULT_STORE_PATH: Path = REPO_ROOT / "data" / "homesoc.db"


def default_config_path(data_root: Path | None = None, bundle_root: Path | None = None) -> Path:
    """``config.yaml`` in the data root, or the bundled copy if the data root has none yet.

    The fallback lets the app (normal user) start before the agent has seeded the data root.
    """
    data_root = REPO_ROOT if data_root is None else data_root
    bundle_root = BUNDLE_ROOT if bundle_root is None else bundle_root
    path = data_root / "config.yaml"
    if path.is_file():
        return path
    bundled = bundle_root / "config.yaml"
    return bundled if bundled.is_file() else path


def seed_data_root(bundle_root: Path | None = None, data_root: Path | None = None) -> list[Path]:
    """Copy the bundled config, allowlists and models into the data root (agent start).

    ``config.yaml`` and the ``data/*.txt`` lists are copied only when missing (the user may
    have edited them); the models are copied when missing or different. Also creates
    ``data/cache``. A no-op when both roots are the same (running from source).

    Returns:
        The data-root files that were written.
    """
    bundle_root = BUNDLE_ROOT if bundle_root is None else bundle_root
    data_root = REPO_ROOT if data_root is None else data_root
    if bundle_root.resolve() == data_root.resolve():
        return []
    written: list[Path] = []
    for rel in SEED_DIRS:
        (data_root / rel).mkdir(parents=True, exist_ok=True)
    for rel, refresh in [(r, False) for r in SEED_IF_MISSING] + [(r, True) for r in SEED_REFRESH]:
        src, dst = bundle_root / rel, data_root / rel
        if not src.is_file():
            logger.warning("Bundled file %s is missing; not seeding %s", src, dst)
            continue
        if dst.is_file() and not (refresh and not filecmp.cmp(src, dst, shallow=False)):
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        written.append(dst)
        logger.info("Seeded %s from %s", dst, src)
    return written

ALLOWED_MODES: tuple[str, ...] = ("off", "notify", "auto")
REQUIRED_SECTIONS: tuple[str, ...] = (
    "mode",
    "capture",
    "calibration",
    "detectors",
    "scoring",
    "api",
)
LOOPBACK_HOST = "127.0.0.1"  # the API must never bind anywhere else (§9.5)
COMMENT_PREFIX = "#"


class ConfigError(ValueError):
    """Raised when ``config.yaml`` is missing, malformed or holds invalid values."""


def load(path: str | Path | None = None) -> dict[str, Any]:
    """Read and validate the config file.

    Args:
        path: Path to a YAML config. Defaults to :func:`default_config_path` (``config.yaml``
            at the repo root when running from source).

    Returns:
        The parsed config as a dict.

    Raises:
        ConfigError: If the file is missing, not a mapping, lacks a required section,
            has an invalid ``mode``, or binds the API to a non-loopback host.
    """
    config_path = Path(path) if path is not None else default_config_path()
    try:
        text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {config_path} is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"Config file {config_path} must contain a YAML mapping at the top level")

    # YAML 1.1 reads a bare `mode: off` as the boolean False; treat it as the "off" mode.
    if data.get("mode") is False:
        data["mode"] = "off"

    _validate(data, config_path)
    logger.debug("Loaded config from %s (mode=%s)", config_path, data["mode"])
    return data


def _validate(data: dict[str, Any], config_path: Path) -> None:
    missing = [key for key in REQUIRED_SECTIONS if key not in data]
    if missing:
        raise ConfigError(
            f"Config file {config_path} is missing required key(s): {', '.join(missing)}"
        )

    mode = data["mode"]
    if mode not in ALLOWED_MODES:
        raise ConfigError(
            f"Invalid mode {mode!r} in {config_path}; allowed modes are: {', '.join(ALLOWED_MODES)}"
        )

    api = data["api"]
    if not isinstance(api, dict) or api.get("host") != LOOPBACK_HOST:
        host = api.get("host") if isinstance(api, dict) else None
        raise ConfigError(
            f"Invalid api.host {host!r} in {config_path}; the API must bind to {LOOPBACK_HOST} only"
        )

    capture = data["capture"]
    if not isinstance(capture, dict) or not capture.get("interface"):
        raise ConfigError(f"Config file {config_path} must set capture.interface")


def store_path(cfg: dict[str, Any]) -> Path:
    """The SQLite store path from ``store.path`` (relative paths are under the repo root).

    Falls back to ``data/homesoc.db`` when the ``store`` section or key is absent.
    """
    store_cfg = cfg.get("store")
    value = store_cfg.get("path") if isinstance(store_cfg, dict) else None
    if not value:
        return DEFAULT_STORE_PATH
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


@dataclass(frozen=True)
class Allowlist:
    """Exe names that are never auto-quarantined (§6.4). Matching is case-insensitive."""

    names: frozenset[str]

    def __contains__(self, exe_name: object) -> bool:
        return isinstance(exe_name, str) and exe_name.strip().casefold() in self.names

    def __len__(self) -> int:
        return len(self.names)


def load_allowlist(path: str | Path | None = None) -> Allowlist:
    """Read an allowlist file: one exe name per line, ``#`` comments and blank lines ignored.

    Args:
        path: Path to the allowlist. Defaults to ``data/allowlist.txt`` at the repo root.

    Returns:
        An :class:`Allowlist` holding the case-folded exe names.
    """
    allowlist_path = Path(path) if path is not None else DEFAULT_ALLOWLIST_PATH
    names: set[str] = set()
    for raw_line in allowlist_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(COMMENT_PREFIX):
            continue
        names.add(line.casefold())
    logger.debug("Loaded %d allowlisted exe names from %s", len(names), allowlist_path)
    return Allowlist(names=frozenset(names))
