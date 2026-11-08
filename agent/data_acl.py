"""Lock the installed data root ``%PROGRAMDATA%\\HomeSOC`` to SYSTEM and Administrators (#72).

``C:\\ProgramData`` lets every local account read (and create folders in) a new subfolder, so
without this the rolling packet capture, ``homesoc.db``, ``agent.log`` and the evidence pcaps
would be readable by any user or any malware running as the user.

The ACL (the installer, ``installer/homesoc.iss``, applies the same one):

- the data root: no inheritance from ``C:\\ProgramData``; SYSTEM and Administrators full
  control, inherited by everything below; owner Administrators (a folder made by a user before
  the fix keeps no owner rights); no explicit Users / Authenticated Users / Everyone /
  CREATOR OWNER entries anywhere in the tree;
- ``data\\evidence`` only: Users read + execute, inherited, so the signed-in user can open an
  exported pcap in Wireshark without admin (Windows' "bypass traverse checking", granted to
  everyone by default, lets them reach it by its full path).

Only the installed (frozen) agent runs this: from source the data root is the repo and its
ACLs are never touched (:func:`should_secure`). Every ``icacls`` call is an argument list (never
a shell) through an injected ``run`` (default ``subprocess.run``), with well-known SIDs so it
works on non-English Windows; tests run on any OS.

Failure policy (``data_acl.refuse_on_failure`` in ``config.yaml``, default false): a failed
``icacls`` call is logged as an ERROR and the agent runs on, so a demo is never bricked by it;
with ``true`` the agent exits instead (``agent.main.main``).
"""

from __future__ import annotations

import logging
import os
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path, PurePath
from typing import Any

logger = logging.getLogger(__name__)

Run = Callable[..., Any]  # subprocess.run-like: (args, **kwargs) -> CompletedProcess

# Well-known SIDs (``*`` = numeric SID for icacls): the same on every Windows language.
SID_SYSTEM = "*S-1-5-18"
SID_ADMINISTRATORS = "*S-1-5-32-544"
SID_USERS = "*S-1-5-32-545"
SID_AUTHENTICATED_USERS = "*S-1-5-11"
SID_EVERYONE = "*S-1-1-0"
SID_CREATOR_OWNER = "*S-1-3-0"
# Never granted anything explicitly anywhere in the data root (evidence's Users RX is re-added).
BROAD_SIDS: tuple[str, ...] = (SID_USERS, SID_AUTHENTICATED_USERS, SID_EVERYONE, SID_CREATOR_OWNER)
FULL_INHERITED = "(OI)(CI)F"   # full control, inherited by subfolders and files
READ_INHERITED = "(OI)(CI)RX"  # read + execute, inherited by subfolders and files

DEFAULT_TIMEOUT_S = 30.0  # used when config.yaml lacks data_acl.timeout_s
DEFAULT_REFUSE_ON_FAILURE = False  # used when config.yaml lacks data_acl.refuse_on_failure


def icacls_path(env: Mapping[str, str]) -> str:
    """``%SystemRoot%\\System32\\icacls.exe`` (an absolute path: no PATH lookup)."""
    system_root = env.get("SystemRoot") or env.get("SYSTEMROOT") or r"C:\Windows"
    return str(Path(system_root) / "System32" / "icacls.exe")


def acl_commands(data_root: PurePath, evidence_dir: PurePath | None,
                 icacls: str = "icacls.exe") -> list[list[str]]:
    """The ``icacls`` argument lists, in order, that lock ``data_root``.

    1. cut inheritance from ``C:\\ProgramData`` and grant only SYSTEM + Administrators full
       control (inherited by the whole tree) - first, so the main hole closes first;
    2. make Administrators the owner of the whole tree (an owner can always rewrite an ACL);
    3. remove explicit Users / Authenticated Users / Everyone / CREATOR OWNER grants anywhere;
    4. grant Users read + execute on ``evidence_dir`` (inherited by the pcaps written there),
       when given.
    """
    root = str(data_root)
    commands = [
        [icacls, root, "/inheritance:r", "/grant:r",
         f"{SID_SYSTEM}:{FULL_INHERITED}", f"{SID_ADMINISTRATORS}:{FULL_INHERITED}", "/Q"],
        [icacls, root, "/setowner", SID_ADMINISTRATORS, "/T", "/Q"],
        [icacls, root, "/remove:g", *BROAD_SIDS, "/T", "/Q"],
    ]
    if evidence_dir is not None:
        commands.append([icacls, str(evidence_dir), "/grant:r",
                         f"{SID_USERS}:{READ_INHERITED}", "/Q"])
    return commands


def should_secure(frozen: bool, data_root: Path, bundle_root: Path) -> bool:
    """Only the installed agent, whose data root is not the bundle (never the dev repo)."""
    return bool(frozen) and data_root.resolve() != bundle_root.resolve()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def secure_data_root(data_root: Path, evidence_dir: Path | None, *, run: Run | None = None,
                     icacls: str | None = None,
                     timeout_s: float = DEFAULT_TIMEOUT_S) -> bool:
    """Create ``data_root`` and ``evidence_dir`` if missing and apply :func:`acl_commands`.

    ``evidence_dir`` outside ``data_root`` (an absolute ``evidence.evidence_dir``) is not
    made readable: a warning is logged and only the data root is locked.

    Returns:
        True if every ``icacls`` call succeeded. Each failure (non-zero exit, timeout, missing
        icacls, an OS error) is logged as an ERROR; the remaining calls still run.
    """
    run = run if run is not None else subprocess.run
    if icacls is None:
        icacls = icacls_path(os.environ)
    data_root.mkdir(parents=True, exist_ok=True)
    if evidence_dir is not None and not _inside(evidence_dir, data_root):
        logger.warning("Evidence folder %s is outside the data folder %s; it is not made "
                       "readable by Users", evidence_dir, data_root)
        evidence_dir = None
    if evidence_dir is not None:
        evidence_dir.mkdir(parents=True, exist_ok=True)

    ok = True
    for args in acl_commands(data_root, evidence_dir, icacls):
        try:
            result = run(args, check=False, capture_output=True, text=True, errors="replace",
                         timeout=timeout_s)
        except subprocess.TimeoutExpired:
            logger.error("Locking the data folder: %s timed out after %s s", args, timeout_s)
            ok = False
            continue
        except OSError as exc:  # icacls missing / not runnable
            logger.error("Locking the data folder: could not run %s: %s", args, exc)
            ok = False
            continue
        if result.returncode != 0:
            output = " ".join(str(s).strip() for s in (result.stdout, result.stderr) if s)
            logger.error("Locking the data folder: %s exited with %s: %s",
                         args, result.returncode, output)
            ok = False
    if ok:
        logger.info("Data folder %s locked to SYSTEM and Administrators (Users may read %s)",
                    data_root, evidence_dir)
    else:
        logger.error("Could not fully lock the data folder %s: other accounts may be able to "
                     "read captured traffic. Reinstall, or run the icacls commands in README "
                     "from an admin PowerShell", data_root)
    return ok


def settings(cfg: Mapping[str, Any]) -> tuple[float, bool]:
    """``(timeout_s, refuse_on_failure)`` from the ``data_acl`` section of ``config.yaml``."""
    section = cfg.get("data_acl") or {}
    return (float(section.get("timeout_s", DEFAULT_TIMEOUT_S)),
            bool(section.get("refuse_on_failure", DEFAULT_REFUSE_ON_FAILURE)))


def secure_installed_data_root(cfg: Mapping[str, Any], evidence_dir: Path, *, frozen: bool,
                               data_root: Path, bundle_root: Path,
                               run: Run | None = None, icacls: str | None = None) -> bool | None:
    """:func:`secure_data_root` for the installed agent; ``None`` (nothing done) from source."""
    if not should_secure(frozen, data_root, bundle_root):
        logger.debug("Running from source: data folder %s ACL left alone", data_root)
        return None
    timeout_s, _ = settings(cfg)
    return secure_data_root(data_root, evidence_dir, run=run, icacls=icacls, timeout_s=timeout_s)
