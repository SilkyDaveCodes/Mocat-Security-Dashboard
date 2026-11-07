"""Process context for scoring: exe path, name, risky directory, Authenticode signature, kill.

CLAUDE.md §6.2. This is one of the few modules allowed to run Windows-only code (PowerShell,
§10). Everything that touches the OS goes through ``psutil`` or ``subprocess.run`` at module
level, so the tests patch those two names and run on any OS.

Result type: :class:`ProcInfo` is a frozen dataclass (typed, hashable, immutable, and matches
the dataclass style of ``agent/events.py``), as documented in CLAUDE.md §6.2.
:meth:`ProcInfo.as_dict` gives the plain-dict shape for JSON / the WebSocket.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import PureWindowsPath
from typing import Any

import psutil

logger = logging.getLogger(__name__)

UNKNOWN_NAME = "unknown"  # same default as FlowEvent.process (§5)

# Risky directories (§6.2). Matched on path components, case-insensitively.
DOWNLOADS_DIR = "downloads"
LOCAL_TEMP_PARTS: tuple[str, ...] = ("appdata", "local", "temp")
TEMP_ENV_VARS: tuple[str, ...] = ("TEMP", "TMP")

# Signature check. The path goes into a PowerShell single-quoted literal (see ps_quote).
POWERSHELL_EXE = "powershell"
POWERSHELL_ARGS: tuple[str, ...] = ("-NoProfile", "-NonInteractive", "-Command")
SIGNATURE_CMD_TEMPLATE = (
    "Get-AuthenticodeSignature -LiteralPath {path} | Select-Object -ExpandProperty Status"
)
SIGNATURE_VALID = "Valid"
SIGNATURE_TIMEOUT_S = 15.0  # a hung PowerShell must not stall the caller forever

# PowerShell treats the ASCII apostrophe and these Unicode single quotes as quote characters
# inside a single-quoted string, so every one of them must be doubled to stay literal.
PS_SINGLE_QUOTES: frozenset[str] = frozenset("'\u2018\u2019\u201a\u201b")
FORBIDDEN_PATH_CHARS: frozenset[str] = frozenset("\r\n\x00")

# kill()
KILL_TIMEOUT_S = 3.0  # wait this long after terminate() before escalating to kill()
PROTECTED_PIDS: frozenset[int] = frozenset({0, 4})  # System Idle Process, System


class UnsafePathError(ValueError):
    """Raised when a path contains characters that cannot be passed to PowerShell safely."""


class KillError(RuntimeError):
    """Raised when :func:`kill` is refused or cannot stop the process."""


@dataclass(frozen=True)
class ProcInfo:
    """What we know about one process.

    ``exe_path`` is ``None`` when the process is gone or its path cannot be read
    (``NoSuchProcess`` / ``AccessDenied``). In that case ``in_risky_dir`` and ``signed`` are
    also ``None``, meaning "unknown", so scoring does not treat an unreadable process as
    unsigned. When ``exe_path`` is known, both are real booleans.
    """

    pid: int
    name: str
    exe_path: str | None
    in_risky_dir: bool | None
    signed: bool | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- risky directories -----------------------------------------------------------------------


def _folded_parts(path: str) -> tuple[str, ...]:
    """Windows path components, case-folded. Works on any host OS and accepts ``/`` too."""
    return tuple(part.casefold() for part in PureWindowsPath(path).parts)


def _contains_run(parts: tuple[str, ...], run: tuple[str, ...]) -> bool:
    width = len(run)
    return any(parts[i : i + width] == run for i in range(len(parts) - width + 1))


def _env_temp_dirs() -> list[str]:
    return [value for var in TEMP_ENV_VARS if (value := os.environ.get(var))]


def is_in_risky_dir(exe_path: str, temp_dirs: Iterable[str] | None = None) -> bool:
    """True if ``exe_path`` lives under Downloads, ``AppData\\Local\\Temp`` or a temp dir.

    Args:
        exe_path: A Windows path such as ``C:\\Users\\bob\\Downloads\\x.exe``.
        temp_dirs: Temp folders to treat as risky. Defaults to ``%TEMP%`` / ``%TMP%`` read
            from the environment at call time.

    Only directory components count (not the file name), and they must match whole, so
    ``C:\\Program Files\\DownloadsHelper\\x.exe`` is not risky.
    """
    dir_parts = _folded_parts(exe_path)[:-1]
    if DOWNLOADS_DIR in dir_parts or _contains_run(dir_parts, LOCAL_TEMP_PARTS):
        return True
    dirs = _env_temp_dirs() if temp_dirs is None else list(temp_dirs)
    for temp_dir in dirs:
        temp_parts = _folded_parts(temp_dir)
        if temp_parts and dir_parts[: len(temp_parts)] == temp_parts:
            return True
    return False


# --- signature check -------------------------------------------------------------------------


def ps_quote(value: str) -> str:
    """Return ``value`` as a PowerShell single-quoted string literal.

    Inside single quotes PowerShell expands nothing (no ``$``, backtick or ``;``); the only
    special characters are the single quotes themselves, which are escaped by doubling.

    Raises:
        UnsafePathError: If ``value`` contains a newline, carriage return or NUL.
    """
    if any(ch in FORBIDDEN_PATH_CHARS for ch in value):
        raise UnsafePathError(f"Refusing to pass a path with control characters: {value!r}")
    escaped = "".join(ch * 2 if ch in PS_SINGLE_QUOTES else ch for ch in value)
    return f"'{escaped}'"


def build_signature_command(exe_path: str) -> str:
    """The PowerShell command that prints the Authenticode status of ``exe_path``."""
    return SIGNATURE_CMD_TEMPLATE.format(path=ps_quote(exe_path))


def _cache_key(exe_path: str) -> str:
    return str(PureWindowsPath(exe_path)).casefold()


_signature_cache: dict[str, bool] = {}
_cache_lock = threading.Lock()


def clear_signature_cache() -> None:
    with _cache_lock:
        _signature_cache.clear()


def _run_signature_check(exe_path: str) -> bool | None:
    """Run PowerShell once. Returns the parsed result, or ``None`` if the check itself failed."""
    try:
        cmd = build_signature_command(exe_path)
    except UnsafePathError:
        logger.warning("Not checking signature of unsafe path %r; treating as unsigned", exe_path)
        return False
    try:
        result = subprocess.run(
            [POWERSHELL_EXE, *POWERSHELL_ARGS, cmd],
            check=False,
            capture_output=True,
            text=True,
            # Windows PowerShell 5.1 writes redirected output in the OEM code page, which can
            # differ from Python's locale encoding. Replace undecodable bytes instead of
            # raising (e.g. an error message about C:\Users\Jürgen\...).
            errors="replace",
            timeout=SIGNATURE_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        logger.warning("Signature check for %s could not run: %s", exe_path, exc)
        return None
    if result.returncode != 0:
        logger.warning(
            "Signature check for %s exited with %d: %s",
            exe_path,
            result.returncode,
            (result.stderr or "").strip(),
        )
        return None
    status = (result.stdout or "").strip()
    if not status:
        logger.warning("Signature check for %s printed nothing", exe_path)
        return None
    if status != SIGNATURE_VALID:
        logger.info("Signature of %s is %s", exe_path, status)
    return status == SIGNATURE_VALID


def is_signed(exe_path: str) -> bool:
    """True only if Authenticode status is ``Valid``. Cached by path, case-insensitively.

    A definite status (``Valid``, ``NotSigned``, ``HashMismatch``, ...) is cached. A failed
    check (PowerShell missing, timeout, non-zero exit, empty output) returns ``False`` but is
    not cached, so a transient failure is retried on the next call.
    """
    key = _cache_key(exe_path)
    with _cache_lock:
        cached = _signature_cache.get(key)
    if cached is not None:
        return cached
    result = _run_signature_check(exe_path)
    if result is None:
        return False
    with _cache_lock:
        _signature_cache[key] = result
    return result


# --- info / kill -----------------------------------------------------------------------------


def _read_name(proc: psutil.Process) -> str:
    try:
        return proc.name() or UNKNOWN_NAME
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        logger.debug("Cannot read name of pid %d: %s", proc.pid, exc)
        return UNKNOWN_NAME


def _read_exe(proc: psutil.Process) -> str | None:
    try:
        return proc.exe() or None
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        logger.debug("Cannot read exe path of pid %d: %s", proc.pid, exc)
        return None


def info(pid: int, temp_dirs: Iterable[str] | None = None) -> ProcInfo:
    """Look up a process. Never raises for a vanished or protected process.

    Args:
        pid: Process ID.
        temp_dirs: Passed to :func:`is_in_risky_dir` (defaults to ``%TEMP%`` / ``%TMP%``).
    """
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        logger.debug("Cannot open pid %d: %s", pid, exc)
        return ProcInfo(pid, UNKNOWN_NAME, None, None, None)

    name = _read_name(proc)
    exe_path = _read_exe(proc)
    if exe_path is None:
        return ProcInfo(pid, name, None, None, None)
    return ProcInfo(
        pid=pid,
        name=name,
        exe_path=exe_path,
        in_risky_dir=is_in_risky_dir(exe_path, temp_dirs),
        signed=is_signed(exe_path),
    )


def kill(pid: int, timeout_s: float = KILL_TIMEOUT_S) -> bool:
    """Stop a process: ``terminate()``, then ``kill()`` if it is still alive after ``timeout_s``.

    ONLY the UI's confirm flow may call this, after the user has confirmed (§6.2). Nothing in
    the agent may call it automatically.

    Returns:
        ``True`` if this call stopped the process, ``False`` if it had already exited.

    Raises:
        KillError: For protected PIDs (System, ourselves), on ``AccessDenied``, or if the
            process survives ``kill()``.
    """
    if pid in PROTECTED_PIDS or pid == os.getpid():
        raise KillError(f"Refusing to kill protected pid {pid}")
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=timeout_s)
        except psutil.TimeoutExpired:
            logger.warning("pid %d still alive %.1f s after terminate(); killing", pid, timeout_s)
            proc.kill()
            proc.wait(timeout=timeout_s)
    except psutil.NoSuchProcess:
        logger.info("pid %d already exited; nothing to kill", pid)
        return False
    except psutil.AccessDenied as exc:
        raise KillError(f"Access denied killing pid {pid}") from exc
    except psutil.TimeoutExpired as exc:
        raise KillError(f"pid {pid} survived kill()") from exc
    logger.info("Killed pid %d", pid)
    return True
