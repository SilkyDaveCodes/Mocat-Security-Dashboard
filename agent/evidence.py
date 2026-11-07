"""Rolling packet capture and per-alert pcap export (CLAUDE.md §6.8).

The agent keeps a ring buffer of the last few capture files with ``dumpcap`` and, when the user
asks for evidence on an alert, cuts the packets to / from the alert's IP out of it with
``tshark``::

    dumpcap -i <iface> -b filesize:20000 -b files:5 -w data/ring.pcapng
    tshark -r data/ring.pcapng -Y "ip.addr==<ip>" -w data/evidence/<alert_id>.pcap

Design
    * Every command is an argument list run without a shell (``Popen`` / ``run`` with
      ``shell`` left at ``False``), so nothing in an argument is ever interpreted. The alert id
      and the IP are still validated before any command is built: the id must match
      :data:`ALERT_ID_RE` and the output path must resolve inside the evidence directory; the
      IP must parse with :mod:`ipaddress` and is canonicalised (no IPv6 scope ids).
    * The process launchers are injected (``popen`` for dumpcap, ``run`` for tshark/mergecap);
      the defaults look up ``subprocess.Popen`` / ``subprocess.run`` at call time, so tests can
      also patch those names. Tests run on any OS without Wireshark.
    * dumpcap never stops the agent: a missing dumpcap is logged as a warning and the agent runs
      without evidence capture. On shutdown it is terminated, waited for, then killed.
    * Ring files: with ``-b`` dumpcap does not write ``ring.pcapng`` itself but
      ``ring_00001_20261107120000.pcapng``, ``ring_00002_...`` and so on (the oldest deleted after
      ``files``). :func:`ring_files` finds them (plus a literal ``ring.pcapng`` if one exists),
      oldest first. With one file, tshark runs once and writes the evidence file directly (the
      exact §6.8 command). With several, tshark filters each file into a temp part inside the
      evidence directory and ``mergecap`` merges the parts (chronologically) into the evidence
      file; the parts are then removed.
    * IPv4 targets filter on ``ip.addr==<ip>`` (§6.8); an IPv6 target uses ``ipv6.addr==<ip>``,
      tshark's field for IPv6 addresses.
    * tshark (and mergecap) write pcapng unless told otherwise; the file keeps the ``.pcap`` name
      from §6.8 and Wireshark opens it either way.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent import config as config_module
from agent.events import Alert

logger = logging.getLogger(__name__)

ALERT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
"""Alert ids that may become a file name (scoring uses ``uuid4().hex``)."""

EVIDENCE_SUFFIX = ".pcap"

# Defaults used when config.yaml lacks a key in the ``evidence`` section.
DEFAULT_DUMPCAP = "dumpcap"
DEFAULT_TSHARK = "tshark"
DEFAULT_MERGECAP = "mergecap"
DEFAULT_RING_PATH = "data/ring.pcapng"
DEFAULT_EVIDENCE_DIR = "data/evidence"
DEFAULT_RING_FILESIZE_KB = 20000
DEFAULT_RING_FILES = 5
DEFAULT_EXPORT_TIMEOUT_S = 60.0
DEFAULT_STOP_TIMEOUT_S = 5.0

Popen = Callable[..., Any]  # subprocess.Popen-like: (args, **kwargs) -> process
Run = Callable[..., Any]  # subprocess.run-like: (args, **kwargs) -> CompletedProcess


class EvidenceError(Exception):
    """tshark / mergecap failed (non-zero exit or timeout)."""


class EvidenceUnavailable(EvidenceError):
    """Evidence can't be exported right now: no ring files yet, or tshark/mergecap missing."""


class UnsafeAlertIdError(ValueError):
    """The alert id is not safe to use as a file name."""


class NoTargetIpError(ValueError):
    """None of the alert's signals is about an IP address."""


# --- settings -----------------------------------------------------------------------------


def _repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else config_module.REPO_ROOT / path


@dataclass(frozen=True)
class EvidenceSettings:
    """The ``evidence`` section of ``config.yaml`` plus ``capture.interface``."""

    interface: str
    ring_path: Path
    evidence_dir: Path
    dumpcap: str = DEFAULT_DUMPCAP
    tshark: str = DEFAULT_TSHARK
    mergecap: str = DEFAULT_MERGECAP
    ring_filesize_kb: int = DEFAULT_RING_FILESIZE_KB
    ring_files: int = DEFAULT_RING_FILES
    export_timeout_s: float = DEFAULT_EXPORT_TIMEOUT_S
    stop_timeout_s: float = DEFAULT_STOP_TIMEOUT_S

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> EvidenceSettings:
        ev = cfg.get("evidence") or {}
        return cls(
            interface=str(cfg["capture"]["interface"]),
            ring_path=_repo_path(ev.get("ring_path", DEFAULT_RING_PATH)),
            evidence_dir=_repo_path(ev.get("evidence_dir", DEFAULT_EVIDENCE_DIR)),
            dumpcap=str(ev.get("dumpcap", DEFAULT_DUMPCAP)),
            tshark=str(ev.get("tshark", DEFAULT_TSHARK)),
            mergecap=str(ev.get("mergecap", DEFAULT_MERGECAP)),
            ring_filesize_kb=int(ev.get("ring_filesize_kb", DEFAULT_RING_FILESIZE_KB)),
            ring_files=int(ev.get("ring_files", DEFAULT_RING_FILES)),
            export_timeout_s=float(ev.get("export_timeout_s", DEFAULT_EXPORT_TIMEOUT_S)),
            stop_timeout_s=float(ev.get("stop_timeout_s", DEFAULT_STOP_TIMEOUT_S)),
        )


# --- validation ---------------------------------------------------------------------------


def validate_alert_id(alert_id: str) -> str:
    """``alert_id`` if it is safe as a file name, else :class:`UnsafeAlertIdError`."""
    if not isinstance(alert_id, str) or not ALERT_ID_RE.fullmatch(alert_id):
        raise UnsafeAlertIdError(f"Unsafe alert id {alert_id!r}")
    return alert_id


def canonical_ip(value: str) -> str | None:
    """``value`` as a canonical IP string, or ``None`` if it is not a plain IP address."""
    if not isinstance(value, str):
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if getattr(ip, "scope_id", None):  # "fe80::1%eth0": not a plain address
        return None
    return str(ip)


def alert_target_ip(alert: Alert) -> str:
    """The first signal target (in order) that is an IP address, canonicalised.

    Domain targets (DGA signals) are skipped. Raises :class:`NoTargetIpError` if none is an IP.
    """
    for signal in alert.signals:
        ip = canonical_ip(signal.target)
        if ip is not None:
            return ip
    raise NoTargetIpError(f"Alert {alert.id} has no signal about an IP address")


def evidence_path(evidence_dir: Path, alert_id: str) -> Path:
    """``<evidence_dir>/<alert_id>.pcap``; refuses an id or path that leaves the directory."""
    validate_alert_id(alert_id)
    root = evidence_dir.resolve()
    out = (root / f"{alert_id}{EVIDENCE_SUFFIX}").resolve()
    if out.parent != root:
        raise UnsafeAlertIdError(f"Evidence path for {alert_id!r} leaves {root}")
    return out


def display_filter(ip: str) -> str:
    """``ip.addr==<ip>`` (IPv4, §6.8) or ``ipv6.addr==<ip>``. ``ip`` must be canonical."""
    field = "ipv6.addr" if ipaddress.ip_address(ip).version == 6 else "ip.addr"
    return f"{field}=={ip}"


# --- commands -----------------------------------------------------------------------------


def build_dumpcap_args(settings: EvidenceSettings) -> list[str]:
    """``dumpcap -i <iface> -b filesize:<kb> -b files:<n> -w <ring_path>`` (§6.8)."""
    return [
        settings.dumpcap,
        "-i", settings.interface,
        "-b", f"filesize:{settings.ring_filesize_kb}",
        "-b", f"files:{settings.ring_files}",
        "-w", str(settings.ring_path),
    ]


def build_tshark_args(tshark: str, ring_file: Path, ip: str, out: Path) -> list[str]:
    """``tshark -r <ring_file> -Y ip.addr==<ip> -w <out>`` (§6.8). ``ip`` must be canonical."""
    return [tshark, "-r", str(ring_file), "-Y", display_filter(ip), "-w", str(out)]


def build_mergecap_args(mergecap: str, parts: Sequence[Path], out: Path) -> list[str]:
    """``mergecap -w <out> <part>...``: merges the parts chronologically."""
    return [mergecap, "-w", str(out), *(str(p) for p in parts)]


def ring_files(ring_path: Path) -> list[Path]:
    """The ring buffer's files, oldest first.

    dumpcap names them ``<stem>_<NNNNN>_<YYYYMMDDhhmmss><suffix>``; they are ordered by the
    file number. A literal ``ring_path`` (no ``-b``) comes first if it exists.
    """
    stem, suffix = ring_path.stem, ring_path.suffix
    pattern = re.compile(rf"^{re.escape(stem)}_(\d+)_(\d{{14}}){re.escape(suffix)}$")
    numbered: list[tuple[int, Path]] = []
    if ring_path.parent.is_dir():
        for path in ring_path.parent.iterdir():
            match = pattern.fullmatch(path.name)
            if match and path.is_file():
                numbered.append((int(match.group(1)), path))
    files = [p for _, p in sorted(numbered)]
    if ring_path.is_file():
        files.insert(0, ring_path)
    return files


# --- rolling capture ----------------------------------------------------------------------


class RingCapture:
    """The ``dumpcap`` ring buffer: :meth:`start` with the agent, :meth:`stop` on shutdown."""

    def __init__(self, settings: EvidenceSettings, popen: Popen | None = None) -> None:
        self.settings = settings
        self._popen = popen if popen is not None else lambda *a, **k: subprocess.Popen(*a, **k)
        self._proc: Any = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self) -> bool:
        """Start dumpcap. A missing dumpcap is logged and ``False`` is returned; never raises."""
        args = build_dumpcap_args(self.settings)
        try:
            self.settings.ring_path.parent.mkdir(parents=True, exist_ok=True)
            self._proc = self._popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, ValueError) as exc:
            logger.warning("Rolling capture not started (%s); evidence export is unavailable. "
                           "Is Wireshark installed and evidence.dumpcap right?", exc)
            self._proc = None
            return False
        logger.info("Rolling capture started on %r -> %s", self.settings.interface,
                    self.settings.ring_path)
        return True

    def stop(self) -> None:
        """Terminate dumpcap; kill it if it doesn't exit within ``stop_timeout_s``."""
        proc, self._proc = self._proc, None
        if proc is None:
            return
        code = proc.poll()
        if code is not None:
            logger.warning("dumpcap had already exited with code %s", code)
            return
        proc.terminate()
        try:
            proc.wait(timeout=self.settings.stop_timeout_s)
        except subprocess.TimeoutExpired:
            logger.warning("dumpcap did not stop within %.1f s; killing it",
                           self.settings.stop_timeout_s)
            proc.kill()
            proc.wait()
        logger.info("Rolling capture stopped")


def start_ring_capture(cfg: dict[str, Any], popen: Popen | None = None) -> RingCapture:
    """Build and start the ring capture from config (``run_agent``'s ``ring_starter``)."""
    ring = RingCapture(EvidenceSettings.from_config(cfg), popen=popen)
    ring.start()
    return ring


# --- export -------------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceResult:
    alert_id: str
    ip: str
    path: Path
    ring_files: int

    def as_dict(self) -> dict[str, Any]:
        size = self.path.stat().st_size if self.path.exists() else 0
        return {"alert_id": self.alert_id, "ip": self.ip, "path": str(self.path),
                "bytes": size, "ring_files": self.ring_files}


class EvidenceExporter:
    """Writes ``<evidence_dir>/<alert_id>.pcap`` with the packets to / from the alert's IP."""

    def __init__(self, settings: EvidenceSettings, run: Run | None = None) -> None:
        self.settings = settings
        self._run = run if run is not None else lambda *a, **k: subprocess.run(*a, **k)
        self._lock = threading.Lock()  # one export at a time: same output file, heavy work

    @classmethod
    def from_config(cls, cfg: dict[str, Any], run: Run | None = None) -> EvidenceExporter:
        return cls(EvidenceSettings.from_config(cfg), run=run)

    def export(self, alert: Alert) -> EvidenceResult:
        """Export the evidence for ``alert``.

        Raises:
            UnsafeAlertIdError: the id can't be a file name (before anything runs).
            NoTargetIpError: no signal target is an IP (before anything runs).
            EvidenceUnavailable: no ring files, or tshark / mergecap is missing.
            EvidenceError: tshark / mergecap failed or timed out.
        """
        out = evidence_path(self.settings.evidence_dir, alert.id)
        ip = alert_target_ip(alert)
        with self._lock:
            files = ring_files(self.settings.ring_path)
            if not files:
                raise EvidenceUnavailable("No rolling capture files yet; is dumpcap running?")
            out.parent.mkdir(parents=True, exist_ok=True)
            if len(files) == 1:
                self._call(build_tshark_args(self.settings.tshark, files[0], ip, out))
            else:
                self._filter_and_merge(files, ip, out)
        logger.info("Evidence for alert %s (%s) written to %s from %d ring file(s)",
                    alert.id, ip, out, len(files))
        return EvidenceResult(alert.id, ip, out, len(files))

    def _filter_and_merge(self, files: list[Path], ip: str, out: Path) -> None:
        with tempfile.TemporaryDirectory(dir=out.parent, prefix=".parts-") as tmp:
            parts = [Path(tmp) / f"part{i:03d}.pcapng" for i in range(len(files))]
            for ring_file, part in zip(files, parts, strict=True):
                self._call(build_tshark_args(self.settings.tshark, ring_file, ip, part))
            self._call(build_mergecap_args(self.settings.mergecap, parts, out))

    def _call(self, args: list[str]) -> None:
        try:
            result = self._run(args, check=False, capture_output=True, text=True,
                               errors="replace", timeout=self.settings.export_timeout_s)
        except FileNotFoundError as exc:
            logger.error("%s not found: %s", args[0], exc)
            raise EvidenceUnavailable(f"{args[0]} not found; is Wireshark installed?") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.error("%s could not run: %s", args[0], exc)
            raise EvidenceError(f"{args[0]} could not run: {exc}") from exc
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            logger.error("%s exited with %d: %s", args[0], result.returncode, stderr)
            raise EvidenceError(f"{args[0]} exited with {result.returncode}: {stderr}")
