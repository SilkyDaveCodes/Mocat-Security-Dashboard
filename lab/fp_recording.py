"""Record normal-use FlowEvents for the false-positive test (ticket #49, docs/fp-test.md).

Run on the Windows VM in an admin terminal (live capture needs Npcap), while you use the PC
normally for an hour::

    .venv\\Scripts\\python -m lab.fp_recording --minutes 60

(default ``--out tests\\fixtures\\normal_use_vm.jsonl``).

It runs the same live capture as the agent (``agent.capture.run``: same interface, NFStream
settings and process lookup from ``config.yaml``) but no detectors, scoring or firewall, so it
can run on its own or next to the agent. Each FlowEvent is written as one JSON line as soon as
it arrives (a crash or Ctrl+C keeps everything recorded so far).

Privacy: a record holds ONLY the keys in :data:`ALLOWED_KEYS` (process names, IPs, hostnames,
plus the non-personal numbers replay needs). Dropped: ``pid``, ``exe_path`` (it holds the
Windows user name), the raw NFStream ``features`` and the ``type`` tag. Every timestamp is
rebased to the moment recording started (``t = 0``), so the file doesn't say when it was
recorded. Hostnames ending in ``.local`` (mDNS names such as ``Jakes-iPhone.local``) are
blanked: they can name a person, and the DGA detector skips them anyway (§6.3), so replay is
unaffected. :func:`personal_data_problems` is the check both the recorder and the tests run.

``seen_ms`` is when the flow reached the agent (NFStream hands a flow over only after it ends).
Replay drives the detectors' clocks from it, so time-windowed logic (anomaly calibration, the
scoring window) behaves as it did live.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path, PureWindowsPath
from typing import Any, TextIO

from agent import capture, config
from agent.events import FlowEvent

logger = logging.getLogger(__name__)

ALLOWED_KEYS: tuple[str, ...] = (
    "seen_ms",     # when the flow reached the agent, ms since recording started
    "ts_ms",       # flow start (FlowEvent.ts_ms), same time base; may be < 0 for a flow that
                   # was already open when recording started
    "end_ms",      # flow end (FlowEvent.end_ms), same time base
    "process",     # exe name only, e.g. "chrome.exe" (never a path)
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "hostname",    # DNS query / TLS SNI, or null
    "app_proto",   # NFStream application_name, or null
    "bytes_out",
    "bytes_in",
    "packets",
    "direction",   # "outbound" | "inbound"
)
"""The only keys a normal-use fixture record may have, in file order. Shared by the recorder,
the replay and ``tests/test_fp_replay.py``."""

INT_KEYS: frozenset[str] = frozenset(
    {"seen_ms", "ts_ms", "end_ms", "src_port", "dst_port", "protocol", "bytes_out", "bytes_in",
     "packets"}
)
OPTIONAL_STR_KEYS: frozenset[str] = frozenset({"hostname", "app_proto"})
DIRECTIONS: frozenset[str] = frozenset({"outbound", "inbound"})
UNKNOWN_PROCESS = "unknown"
REDACTED_HOST_SUFFIXES: tuple[str, ...] = (".local",)

# A value that looks like a Windows path or a user profile path (it would leak the user name).
USER_PATH_PATTERN = re.compile(r"(\\users\\|/users/|\\appdata\\|^[a-z]:[\\/]|\\\\)", re.IGNORECASE)

DEFAULT_OUT = config.REPO_ROOT / "tests" / "fixtures" / "normal_use_vm.jsonl"
DEFAULT_MINUTES = 60.0
MS_PER_S = 1000
REPLAY_PID_BASE = 1000  # replay gives each process name its own fake PID from here
NO_PID = -1


def _now_ms() -> int:
    return int(time.time() * MS_PER_S)


# --- record <-> FlowEvent ---------------------------------------------------------------------


def sanitize_process(name: str | None) -> str:
    """The bare exe name (``C:\\Users\\x\\a.exe`` -> ``a.exe``); empty -> ``"unknown"``."""
    text = (name or "").strip()
    if "\\" in text or "/" in text:
        text = PureWindowsPath(text.replace("/", "\\")).name
    return text or UNKNOWN_PROCESS


def sanitize_hostname(hostname: str | None) -> str | None:
    """``None`` for an empty hostname or a ``.local`` (mDNS) name, else the hostname."""
    host = (hostname or "").strip()
    if not host or host.lower().rstrip(".").endswith(REDACTED_HOST_SUFFIXES):
        return None
    return host


def to_record(event: FlowEvent, t0_ms: int, seen_ms: int) -> dict[str, Any]:
    """One fixture record: only :data:`ALLOWED_KEYS`, times rebased to ``t0_ms``."""
    return {
        "seen_ms": int(seen_ms) - t0_ms,
        "ts_ms": int(event.ts_ms) - t0_ms,
        "end_ms": int(event.end_ms) - t0_ms,
        "process": sanitize_process(event.process),
        "src_ip": str(event.src_ip),
        "src_port": int(event.src_port),
        "dst_ip": str(event.dst_ip),
        "dst_port": int(event.dst_port),
        "protocol": int(event.protocol),
        "hostname": sanitize_hostname(event.hostname),
        "app_proto": (event.app_proto or None),
        "bytes_out": int(event.bytes_out),
        "bytes_in": int(event.bytes_in),
        "packets": int(event.packets),
        "direction": event.direction,
    }


def personal_data_problems(record: dict[str, Any]) -> list[str]:
    """Why ``record`` is not a clean fixture record (empty list = clean).

    Checks: exactly the :data:`ALLOWED_KEYS`, the value types, and that no string value looks
    like a Windows or user-profile path.
    """
    problems: list[str] = []
    extra = sorted(set(record) - set(ALLOWED_KEYS))
    missing = sorted(set(ALLOWED_KEYS) - set(record))
    if extra:
        problems.append(f"keys not allowed: {extra}")
    if missing:
        problems.append(f"keys missing: {missing}")
    for key, value in record.items():
        if key in INT_KEYS:
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(f"{key} must be an int, got {value!r}")
        elif key in OPTIONAL_STR_KEYS:
            if value is not None and not isinstance(value, str):
                problems.append(f"{key} must be a string or null, got {value!r}")
        elif not isinstance(value, str):
            problems.append(f"{key} must be a string, got {value!r}")
        if isinstance(value, str) and USER_PATH_PATTERN.search(value):
            problems.append(f"{key} looks like a Windows/user path: {value!r}")
    if record.get("direction") not in DIRECTIONS:
        problems.append(f"direction must be one of {sorted(DIRECTIONS)}")
    process = record.get("process")
    if isinstance(process, str) and ("\\" in process or "/" in process):
        problems.append(f"process must be an exe name, not a path: {process!r}")
    return problems


def from_record(record: dict[str, Any], pid: int = NO_PID) -> FlowEvent:
    """The FlowEvent a record stands for (``pid`` comes from the replay, not the file)."""
    return FlowEvent(
        ts_ms=record["ts_ms"],
        end_ms=record["end_ms"],
        process=record["process"],
        pid=pid,
        exe_path=None,
        src_ip=record["src_ip"],
        src_port=record["src_port"],
        dst_ip=record["dst_ip"],
        dst_port=record["dst_port"],
        protocol=record["protocol"],
        hostname=record["hostname"],
        app_proto=record["app_proto"],
        bytes_out=record["bytes_out"],
        bytes_in=record["bytes_in"],
        packets=record["packets"],
        direction=record["direction"],
        features={},
    )


def dumps(record: dict[str, Any]) -> str:
    """One JSONL line, keys in :data:`ALLOWED_KEYS` order."""
    return json.dumps({k: record[k] for k in ALLOWED_KEYS}, separators=(",", ":"))


def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Every record of a JSONL fixture (blank lines skipped)."""
    records: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: not valid JSON: {exc}") from exc
    return records


def replay_events(records: Iterable[dict[str, Any]]) -> Iterator[tuple[int, FlowEvent]]:
    """``(seen_ms, FlowEvent)`` in arrival order. Each process name gets one stable fake PID
    (``"unknown"`` gets ``-1``, as live capture does)."""
    pids: dict[str, int] = {}
    for record in sorted(records, key=lambda r: r["seen_ms"]):  # stable: ties keep file order
        name = record["process"]
        if name == UNKNOWN_PROCESS:
            pid = NO_PID
        else:
            pid = pids.setdefault(name, REPLAY_PID_BASE + len(pids))
        yield record["seen_ms"], from_record(record, pid)


# --- live recorder ----------------------------------------------------------------------------


class FixtureWriter:
    """Stands in for the bus in ``capture.run``: writes each FlowEvent as a clean record.

    Sets ``stop_event`` once ``duration_s`` has passed (capture stops at the next flow).
    """

    def __init__(
        self,
        out: TextIO,
        duration_s: float,
        stop_event: threading.Event,
        clock: Callable[[], int] = _now_ms,
    ) -> None:
        self._out = out
        self._clock = clock
        self._t0_ms = clock()
        self._deadline_ms = self._t0_ms + int(duration_s * MS_PER_S)
        self._stop_event = stop_event
        self.written = 0
        self.skipped = 0

    def publish_threadsafe(self, event: Any) -> None:
        if not isinstance(event, FlowEvent):
            return
        now = self._clock()
        if now >= self._deadline_ms:
            self._stop_event.set()
            return
        record = to_record(event, self._t0_ms, now)
        problems = personal_data_problems(record)
        if problems:  # never write a record that fails the privacy check
            self.skipped += 1
            logger.warning("Skipping a flow from %s: %s", record["process"], "; ".join(problems))
            return
        self._out.write(dumps(record) + "\n")
        self._out.flush()
        self.written += 1


def record(
    cfg: dict[str, Any],
    out_path: str | Path,
    duration_s: float,
    *,
    overwrite: bool = False,
    clock: Callable[[], int] = _now_ms,
    **capture_kwargs: Any,
) -> int:
    """Capture live flows into ``out_path`` for ``duration_s`` seconds. Returns records written.

    ``capture_kwargs`` go to :func:`agent.capture.run` (``streamer_factory``,
    ``local_addresses``, ``process_fallback``); tests pass fakes there.

    Raises:
        FileExistsError: If ``out_path`` exists and ``overwrite`` is False.
    """
    path = Path(out_path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (pass --force to overwrite it)")
    path.parent.mkdir(parents=True, exist_ok=True)
    stop_event = threading.Event()
    with path.open("w", encoding="utf-8", newline="\n") as out:
        writer = FixtureWriter(out, duration_s, stop_event, clock=clock)
        try:
            capture.run(writer, cfg, stop_event=stop_event, **capture_kwargs)  # type: ignore[arg-type]
        except KeyboardInterrupt:
            logger.info("Recording stopped by Ctrl+C")
    logger.info("Wrote %d flow record(s) to %s (%d skipped)", writer.written, path, writer.skipped)
    return writer.written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record normal-use FlowEvents for the FP test.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="JSONL fixture to write (default: tests/fixtures/normal_use_vm.jsonl)")
    parser.add_argument("--minutes", type=float, default=DEFAULT_MINUTES,
                        help="how long to record (default: 60)")
    parser.add_argument("--config", type=Path, default=None, help="config.yaml to use")
    parser.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        cfg = config.load(args.config)
        logger.info("Recording on %r for %.0f min into %s (Ctrl+C stops early)",
                    cfg["capture"]["interface"], args.minutes, args.out)
        record(cfg, args.out, args.minutes * 60, overwrite=args.force)
    except (config.ConfigError, capture.CaptureError, FileExistsError) as exc:
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
