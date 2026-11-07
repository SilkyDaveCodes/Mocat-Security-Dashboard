"""Live capture: NFStream flows -> :class:`FlowEvent` on the bus (CLAUDE.md §6.1).

The NFlow -> FlowEvent mapping lives in the pure function :func:`to_flow_event`, so it can be
unit-tested on any OS with fake flow objects (e.g. ``types.SimpleNamespace``).

NFStream is Windows/VM-only for this project. It is imported lazily inside :func:`make_streamer`,
so ``import agent.capture`` (and the test suite) works without it installed. If it is missing at
run time, :func:`make_streamer` raises :class:`CaptureError` with an install hint.

Threading: iterating an ``NFStreamer`` is synchronous and blocks while waiting for flows, so
:func:`run` must run in its own thread (e.g. ``asyncio.to_thread`` or ``threading.Thread``), never
on the event-loop thread. It publishes with ``bus.publish_threadsafe`` as ``agent/bus.py``
requires for non-loop threads.

Manual check on the Windows VM (admin terminal)::

    .venv\\Scripts\\python -m agent.capture
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any, Literal

from agent import config
from agent.bus import Bus
from agent.events import FlowEvent

logger = logging.getLogger(__name__)

UNKNOWN_PROCESS = "unknown"
UNKNOWN_PID = -1
NFSTREAM_UNKNOWN_PIDS: frozenset[int] = frozenset({0, -1})  # NFStream's "no PID" values

DEFAULT_PORT_PID_CACHE_TTL_S = 2.0  # used when config.yaml lacks capture.port_pid_cache_ttl_s
DEFAULT_PORT_POLL_INTERVAL_S = 0.05  # used when config.yaml lacks capture.port_poll_interval_s
DEFAULT_PORT_HISTORY_S = 60.0  # used when config.yaml lacks capture.port_history_s

# IP protocol number -> socket type, for matching a flow to a psutil connection.
_SOCK_TYPE_BY_PROTOCOL: dict[int, int] = {6: socket.SOCK_STREAM, 17: socket.SOCK_DGRAM}

# §6.1 NFStreamer settings that are fixed by the spec (interface and timeouts come from config).
# n_dissections is deliberately NOT passed: its default (20) is what fills requested_server_name.
STATISTICAL_ANALYSIS = True
SYSTEM_VISIBILITY_MODE = 1  # 1 = report the process name/PID that owns each flow

_DIRECTIONS = ("bidirectional", "src2dst", "dst2src")
_STATS = ("min", "mean", "stddev", "max")
_TCP_FLAGS = ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin")

FEATURE_FIELDS: tuple[str, ...] = (
    # volume and duration per direction
    *(f"{d}_{m}" for d in _DIRECTIONS for m in ("duration_ms", "packets", "bytes")),
    # packet-size stats (statistical_analysis=True)
    *(f"{d}_{s}_ps" for d in _DIRECTIONS for s in _STATS),
    # packet inter-arrival-time stats (statistical_analysis=True)
    *(f"{d}_{s}_piat_ms" for d in _DIRECTIONS for s in _STATS),
    # TCP flag counts (statistical_analysis=True)
    *(f"{d}_{f}_packets" for d in _DIRECTIONS for f in _TCP_FLAGS),
)
"""Raw NFStream statistics copied into ``FlowEvent.features`` for the flow model (§6.3).

Never includes IPs, ports or MACs: those must not be model features (§7).
"""

ProcessFallback = Callable[[Any], tuple[str, int] | None]
"""Resolves ``(process, pid)`` for a flow whose ``system_process_name`` is empty."""

StreamerFactory = Callable[[dict[str, Any]], Iterable[Any]]


class CaptureError(RuntimeError):
    """Raised when live capture cannot start (e.g. NFStream is not installed)."""


# --- mapping (pure) ---------------------------------------------------------------------------


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _str_or_none(value: Any) -> str | None:
    """NFStream reports "no hostname / no app" as ``""``; FlowEvent uses ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
"""A parsed IP address (IPv4 or IPv6)."""


def parse_ip(ip: str) -> IPAddress | None:
    """Parse ``ip``; drop an IPv6 zone (``fe80::1%eth0``) and unwrap IPv4-mapped IPv6
    (``::ffff:1.2.3.4``). Unparseable -> ``None``."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def host_addresses() -> frozenset[IPAddress]:
    """This PC's own IP addresses, from every network interface (psutil.net_if_addrs)."""
    import psutil  # lazy: only live capture needs it

    found: set[IPAddress] = set()
    for addrs in psutil.net_if_addrs().values():
        for snic in addrs:
            if snic.family in (socket.AF_INET, socket.AF_INET6):
                addr = parse_ip(snic.address)
                if addr is not None:
                    found.add(addr)
    return frozenset(found)


def is_local_address(ip: str, local_ips: Iterable[IPAddress]) -> bool:
    """True if ``ip`` is one of this PC's own addresses (``local_ips``) or loopback (§6.1).

    "Local" means *this host*, not "any private IP": a flow started by another machine on the
    LAN or the lab network (e.g. 192.168.56.20) is inbound. Unparseable -> False.
    """
    addr = parse_ip(ip)
    if addr is None:
        return False
    return addr.is_loopback or addr in frozenset(local_ips)


def direction_of(src_ip: str, local_ips: Iterable[IPAddress]) -> Literal["outbound", "inbound"]:
    """``outbound`` if this PC started the flow (``src_ip`` is one of its addresses), else
    ``inbound`` (§6.1)."""
    return "outbound" if is_local_address(src_ip, local_ips) else "inbound"


def default_process_fallback(flow: Any) -> tuple[str, int] | None:
    """The pure mapping's default: no lookup, the flow keeps ``"unknown"``/``-1``.

    Live capture (:func:`run`) passes a :class:`PortPidResolver` instead, which maps the flow's
    local port to a PID with ``psutil.net_connections``.
    """
    return None


def _process_of(flow: Any, process_fallback: ProcessFallback | None) -> tuple[str, int]:
    name = _str_or_none(getattr(flow, "system_process_name", None))
    if name is None:
        resolved = (process_fallback or default_process_fallback)(flow)
        return resolved if resolved is not None else (UNKNOWN_PROCESS, UNKNOWN_PID)
    pid = _int(getattr(flow, "system_process_pid", None), UNKNOWN_PID)
    return name, (UNKNOWN_PID if pid in NFSTREAM_UNKNOWN_PIDS else pid)


def extract_features(flow: Any) -> dict[str, Any]:
    """Copy the :data:`FEATURE_FIELDS` the flow has. Missing or ``None`` fields are skipped."""
    features: dict[str, Any] = {}
    for name in FEATURE_FIELDS:
        value = getattr(flow, name, None)
        if value is not None:
            features[name] = value
    return features


def to_flow_event(
    flow: Any,
    local_ips: Iterable[IPAddress],
    process_fallback: ProcessFallback | None = None,
) -> FlowEvent:
    """Map one NFStream NFlow (or any object with the same attributes) to a :class:`FlowEvent`.

    ``local_ips`` are this PC's own addresses (see :func:`host_addresses`); they decide
    ``direction``. ``exe_path`` stays ``None``: NFStream doesn't report it; procinfo fills it in.
    """
    process, pid = _process_of(flow, process_fallback)
    src_ip = str(getattr(flow, "src_ip", "") or "")
    return FlowEvent(
        ts_ms=_int(getattr(flow, "bidirectional_first_seen_ms", 0)),
        end_ms=_int(getattr(flow, "bidirectional_last_seen_ms", 0)),
        process=process,
        pid=pid,
        exe_path=None,
        src_ip=src_ip,
        src_port=_int(getattr(flow, "src_port", 0)),
        dst_ip=str(getattr(flow, "dst_ip", "") or ""),
        dst_port=_int(getattr(flow, "dst_port", 0)),
        protocol=_int(getattr(flow, "protocol", 0)),
        hostname=_str_or_none(getattr(flow, "requested_server_name", None)),
        app_proto=_str_or_none(getattr(flow, "application_name", None)),
        bytes_out=_int(getattr(flow, "src2dst_bytes", 0)),
        bytes_in=_int(getattr(flow, "dst2src_bytes", 0)),
        packets=_int(getattr(flow, "bidirectional_packets", 0)),
        direction=direction_of(src_ip, local_ips),
        features=extract_features(flow),
    )


# --- streamer and run loop --------------------------------------------------------------------


def make_streamer(cfg: dict[str, Any]) -> Any:
    """Build an ``nfstream.NFStreamer`` with exactly the §6.1 settings.

    Raises:
        CaptureError: If NFStream is not installed.
    """
    try:
        from nfstream import NFStreamer  # lazy: Windows/VM-only dependency
    except ImportError as exc:
        raise CaptureError(
            "NFStream is not installed. Live capture needs Windows with Npcap and "
            "`pip install nfstream` (CLAUDE.md §8)."
        ) from exc

    capture_cfg = cfg["capture"]
    return NFStreamer(
        source=capture_cfg["interface"],
        statistical_analysis=STATISTICAL_ANALYSIS,
        system_visibility_mode=SYSTEM_VISIBILITY_MODE,
        idle_timeout=capture_cfg["idle_timeout"],
        active_timeout=capture_cfg["active_timeout"],
    )


class LocalAddresses:
    """This PC's addresses, re-read every ``refresh_s`` seconds (DHCP / Wi-Fi changes)."""

    def __init__(
        self,
        refresh_s: float,
        source: Callable[[], frozenset[IPAddress]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._refresh_s = refresh_s
        # Default: look host_addresses up at call time (not bound at import), so it can be patched.
        self._source = source or (lambda: host_addresses())
        self._clock = clock
        self._ips: frozenset[IPAddress] = frozenset()
        self._read_at: float | None = None

    def get(self) -> frozenset[IPAddress]:
        now = self._clock()
        if self._read_at is None or now - self._read_at >= self._refresh_s:
            try:
                self._ips = self._source()
            except Exception:
                logger.exception("Could not read this PC's addresses; keeping the last ones")
            self._read_at = now
        return self._ips


def _socket_owners() -> dict[tuple[int, int], int]:
    """``(socket type, local port) -> PID`` for every socket psutil can see right now.

    Raises whatever ``psutil.net_connections`` raises (callers log it).
    """
    import psutil  # lazy: only live capture needs it

    ports: dict[tuple[int, int], int] = {}
    for conn in psutil.net_connections(kind="inet"):
        port = getattr(conn.laddr, "port", None) if conn.laddr else None
        if conn.pid is None or conn.pid in NFSTREAM_UNKNOWN_PIDS or not port:
            continue
        ports.setdefault((int(conn.type), int(port)), int(conn.pid))
    return ports


class PortHistory:
    """Remembers who owned each local port over the last ``keep_s`` seconds.

    Why: NFStream reports a short connection (a beacon check-in, a DNS query) only after it has
    closed, so by the time :class:`PortPidResolver` asks psutil who owns its port, nobody does
    and the flow would be ``"unknown"`` (alert only, never quarantined; found in #58). A
    background thread (:meth:`start`) polls ``psutil.net_connections`` every ``poll_s`` seconds
    and records each ``(socket type, port) -> (PID, name)`` sighting, with the name read while
    the process is still alive. :meth:`lookup` returns the most recent owner seen within
    ``keep_s``. Connections shorter than ``poll_s`` can still be missed.

    Thread-safe. Never raises from the poll loop: a psutil error is logged once and retried.
    """

    def __init__(
        self,
        poll_s: float,
        keep_s: float,
        clock: Callable[[], float] = time.monotonic,
        read: Callable[[], dict[tuple[int, int], int]] | None = None,
    ) -> None:
        if poll_s <= 0 or keep_s <= 0:
            raise ValueError("port history poll and keep times must be > 0")
        self._poll_s = poll_s
        self._keep_s = keep_s
        self._clock = clock
        self._read = read or (lambda: _socket_owners())  # looked up at call time: patchable
        self._seen: dict[tuple[int, int], tuple[int, str | None, float]] = {}
        self._names: dict[int, str | None] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._failing = False

    def poll_once(self) -> None:
        """Record the current owner of every port, then forget sightings older than ``keep_s``."""
        try:
            owners = self._read()
        except Exception as exc:  # AccessDenied, OSError, ...
            log = logger.debug if self._failing else logger.warning
            log("psutil.net_connections failed (%s); port history not updated", exc)
            self._failing = True
            return
        self._failing = False
        now = self._clock()
        live_pids = set(owners.values())
        for pid in live_pids - self._names.keys():
            self._names[pid] = _process_name(pid)  # read once per PID, while it is alive
        with self._lock:
            for key, pid in owners.items():
                self._seen[key] = (pid, self._names.get(pid), now)
            cutoff = now - self._keep_s
            for key in [k for k, (_, _, seen) in self._seen.items() if seen < cutoff]:
                del self._seen[key]
            remembered = {pid for pid, _, _ in self._seen.values()}
        for pid in [p for p in self._names if p not in remembered]:
            del self._names[pid]

    def lookup(self, key: tuple[int, int]) -> tuple[str | None, int] | None:
        """``(name, pid)`` of the last process seen on ``key`` within ``keep_s``, else ``None``."""
        with self._lock:
            entry = self._seen.get(key)
        if entry is None or entry[2] < self._clock() - self._keep_s:
            return None
        pid, name, _ = entry
        return name, pid

    def start(self) -> None:
        """Poll in a daemon thread until :meth:`stop`."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="port-history", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self._poll_s)


class PortPidResolver:
    """Process fallback: find who owns a flow's local port with ``psutil.net_connections`` (§6.1).

    Used for flows whose ``system_process_name`` is empty. The local port is the port on this
    PC's side: ``src_port`` for outbound flows, ``dst_port`` for inbound ones. The lookup is keyed
    by ``(socket type, port)`` so a TCP flow only matches a TCP socket and UDP only UDP; other
    protocols (ICMP, ...) have no ports and never match.

    One ``net_connections`` snapshot (port -> PID, plus PID -> name) is cached for ``ttl_s``
    seconds, so a burst of flows costs one psutil call. After the TTL the next lookup refreshes it.
    If the snapshot has no owner (the connection already closed) and a :class:`PortHistory` is
    given, its most recent sighting of the port is used.

    Never raises: a psutil error (e.g. ``AccessDenied`` on macOS) is logged and the flow keeps
    the defaults. If the PID is found but its name can't be read (process gone / access
    denied), the PID is kept and the process stays ``"unknown"``.
    """

    def __init__(
        self,
        ttl_s: float,
        local_addresses: LocalAddresses,
        clock: Callable[[], float] = time.monotonic,
        history: PortHistory | None = None,
    ) -> None:
        self._ttl_s = ttl_s
        self._local_addresses = local_addresses
        self._clock = clock
        self._history = history
        self._ports: dict[tuple[int, int], int] = {}
        self._names: dict[int, str | None] = {}
        self._read_at: float | None = None
        self._failing = False

    def __call__(self, flow: Any) -> tuple[str, int] | None:
        key = self._socket_key(flow)
        if key is None:
            return None
        pid = self._snapshot().get(key)
        if pid is not None:
            return (self._name_of(pid) or UNKNOWN_PROCESS, pid)
        seen = self._history.lookup(key) if self._history is not None else None
        if seen is None:
            return None
        name, pid = seen
        return (name or UNKNOWN_PROCESS, pid)

    def _socket_key(self, flow: Any) -> tuple[int, int] | None:
        sock_type = _SOCK_TYPE_BY_PROTOCOL.get(_int(getattr(flow, "protocol", 0)))
        if sock_type is None:
            return None
        src_ip = str(getattr(flow, "src_ip", "") or "")
        outbound = direction_of(src_ip, self._local_addresses.get()) == "outbound"
        port = _int(getattr(flow, "src_port" if outbound else "dst_port", 0))
        return (sock_type, port) if port > 0 else None

    def _snapshot(self) -> dict[tuple[int, int], int]:
        now = self._clock()
        if self._read_at is None or now - self._read_at >= self._ttl_s:
            self._ports = self._read_ports()
            self._names = {}
            self._read_at = now  # also after an error: retry only once the TTL has passed
        return self._ports

    def _read_ports(self) -> dict[tuple[int, int], int]:
        try:
            ports = _socket_owners()
        except Exception as exc:  # AccessDenied (macOS without root), OSError, ...
            log = logger.debug if self._failing else logger.warning
            log("psutil.net_connections failed (%s); process fallback has no data", exc)
            self._failing = True
            return {}
        self._failing = False
        return ports

    def _name_of(self, pid: int) -> str | None:
        if pid not in self._names:
            self._names[pid] = _process_name(pid)
        return self._names[pid]


def _process_name(pid: int) -> str | None:
    """``psutil.Process(pid).name()``, or ``None`` (logged) if it can't be read."""
    import psutil  # lazy: only live capture needs it

    try:
        return _str_or_none(psutil.Process(pid).name())
    except Exception as exc:  # NoSuchProcess, AccessDenied, ...
        logger.debug("Could not read the name of PID %d: %s", pid, exc)
        return None


def run(
    bus: Bus,
    cfg: dict[str, Any],
    streamer_factory: StreamerFactory = make_streamer,
    stop_event: threading.Event | None = None,
    process_fallback: ProcessFallback | None = None,
    local_addresses: LocalAddresses | None = None,
) -> int:
    """Capture flows and publish each as a FlowEvent. Blocking: run it in its own thread.

    Stops when the streamer ends or ``stop_event`` is set. The stop is checked between flows,
    so it takes effect when the next flow arrives (NFStream blocks while waiting for one).
    A flow that fails to map is logged and skipped. ``local_addresses`` defaults to this PC's
    own addresses, refreshed every ``capture.local_ips_refresh_s`` seconds. ``process_fallback``
    defaults to a :class:`PortPidResolver` whose cache lives ``capture.port_pid_cache_ttl_s``
    seconds (:data:`DEFAULT_PORT_PID_CACHE_TTL_S` if the key is missing), backed by a
    :class:`PortHistory` (``capture.port_poll_interval_s`` / ``capture.port_history_s``) that
    runs while the capture runs, so short connections keep their process.

    Returns:
        The number of events published.
    """
    capture_cfg = cfg.get("capture", {})
    if local_addresses is None:
        local_addresses = LocalAddresses(capture_cfg["local_ips_refresh_s"])
    history: PortHistory | None = None
    if process_fallback is None:
        ttl_s = capture_cfg.get("port_pid_cache_ttl_s", DEFAULT_PORT_PID_CACHE_TTL_S)
        history = PortHistory(
            capture_cfg.get("port_poll_interval_s", DEFAULT_PORT_POLL_INTERVAL_S),
            capture_cfg.get("port_history_s", DEFAULT_PORT_HISTORY_S),
        )
        history.start()
        process_fallback = PortPidResolver(ttl_s, local_addresses, history=history)
    published = 0
    try:
        for flow in streamer_factory(cfg):
            if stop_event is not None and stop_event.is_set():
                break
            try:
                event = to_flow_event(flow, local_addresses.get(), process_fallback)
            except Exception:
                logger.exception("Could not map an NFStream flow to a FlowEvent; skipping it")
                continue
            bus.publish_threadsafe(event)
            published += 1
    finally:
        if history is not None:
            history.stop()
    logger.info("Capture stopped after publishing %d flow(s)", published)
    return published


# --- CLI (manual check on the Windows VM) -----------------------------------------------------


async def _log_flows(bus: Bus) -> None:
    with bus.subscribe("capture-cli") as sub:
        async for event in sub:
            logger.info(
                "flow %s pid=%s host=%s -> %s:%s (%s)",
                event.process, event.pid, event.hostname, event.dst_ip, event.dst_port,
                event.direction,
            )


async def _main_async(cfg: dict[str, Any], stop_event: threading.Event) -> None:
    bus = Bus.from_config(cfg, loop=asyncio.get_running_loop())
    printer = asyncio.create_task(_log_flows(bus))
    try:
        await asyncio.to_thread(run, bus, cfg, stop_event=stop_event)
    finally:
        stop_event.set()  # on Ctrl+C: the capture thread exits at its next flow
        printer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await printer


def main() -> None:
    """``python -m agent.capture``: log every FlowEvent's process, PID, hostname and dst."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = config.load()
    logger.info("Capturing on interface %r (Ctrl+C to stop)", cfg["capture"]["interface"])
    stop_event = threading.Event()
    try:
        asyncio.run(_main_async(cfg, stop_event))
    except KeyboardInterrupt:
        logger.info("Stopping capture")
    except CaptureError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
