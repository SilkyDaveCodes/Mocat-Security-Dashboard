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
    """No fallback yet: the flow keeps the FlowEvent defaults (``"unknown"``, ``-1``).

    TODO(#5): map the flow's local port to a PID with ``psutil.net_connections(kind="inet")``
    and return ``(process_name, pid)``. Pass the result as ``process_fallback``.
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
    own addresses, refreshed every ``capture.local_ips_refresh_s`` seconds.

    Returns:
        The number of events published.
    """
    if local_addresses is None:
        local_addresses = LocalAddresses(cfg["capture"]["local_ips_refresh_s"])
    published = 0
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
