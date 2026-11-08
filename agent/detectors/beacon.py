"""C2 beaconing detector (CLAUDE.md §6.3 "beacon.py").

For every ``(process, dst_ip, dst_port)`` the detector keeps the start times (``ts_ms``) of the
last ``history`` outbound flows. Once it has ``>= min_starts`` of them it computes the intervals
between consecutive starts. If the mean interval is within ``[mean_interval_min_s,
mean_interval_max_s]`` and the coefficient of variation (population std dev / mean) is below
``cv_max``, the connection is a beacon: ``score`` (or ``high_score`` once ``high_score_min_starts``
starts are held), ``mitre="T1071.001"``.

Details:
    * Only ``direction == "outbound"`` flows are tracked: a beacon is the PC checking in with a
      remote host. Inbound flows would key on our own address.
    * Start times are kept sorted, so out-of-order events are handled; an exact duplicate start
      time for the same key is ignored (it would add a fake 0 s interval).
    * The "spread" in the reason text is the population standard deviation of the intervals.
    * With ``new_connections_only`` (default on) a start is a *new connection*: a flow on the
      same ``(src_ip, src_port, protocol)`` as a start already held for that key is the same
      connection again, not a new check-in, and adds no start. NFStream cuts one long-lived
      connection into many flows (a new flow after ``capture.idle_timeout`` of silence or every
      ``capture.active_timeout``), so a websocket keepalive (Spotify, Discord, Chrome push) or a
      long download would otherwise look like a perfectly regular beacon (ticket #49 FP test).
      The lab sim opens a new connection per check-in (§9.1), as most C2 beacons do. A flow
      with no source port (``0``, e.g. ICMP) always counts as new.
    * With ``skip_non_unicast`` (default on) flows to a multicast, broadcast or unspecified
      address are ignored: no server answers there, so it can't be C2. Windows sends IGMP/MLD
      membership reports to 224.0.0.22 / ff02::16 every ~5 min, which looked like a beacon in
      the VM recording (ticket #49).
    * ``allowlisted_score`` (``null`` = off): an app in the exe allowlist (``paths.allowlist``,
      the same list scoring uses) gets this score instead of ``score``/``high_score``. Kept
      below the alert threshold, a beacon alone stays quiet for a browser, while it still
      adds up with another detector (intel, DGA). Open tabs on ad-heavy pages contact ad
      servers every 30 s on a new connection each time, a perfect beacon (VM recording,
      ticket #49). The allowlist matches by exe name, so malware named ``chrome.exe`` gets the
      low score too: the same trade-off the allowlist already makes for quarantine (§6.4).
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import statistics
from typing import Any

from agent import config as config_module
from agent.config import Allowlist
from agent.events import FlowEvent, Signal

logger = logging.getLogger(__name__)

DETECTOR_NAME = "beacon"
MITRE_TECHNIQUE = "T1071.001"  # Application Layer Protocol: Web Protocols
OUTBOUND = "outbound"
MS_PER_S = 1000

BeaconKey = tuple[str, str, int]
ConnId = tuple[str, int, int]  # (src_ip, src_port, protocol): one connection on this PC's side
DEFAULT_NEW_CONNECTIONS_ONLY = True
DEFAULT_SKIP_NON_UNICAST = True
LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def _is_non_unicast(ip: str) -> bool:
    """True for a multicast, limited-broadcast or unspecified address (never a C2 server)."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return addr.is_multicast or addr.is_unspecified or addr == LIMITED_BROADCAST


class BeaconDetector:
    """Flags connections an app opens again and again at a very regular interval."""

    def __init__(
        self, cfg: dict[str, Any] | None = None, allowlist: Allowlist | None = None
    ) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
            allowlist: Exe names that get ``allowlisted_score``. Loaded from
                ``paths.allowlist`` (or the default ``data/allowlist.txt``) when omitted and
                ``allowlisted_score`` is set.
        """
        cfg = cfg if cfg is not None else config_module.load()
        beacon_cfg = cfg["detectors"]["beacon"]
        self._history = int(beacon_cfg["history"])
        self._min_starts = int(beacon_cfg["min_starts"])
        self._mean_min_s = float(beacon_cfg["mean_interval_min_s"])
        self._mean_max_s = float(beacon_cfg["mean_interval_max_s"])
        self._cv_max = float(beacon_cfg["cv_max"])
        self._score = float(beacon_cfg["score"])
        self._high_score = float(beacon_cfg["high_score"])
        self._high_score_min_starts = int(beacon_cfg["high_score_min_starts"])
        self._new_connections_only = bool(
            beacon_cfg.get("new_connections_only", DEFAULT_NEW_CONNECTIONS_ONLY)
        )
        self._skip_non_unicast = bool(
            beacon_cfg.get("skip_non_unicast", DEFAULT_SKIP_NON_UNICAST)
        )
        raw_allowlisted = beacon_cfg.get("allowlisted_score")
        self._allowlisted_score = None if raw_allowlisted is None else float(raw_allowlisted)
        if self._allowlisted_score is not None and allowlist is None:
            path = cfg.get("paths", {}).get("allowlist")
            allowlist = config_module.load_allowlist(
                config_module.REPO_ROOT / path if path else None
            )
        self._allowlist = allowlist if allowlist is not None else Allowlist(frozenset())
        # Per key: (start ms, connection id or None), sorted by start time.
        self._starts: dict[BeaconKey, list[tuple[int, ConnId | None]]] = {}

    def process(self, event: FlowEvent) -> list[Signal]:
        """Return one beacon Signal if this flow's connection now looks periodic, else ``[]``."""
        if event.direction != OUTBOUND or not event.dst_ip:
            return []
        if self._skip_non_unicast and _is_non_unicast(event.dst_ip):
            return []
        conn = (event.src_ip, event.src_port, event.protocol) if event.src_port > 0 else None
        starts = self._record((event.process, event.dst_ip, event.dst_port), event.ts_ms, conn)
        if starts is None:  # the same connection again: no new start
            return []
        if len(starts) < self._min_starts:
            return []

        intervals_s = [(b - a) / MS_PER_S for a, b in zip(starts, starts[1:], strict=False)]
        mean_s = statistics.fmean(intervals_s)
        if not self._mean_min_s <= mean_s <= self._mean_max_s:
            return []
        spread_s = statistics.pstdev(intervals_s)
        if spread_s / mean_s >= self._cv_max:
            return []

        score = self._high_score if len(starts) >= self._high_score_min_starts else self._score
        reasons = [
            f"checks in with {event.dst_ip} every {mean_s:.1f} s (±{spread_s:.1f} s)",
            f"{len(starts)} regular connections to port {event.dst_port}",
        ]
        if self._allowlisted_score is not None and event.process in self._allowlist:
            score = min(score, self._allowlisted_score)
            reasons.append(f"{event.process} is a trusted app, so this counts for less")
        logger.debug(
            "Beacon: %s -> %s:%d every %.1f s (±%.1f s, %d starts)",
            event.process, event.dst_ip, event.dst_port, mean_s, spread_s, len(starts),
        )
        return [
            Signal(
                detector=DETECTOR_NAME,
                process=event.process,
                pid=event.pid,
                target=event.dst_ip,
                score=score,
                reasons=reasons,
                mitre=MITRE_TECHNIQUE,
                ts_ms=event.ts_ms,
            )
        ]

    def _record(self, key: BeaconKey, ts_ms: int, conn: ConnId | None) -> list[int] | None:
        """Insert a start (sorted, no duplicate times), keep the newest ``history``; return the
        start times. ``None`` if ``conn`` is a connection already held (not a new start)."""
        entries = self._starts.setdefault(key, [])
        if (self._new_connections_only and conn is not None
                and any(held == conn for _, held in entries)):
            return None
        index = bisect.bisect_left(entries, ts_ms, key=lambda entry: entry[0])
        if index == len(entries) or entries[index][0] != ts_ms:
            entries.insert(index, (ts_ms, conn))
            if len(entries) > self._history:
                del entries[: len(entries) - self._history]
        return [ts for ts, _ in entries]


_default_detector: BeaconDetector | None = None


def process(event: FlowEvent) -> list[Signal]:
    """Module-level detector entry point (§6.3), backed by one lazily created BeaconDetector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = BeaconDetector()
    return _default_detector.process(event)
