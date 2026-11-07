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
"""

from __future__ import annotations

import bisect
import logging
import statistics
from typing import Any

from agent import config as config_module
from agent.events import FlowEvent, Signal

logger = logging.getLogger(__name__)

DETECTOR_NAME = "beacon"
MITRE_TECHNIQUE = "T1071.001"  # Application Layer Protocol: Web Protocols
OUTBOUND = "outbound"
MS_PER_S = 1000

BeaconKey = tuple[str, str, int]


class BeaconDetector:
    """Flags connections an app opens again and again at a very regular interval."""

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
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
        self._starts: dict[BeaconKey, list[int]] = {}

    def process(self, event: FlowEvent) -> list[Signal]:
        """Return one beacon Signal if this flow's connection now looks periodic, else ``[]``."""
        if event.direction != OUTBOUND or not event.dst_ip:
            return []
        starts = self._record((event.process, event.dst_ip, event.dst_port), event.ts_ms)
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

    def _record(self, key: BeaconKey, ts_ms: int) -> list[int]:
        """Insert a start time (sorted, no duplicates), keep the newest ``history``; return them."""
        starts = self._starts.setdefault(key, [])
        index = bisect.bisect_left(starts, ts_ms)
        if index == len(starts) or starts[index] != ts_ms:
            starts.insert(index, ts_ms)
            if len(starts) > self._history:
                del starts[: len(starts) - self._history]
        return starts


_default_detector: BeaconDetector | None = None


def process(event: FlowEvent) -> list[Signal]:
    """Module-level detector entry point (§6.3), backed by one lazily created BeaconDetector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = BeaconDetector()
    return _default_detector.process(event)
