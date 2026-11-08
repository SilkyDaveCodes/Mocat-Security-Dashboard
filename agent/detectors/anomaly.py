"""Unusual-upload detector (CLAUDE.md §6.3 "anomaly.py").

The detector learns what each app's network traffic normally looks like and flags a 60-second
window in which an app suddenly uploads a lot more than usual (exfiltration, MITRE T1041).

Windows
    Outbound flows are summed per process into windows of ``window_s`` seconds:
    ``bytes_out`` (sum of ``FlowEvent.bytes_out``), ``flows`` (count) and ``unique_dst_ips``.
    ``new_countries`` (optional in §6.3) is not used: there is no GeoIP data. Only windows in
    which the process made at least one outbound flow exist (idle minutes are not recorded).

Clock
    Windows are cut on ``window_s`` boundaries of the **injected clock** (``clock()`` in ms,
    wall time by default), i.e. the time a flow reaches the detector, not ``FlowEvent.ts_ms``.
    NFStream emits a flow only after it ends (idle/active timeout), so flow timestamps arrive
    late and out of order; the processing time is monotonic and trivially faked in tests.
    Open windows whose boundary has passed are closed on the next ``process()`` or ``tick()``.

Calibration
    For ``calibration.minutes`` after the detector is created (or until the stored calibration
    end, after a restart) windows are only collected; no Signal is ever emitted. When a window
    closes it is appended to that process's baseline and saved through the store.

Scoring (after calibration)
    * A process with ``>= min_windows`` baseline windows gets its own ``IsolationForest``; any
      other process (new or thin) is scored by a global model fitted on every process's windows
      pooled (needs ``global_min_windows`` of them; with fewer there is nothing to compare with
      and the detector stays silent). Models are fitted lazily, ``random_state=42``, and refitted
      when the baseline has grown since the last fit.
    * Features are ``log1p`` of the three window counters, so a model sees ratios, not raw sizes.
    * The open window is checked as flows arrive, once its ``bytes_out`` exceeds
      ``bytes_out_threshold`` (10 MB). If the model calls it anomalous, one Signal per process per
      window is emitted: ``score`` in ``[score_min, score_max]`` (how far past the model's
      anomaly threshold it is), ``mitre="T1041"``, ``target`` = the destination that received
      most of the window's bytes. An anomalous window at or under the threshold never signals.
    * With ``learn_after_calibration`` a closed window that was neither flagged nor over the
      threshold is still added to the baseline, so a process can reach ``min_windows`` after the
      (10-minute demo) calibration. Each baseline keeps the newest ``max_windows`` windows.

Baselines in the store (one dict per process name)
    ``{"version": 1, "calibration_end_ms": int, "windows": [[bytes_out, flows, unique_dst_ips]]}``.
    A detector created with a store that already holds baselines reloads them, resumes the
    stored calibration end (calibration is not repeated after a restart) and refits its models
    from the stored windows.
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

import numpy as np
from sklearn.ensemble import IsolationForest

from agent import config as config_module
from agent.events import FlowEvent, Signal

logger = logging.getLogger(__name__)

DETECTOR_NAME = "anomaly"
MITRE_TECHNIQUE = "T1041"  # Exfiltration Over C2 Channel
OUTBOUND = "outbound"
RANDOM_STATE = 42  # CLAUDE.md §7
BASELINE_VERSION = 1
MS_PER_S = 1000
BYTES_PER_MB = 1_000_000

DEFAULTS: dict[str, Any] = {
    "window_s": 60,
    "min_windows": 30,
    "bytes_out_threshold": 10_000_000,
    "score_min": 0.6,
    "score_max": 0.9,
    "global_min_windows": 10,
    "max_windows": 1440,
    "learn_after_calibration": True,
    "contamination": "auto",
    "n_estimators": 100,
}
DEFAULT_CALIBRATION_MINUTES = 10

Window = list[int]  # [bytes_out, flows, unique_dst_ips]
ModelKind = Literal["process", "global"]


class BaselineStore(Protocol):
    """The part of :class:`agent.store.Store` this detector uses."""

    def save_baseline(
        self, process: str, data: dict[str, Any], updated_ms: int | None = None
    ) -> None: ...

    def load_baselines(self) -> dict[str, dict[str, Any]]: ...


def _now_ms() -> int:
    return int(time.time() * MS_PER_S)


@dataclass
class _OpenWindow:
    index: int
    pid: int = -1
    bytes_out: int = 0
    flows: int = 0
    dst_bytes: dict[str, int] = field(default_factory=dict)
    flagged: bool = False

    def as_window(self) -> Window:
        return [self.bytes_out, self.flows, len(self.dst_bytes)]


@dataclass(frozen=True)
class Assessment:
    """The model's verdict on one window."""

    anomalous: bool
    anomaly_score: float     # IsolationForest anomaly score in (0, 1]; higher = stranger
    threshold: float         # anomaly_score above this = anomalous
    model: ModelKind
    usual_bytes_out: float   # median bytes_out of the windows the model was fitted on


@dataclass
class _Fitted:
    model: IsolationForest
    n_windows: int
    usual_bytes_out: float


def _features(windows: list[Window]) -> np.ndarray:
    return np.log1p(np.asarray(windows, dtype=float))


def _mb(n_bytes: float) -> str:
    return f"{n_bytes / BYTES_PER_MB:.1f} MB"


class AnomalyDetector:
    """Flags 60-second windows in which an app uploads far more than its learned baseline."""

    def __init__(
        self,
        cfg: dict[str, Any] | None = None,
        store: BaselineStore | None = None,
        clock: Callable[[], int] = _now_ms,
    ) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
                Missing ``detectors.anomaly`` keys fall back to :data:`DEFAULTS`.
            store: Where baselines are saved/loaded (an :class:`agent.store.Store`). ``None``
                keeps them in memory only.
            clock: Returns the current time in ms. Inject a fake one in tests.
        """
        cfg = cfg if cfg is not None else config_module.load()
        a_cfg = {**DEFAULTS, **(cfg.get("detectors", {}).get("anomaly") or {})}
        self._window_ms = int(float(a_cfg["window_s"]) * MS_PER_S)
        self._min_windows = int(a_cfg["min_windows"])
        self._threshold = int(a_cfg["bytes_out_threshold"])
        self._score_min = float(a_cfg["score_min"])
        self._score_max = float(a_cfg["score_max"])
        self._global_min_windows = int(a_cfg["global_min_windows"])
        self._max_windows = int(a_cfg["max_windows"])
        self._learn_after = bool(a_cfg["learn_after_calibration"])
        contamination = a_cfg["contamination"]
        self._contamination: str | float = (
            contamination if contamination == "auto" else float(contamination)
        )
        self._n_estimators = int(a_cfg["n_estimators"])
        calibration_min = float(
            (cfg.get("calibration") or {}).get("minutes", DEFAULT_CALIBRATION_MINUTES)
        )

        self._clock = clock
        self._store = store
        self._baselines: dict[str, list[Window]] = {}
        self._open: dict[str, _OpenWindow] = {}
        self._models: dict[str, _Fitted] = {}
        self._global: _Fitted | None = None

        stored_end = self._load_from_store()
        if stored_end is not None:
            self._calibration_end_ms = stored_end
            logger.info(
                "Anomaly: reloaded %d baselines (%d windows); calibration ends at %d",
                len(self._baselines), self.total_windows, stored_end,
            )
        else:
            self._calibration_end_ms = clock() + int(calibration_min * 60 * MS_PER_S)

    # --- public -------------------------------------------------------------------------------

    @property
    def calibration_end_ms(self) -> int:
        return self._calibration_end_ms

    @property
    def total_windows(self) -> int:
        return sum(len(w) for w in self._baselines.values())

    def calibrating(self) -> bool:
        return self._clock() < self._calibration_end_ms

    def baseline(self, process: str) -> list[Window]:
        """A copy of one process's baseline windows (``[bytes_out, flows, unique_dst_ips]``)."""
        return [list(w) for w in self._baselines.get(process, [])]

    def process(self, event: FlowEvent) -> list[Signal]:
        """Add an outbound flow to its process's window; return a Signal for an unusual upload."""
        now = self._clock()
        self._close_expired(now)
        if event.direction != OUTBOUND:
            return []

        index = now // self._window_ms
        win = self._open.get(event.process)
        if win is None:
            win = self._open[event.process] = _OpenWindow(index=index)
        win.pid = event.pid
        win.bytes_out += max(event.bytes_out, 0)
        win.flows += 1
        if event.dst_ip:
            win.dst_bytes[event.dst_ip] = win.dst_bytes.get(event.dst_ip, 0) + event.bytes_out

        if win.flagged or now < self._calibration_end_ms or win.bytes_out <= self._threshold:
            return []
        assessment = self.assess(event.process, win.as_window())
        if assessment is None or not assessment.anomalous:
            return []
        win.flagged = True
        return [self._signal(event.process, win, assessment, now)]

    def tick(self) -> None:
        """Close windows whose boundary has passed (call periodically when flows are sparse)."""
        self._close_expired(self._clock())

    def assess(self, process: str, window: Window) -> Assessment | None:
        """Score one window with the process's model, or the global one if the process is thin.

        Returns ``None`` when there is no baseline to compare with yet.
        """
        fitted, kind = self._model_for(process)
        if fitted is None:
            return None
        anomaly_score = float(-fitted.model.score_samples(_features([window]))[0])
        threshold = float(-fitted.model.offset_)
        return Assessment(
            anomalous=anomaly_score > threshold,
            anomaly_score=anomaly_score,
            threshold=threshold,
            model=kind,
            usual_bytes_out=fitted.usual_bytes_out,
        )

    # --- windows ------------------------------------------------------------------------------

    def _close_expired(self, now: int) -> None:
        index = now // self._window_ms
        for proc in [p for p, w in self._open.items() if w.index < index]:
            self._close(proc, self._open.pop(proc), now)

    def _close(self, process: str, win: _OpenWindow, now: int) -> None:
        in_calibration = win.index * self._window_ms < self._calibration_end_ms
        if not in_calibration:
            if not self._learn_after or win.flagged or win.bytes_out > self._threshold:
                return
        windows = self._baselines.setdefault(process, [])
        windows.append(win.as_window())
        if len(windows) > self._max_windows:
            del windows[: len(windows) - self._max_windows]
        self._save(process, now)

    # --- models -------------------------------------------------------------------------------

    def _model_for(self, process: str) -> tuple[_Fitted | None, ModelKind]:
        windows = self._baselines.get(process, [])
        if len(windows) >= self._min_windows:
            fitted = self._models.get(process)
            if fitted is None or fitted.n_windows != len(windows):
                fitted = self._models[process] = self._fit(windows)
            return fitted, "process"

        total = self.total_windows
        if total < self._global_min_windows:
            return None, "global"
        if self._global is None or self._global.n_windows != total:
            pooled = [w for ws in self._baselines.values() for w in ws]
            self._global = self._fit(pooled)
        return self._global, "global"

    def _fit(self, windows: list[Window]) -> _Fitted:
        model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=RANDOM_STATE,
        )
        model.fit(_features(windows))
        usual = statistics.median(w[0] for w in windows)
        return _Fitted(model=model, n_windows=len(windows), usual_bytes_out=usual)

    def _score(self, assessment: Assessment) -> float:
        """Map how far past the model's threshold a window is onto [score_min, score_max]."""
        span = max(1.0 - assessment.threshold, math.ulp(1.0))
        excess = min(max((assessment.anomaly_score - assessment.threshold) / span, 0.0), 1.0)
        return round(self._score_min + (self._score_max - self._score_min) * excess, 4)

    def _signal(
        self, process: str, win: _OpenWindow, assessment: Assessment, now: int
    ) -> Signal:
        target = max(win.dst_bytes, key=win.dst_bytes.__getitem__) if win.dst_bytes else ""
        window_s = self._window_ms / MS_PER_S
        reasons = [
            f"uploaded {_mb(win.bytes_out)} in {window_s:.0f} s, far above its usual "
            f"{_mb(assessment.usual_bytes_out)}"
            if assessment.model == "process"
            else f"uploaded {_mb(win.bytes_out)} in {window_s:.0f} s; apps on this PC usually "
            f"upload {_mb(assessment.usual_bytes_out)}",
            f"{win.flows} connections to {len(win.dst_bytes)} address(es) in that window",
        ]
        logger.info(
            "Anomaly: %s uploaded %d bytes in one window (%s model, score %.3f > %.3f)",
            process, win.bytes_out, assessment.model, assessment.anomaly_score,
            assessment.threshold,
        )
        return Signal(
            detector=DETECTOR_NAME,
            process=process,
            pid=win.pid,
            target=target,
            score=self._score(assessment),
            reasons=reasons,
            mitre=MITRE_TECHNIQUE,
            ts_ms=now,
        )

    # --- store --------------------------------------------------------------------------------

    def _save(self, process: str, now: int) -> None:
        if self._store is None:
            return
        data = {
            "version": BASELINE_VERSION,
            "calibration_end_ms": self._calibration_end_ms,
            "windows": self._baselines[process],
        }
        try:
            self._store.save_baseline(process, data, updated_ms=now)
        except Exception:  # never let a store failure stop detection
            logger.exception("Anomaly: could not save the baseline for %s", process)

    def _load_from_store(self) -> int | None:
        """Load stored baselines; return the stored calibration end, or None if there is none."""
        if self._store is None:
            return None
        ends: list[int] = []
        for proc, data in self._store.load_baselines().items():
            try:
                windows = [[int(v) for v in w] for w in data["windows"]]
                if any(len(w) != 3 for w in windows):
                    raise ValueError("window must have 3 values")
                end = int(data["calibration_end_ms"])
            except (KeyError, TypeError, ValueError):
                logger.warning("Anomaly: ignoring malformed stored baseline for %s", proc)
                continue
            self._baselines[proc] = windows[-self._max_windows :]
            ends.append(end)
        return min(ends) if ends else None


_default_detector: AnomalyDetector | None = None


def process(event: FlowEvent) -> list[Signal]:
    """Module-level detector entry point (§6.3), backed by one lazily created AnomalyDetector.

    It keeps baselines in memory only; the agent builds an ``AnomalyDetector(cfg, store)``
    to persist them.
    """
    global _default_detector
    if _default_detector is None:
        _default_detector = AnomalyDetector()
    return _default_detector.process(event)
