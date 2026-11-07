"""Inbound attack classifier (CLAUDE.md §6.3 "flow_model.py").

Scores **inbound** flows (``direction == "inbound"``: started by another machine) with the
classifier in ``models/flow.joblib`` (labels: benign, portscan, bruteforce, dos). Outbound flows
are ignored and never reach the model.

Features
    ``flow.joblib`` is trained **per flow** (``models/train_flow.py``: one row per NFStream flow,
    :func:`agent.detectors.flow_features.features` of its raw statistics). Live inference does
    exactly the same: each inbound flow's ``FlowEvent.features`` go through the same function and
    are put in the column order saved in the bundle (``feature_names``), giving one
    ``predict_proba`` row per flow.

Window (:class:`WindowTracker`)
    No lab-plan ``WindowTracker`` exists in the repo, so this is the port: every inbound flow's
    probability row is kept per **source IP** for ``window_s`` seconds of the injected clock
    (processing time, like scoring and anomaly), newest ``max_flows_per_source`` only. The
    window's classification is the **mean** probability of each class over its flows: one stray
    flow that looks like a scan does not make an attack, a sustained run of them does, and a
    model trained per flow is averaged rather than maxed so a single over-confident row cannot
    trigger alone.

Signal
    The non-benign class with the highest mean probability, if it is ``>= probability_threshold``
    and the window holds ``>= min_flows`` flows -> ``Signal(detector="flow_model",
    target=src_ip, score=mean probability, mitre=T1046 | T1110 | T1498)``. Benign is never
    signalled. ``process``/``pid`` are the flow's (often the listening service or ``unknown``);
    scoring windows inbound signals per ``target`` anyway (§6.4).

Repeat suppression
    At most one Signal per ``(source IP, class)`` every ``repeat_s`` seconds, so an ongoing
    attack does not emit a Signal per flow. Scoring adds its own repeat suppression on top.

Model loading
    A ``train_flow.py`` bundle dict (``model``, ``feature_names``, ``class_index``), or a bare
    object with ``predict_proba`` and ``classes_``. A missing or unusable model is logged and the
    detector returns no signals (it stays registered, like ``dga``).
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent import config as config_module
from agent.detectors.flow_features import FEATURE_NAMES, features
from agent.events import FlowEvent, Signal

logger = logging.getLogger(__name__)

DETECTOR_NAME = "flow_model"
INBOUND = "inbound"
BENIGN = "benign"
MS_PER_S = 1000

# Attack class -> MITRE ATT&CK technique (§6.3). alerts_text.FLOW_MODEL_ATTACKS keys on these IDs.
MITRE_BY_CLASS: dict[str, str] = {
    "portscan": "T1046",    # Network Service Discovery
    "bruteforce": "T1110",  # Brute Force
    "dos": "T1498",         # Network Denial of Service
}
# Attack class -> words for the reason text.
DESCRIPTION_BY_CLASS: dict[str, str] = {
    "portscan": "port scan",
    "bruteforce": "brute-force login attempts",
    "dos": "denial-of-service flood",
}

Clock = Callable[[], int]


def _now_ms() -> int:
    return int(time.time() * MS_PER_S)


@dataclass(frozen=True)
class WindowSummary:
    """One source IP's window: how many flows, and the mean probability of every class."""

    flows: int
    mean_proba: dict[str, float]


class WindowTracker:
    """Keeps each source IP's recent per-flow class probabilities for ``window_ms``.

    Time is whatever the caller passes (the detector passes its injected clock). Flows older
    than ``window_ms`` drop out; at most ``max_flows`` newest are kept per source. Sources with
    no flow left are forgotten (checked for the touched source on every add, and for all
    sources at most once per window).
    """

    def __init__(self, window_ms: int, max_flows: int) -> None:
        if window_ms <= 0 or max_flows <= 0:
            raise ValueError("window_ms and max_flows must be positive")
        self._window_ms = window_ms
        self._max_flows = max_flows
        self._flows: dict[str, deque[tuple[int, dict[str, float]]]] = {}
        self._last_sweep_ms: int | None = None

    def add(self, source: str, now_ms: int, proba: Mapping[str, float]) -> WindowSummary:
        """Record one flow's class probabilities for ``source``; return its window summary."""
        self._sweep(now_ms)
        flows = self._flows.setdefault(source, deque(maxlen=self._max_flows))
        flows.append((now_ms, dict(proba)))
        self._expire(flows, now_ms)
        return self._summarize(flows)

    def summary(self, source: str, now_ms: int) -> WindowSummary:
        """The window of ``source`` at ``now_ms`` (0 flows if none is held)."""
        flows = self._flows.get(source)
        if flows is None:
            return WindowSummary(0, {})
        self._expire(flows, now_ms)
        if not flows:
            del self._flows[source]
        return self._summarize(flows)

    def sources(self) -> list[str]:
        """Source IPs currently held."""
        return list(self._flows)

    def _expire(self, flows: deque[tuple[int, dict[str, float]]], now_ms: int) -> None:
        while flows and now_ms - flows[0][0] > self._window_ms:
            flows.popleft()

    def _sweep(self, now_ms: int) -> None:
        if self._last_sweep_ms is not None and now_ms - self._last_sweep_ms < self._window_ms:
            return
        self._last_sweep_ms = now_ms
        for source in list(self._flows):
            flows = self._flows[source]
            self._expire(flows, now_ms)
            if not flows:
                del self._flows[source]

    @staticmethod
    def _summarize(flows: deque[tuple[int, dict[str, float]]]) -> WindowSummary:
        if not flows:
            return WindowSummary(0, {})
        totals: dict[str, float] = {}
        for _, proba in flows:
            for label, p in proba.items():
                totals[label] = totals.get(label, 0.0) + p
        n = len(flows)
        return WindowSummary(n, {label: total / n for label, total in totals.items()})


def _load_model(path: Path) -> Any | None:
    try:
        import joblib

        return joblib.load(path)
    except FileNotFoundError:
        logger.warning("Flow model not found at %s; inbound attack detection is off", path)
    except Exception:  # a broken model file must not stop the agent
        logger.exception("Could not load flow model from %s; inbound attack detection is off",
                         path)
    return None


def _unpack_model(model: Any | None) -> tuple[Any | None, list[str], dict[str, int]]:
    """(estimator, feature order, label -> predict_proba column); estimator None if unusable."""
    if model is None:
        return None, list(FEATURE_NAMES), {}
    if isinstance(model, dict):
        estimator = model.get("model")
        names = list(model.get("feature_names", FEATURE_NAMES))
        class_index = model.get("class_index")
        if class_index is None and estimator is not None and hasattr(estimator, "classes_"):
            class_index = {str(c): i for i, c in enumerate(estimator.classes_)}
    else:
        estimator = model
        names = list(FEATURE_NAMES)
        classes = getattr(model, "classes_", None)
        class_index = {str(c): i for i, c in enumerate(classes)} if classes is not None else None
    if estimator is None or not hasattr(estimator, "predict_proba"):
        logger.error("Flow model has no predict_proba; inbound attack detection is off")
        return None, names, {}
    unknown = [n for n in names if n not in FEATURE_NAMES]
    if unknown:
        logger.error("Flow model expects unknown features %s; inbound attack detection is off",
                     unknown)
        return None, names, {}
    if not class_index or not any(label in class_index for label in MITRE_BY_CLASS):
        logger.error("Flow model has no attack classes (%s); inbound attack detection is off",
                     sorted(MITRE_BY_CLASS))
        return None, names, {}
    return estimator, names, {str(k): int(v) for k, v in class_index.items()}


def _repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else config_module.REPO_ROOT / path


class FlowModelDetector:
    """Flags inbound port scans, brute-force logins and floods, per attacking source IP."""

    def __init__(
        self,
        cfg: dict[str, Any] | None = None,
        *,
        model: Any | None = None,
        model_path: str | Path | None = None,
        clock: Clock = _now_ms,
    ) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
            model: A ``train_flow.py`` bundle dict, or a bare object with ``predict_proba`` and
                ``classes_``. Loaded from ``model_path`` when omitted. Tests pass a stub here.
            model_path: Defaults to ``paths.flow_model``.
            clock: Returns the current time in ms (window and repeat timing). Fake it in tests.
        """
        cfg = cfg if cfg is not None else config_module.load()
        fm_cfg = cfg["detectors"]["flow_model"]
        self._threshold = float(fm_cfg["probability_threshold"])
        self._window_ms = int(float(fm_cfg["window_s"]) * MS_PER_S)
        self._min_flows = int(fm_cfg["min_flows"])
        self._repeat_ms = int(float(fm_cfg["repeat_s"]) * MS_PER_S)
        self._clock = clock

        if model is None:
            model = _load_model(Path(model_path or _repo_path(cfg["paths"]["flow_model"])))
        self._model, self._feature_names, self._class_index = _unpack_model(model)
        self._tracker = WindowTracker(self._window_ms, int(fm_cfg["max_flows_per_source"]))
        self._last_signal_ms: dict[tuple[str, str], int] = {}

    @property
    def tracker(self) -> WindowTracker:
        return self._tracker

    def process(self, event: FlowEvent) -> list[Signal]:
        """Return one Signal when this source IP's window now looks like an attack, else ``[]``."""
        if self._model is None or event.direction != INBOUND or not event.src_ip:
            return []
        now = self._clock()
        window = self._tracker.add(event.src_ip, now, self._predict(event.features))
        if window.flows < self._min_flows:
            return []

        attacks = [label for label in MITRE_BY_CLASS if label in window.mean_proba]
        label = max(attacks, key=lambda a: window.mean_proba[a])
        probability = window.mean_proba[label]
        if probability < self._threshold:
            return []
        if not self._due(event.src_ip, label, now):
            return []

        window_s = self._window_ms / MS_PER_S
        reasons = [
            f"{DESCRIPTION_BY_CLASS[label]} from {event.src_ip} "
            f"(p={probability:.2f}, {window.flows} flows in {window_s:g} s)",
        ]
        logger.debug("Flow model: %s from %s p=%.2f over %d flows",
                     label, event.src_ip, probability, window.flows)
        return [
            Signal(
                detector=DETECTOR_NAME,
                process=event.process,
                pid=event.pid,
                target=event.src_ip,
                score=probability,
                reasons=reasons,
                mitre=MITRE_BY_CLASS[label],
                ts_ms=event.ts_ms,
            )
        ]

    # --- internals ---------------------------------------------------------------------------

    def _predict(self, raw: Mapping[str, Any]) -> dict[str, float]:
        feats = features(raw)
        row = self._model.predict_proba([[feats[name] for name in self._feature_names]])[0]
        return {label: float(row[i]) for label, i in self._class_index.items()}

    def _due(self, source: str, label: str, now_ms: int) -> bool:
        """True (and remembered) unless this (source, class) was signalled within repeat_s."""
        key = (source, label)
        last = self._last_signal_ms.get(key)
        if last is not None and now_ms - last < self._repeat_ms:
            return False
        if len(self._last_signal_ms) > len(self._tracker.sources()) * len(MITRE_BY_CLASS):
            self._last_signal_ms = {
                k: t for k, t in self._last_signal_ms.items() if now_ms - t < self._repeat_ms
            }
        self._last_signal_ms[key] = now_ms
        return True


_default_detector: FlowModelDetector | None = None


def process(event: FlowEvent) -> list[Signal]:
    """Module-level detector entry point (§6.3), backed by one lazily created FlowModelDetector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = FlowModelDetector()
    return _default_detector.process(event)
