"""Tests for agent/detectors/flow_model.py (ticket #48): inbound attack classification."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

import pytest

from agent import config
from agent.detectors.flow_features import FEATURE_NAMES
from agent.detectors.flow_model import FlowModelDetector, WindowTracker
from agent.events import FlowEvent
from agent.main import NamedDetector, Pipeline
from agent.scoring import Scorer
from agent.store import Store

CLASSES = ["benign", "portscan", "bruteforce", "dos"]
ATTACKER = "192.168.56.20"
OTHER = "192.168.56.30"
PC_IP = "192.168.56.10"
T0 = 1_700_000_000_000


class StubModel:
    """predict_proba returns a fixed row; every call's input is recorded."""

    def __init__(self, label: str = "benign", p: float = 1.0) -> None:
        self.calls: list[list[list[float]]] = []
        self.set(label, p)

    def set(self, label: str, p: float) -> None:
        rest = (1.0 - p) / (len(CLASSES) - 1)
        self.row = [p if c == label else rest for c in CLASSES]

    def predict_proba(self, X: list[list[float]]) -> list[list[float]]:
        self.calls.append(X)
        return [list(self.row) for _ in X]


class Clock:
    def __init__(self, now: int = T0) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def bundle(model: Any) -> dict[str, Any]:
    return {"model": model, "feature_names": list(FEATURE_NAMES), "classes": CLASSES,
            "class_index": {c: i for i, c in enumerate(CLASSES)}}


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


def make(cfg: dict[str, Any], model: StubModel, clock: Clock) -> FlowModelDetector:
    return FlowModelDetector(cfg, model=bundle(model), clock=clock)


def inbound(src: str = ATTACKER, port: int = 40000, direction: str = "inbound",
            ts: int = T0) -> FlowEvent:
    return FlowEvent(ts_ms=ts, end_ms=ts + 5, process="svchost.exe", pid=900, src_ip=src,
                     src_port=port, dst_ip=PC_IP, dst_port=445, protocol=6, packets=2,
                     direction=direction,  # type: ignore[arg-type]
                     features={"bidirectional_packets": 2, "bidirectional_syn_packets": 1,
                               "bidirectional_bytes": 120, "bidirectional_duration_ms": 3})


def feed(det: FlowModelDetector, n: int, src: str = ATTACKER) -> list:
    out = []
    for i in range(n):
        out.extend(det.process(inbound(src, 40000 + i)))
    return out


# --- outbound never reaches the model ---------------------------------------------------------

def test_outbound_flows_are_ignored_and_never_reach_the_model(cfg: dict[str, Any]) -> None:
    model = StubModel("portscan", 0.99)
    det = make(cfg, model, Clock())
    signals = []
    for i in range(20):
        signals += det.process(inbound(port=40000 + i, direction="outbound"))
    assert signals == []
    assert model.calls == []
    assert det.tracker.sources() == []


def test_inbound_flow_reaches_model_with_training_feature_vector(cfg: dict[str, Any]) -> None:
    model = StubModel()
    det = make(cfg, model, Clock())
    det.process(inbound())
    assert len(model.calls) == 1
    (row,) = model.calls[0]
    assert len(row) == len(FEATURE_NAMES)
    feats = dict(zip(FEATURE_NAMES, row, strict=True))
    assert feats["bidirectional_packets"] == 2.0
    assert feats["syn_share"] == 0.5


# --- class -> MITRE on src_ip ------------------------------------------------------------------

@pytest.mark.parametrize(("label", "mitre"),
                         [("portscan", "T1046"), ("bruteforce", "T1110"), ("dos", "T1498")])
def test_attack_window_at_0_9_gives_signal_on_src_ip(cfg: dict[str, Any], label: str,
                                                     mitre: str) -> None:
    det = make(cfg, StubModel(label, 0.9), Clock())
    min_flows = cfg["detectors"]["flow_model"]["min_flows"]
    signals = feed(det, min_flows)
    assert len(signals) == 1
    sig = signals[0]
    assert sig.detector == "flow_model"
    assert sig.target == ATTACKER
    assert sig.mitre == mitre
    assert sig.score == pytest.approx(0.9)
    assert sig.process == "svchost.exe" and sig.pid == 900
    assert ATTACKER in sig.reasons[0] and f"{min_flows} flows" in sig.reasons[0]


def test_no_signal_before_min_flows(cfg: dict[str, Any]) -> None:
    det = make(cfg, StubModel("portscan", 0.99), Clock())
    assert feed(det, cfg["detectors"]["flow_model"]["min_flows"] - 1) == []


# --- threshold ---------------------------------------------------------------------------------

@pytest.mark.parametrize("label", ["portscan", "bruteforce", "dos"])
def test_non_benign_below_threshold_gives_no_signal(cfg: dict[str, Any], label: str) -> None:
    assert cfg["detectors"]["flow_model"]["probability_threshold"] == 0.85
    det = make(cfg, StubModel(label, 0.8), Clock())
    assert feed(det, 30) == []


def test_benign_at_any_probability_gives_no_signal(cfg: dict[str, Any]) -> None:
    for p in (0.5, 0.9, 0.99, 1.0):
        det = make(cfg, StubModel("benign", p), Clock())
        assert feed(det, 30) == []


def test_threshold_comes_from_config(cfg: dict[str, Any]) -> None:
    cfg["detectors"]["flow_model"]["probability_threshold"] = 0.75
    det = make(cfg, StubModel("portscan", 0.8), Clock())
    assert len(feed(det, cfg["detectors"]["flow_model"]["min_flows"])) == 1


def test_window_uses_mean_probability_over_flows(cfg: dict[str, Any]) -> None:
    cfg["detectors"]["flow_model"]["min_flows"] = 1
    model = StubModel("portscan", 0.95)
    det = make(cfg, model, Clock())
    assert len(det.process(inbound(port=1))) == 1          # mean 0.95
    model.set("benign", 1.0)
    for port in range(2, 6):                                # mean drops below 0.85
        assert det.process(inbound(port=port)) == []


# --- window tracker ----------------------------------------------------------------------------

def test_window_tracker_groups_flows_per_source_ip() -> None:
    tracker = WindowTracker(window_ms=60_000, max_flows=100)
    tracker.add(ATTACKER, T0, {"portscan": 1.0, "benign": 0.0})
    tracker.add(OTHER, T0 + 1, {"portscan": 0.0, "benign": 1.0})
    a = tracker.add(ATTACKER, T0 + 2, {"portscan": 0.5, "benign": 0.5})
    assert a.flows == 2
    assert a.mean_proba["portscan"] == pytest.approx(0.75)
    b = tracker.summary(OTHER, T0 + 3)
    assert b.flows == 1 and b.mean_proba["benign"] == 1.0
    assert sorted(tracker.sources()) == [ATTACKER, OTHER]


def test_window_tracker_drops_flows_older_than_window() -> None:
    tracker = WindowTracker(window_ms=60_000, max_flows=100)
    tracker.add(ATTACKER, T0, {"dos": 1.0})
    tracker.add(ATTACKER, T0 + 30_000, {"dos": 0.0})
    assert tracker.summary(ATTACKER, T0 + 60_000).flows == 2
    assert tracker.summary(ATTACKER, T0 + 60_001).flows == 1
    assert tracker.summary(ATTACKER, T0 + 90_001).flows == 0
    assert tracker.sources() == []


def test_window_tracker_caps_flows_per_source() -> None:
    tracker = WindowTracker(window_ms=60_000, max_flows=3)
    for i in range(10):
        summary = tracker.add(ATTACKER, T0 + i, {"dos": float(i)})
    assert summary.flows == 3
    assert summary.mean_proba["dos"] == pytest.approx(8.0)  # newest three: 7, 8, 9


def test_detector_window_is_per_source_and_uses_configured_window(cfg: dict[str, Any]) -> None:
    fm = cfg["detectors"]["flow_model"]
    fm["window_s"] = 10
    fm["min_flows"] = 3
    clock = Clock()
    det = make(cfg, StubModel("portscan", 0.95), clock)
    # Two flows each from two sources: neither window has 3 flows.
    assert feed(det, 2, ATTACKER) == [] and feed(det, 2, OTHER) == []
    clock.now += 10_001  # past the window: the old flows drop out
    assert feed(det, 2, ATTACKER) == []
    assert det.tracker.summary(ATTACKER, clock.now).flows == 2
    signals = feed(det, 1, ATTACKER)
    assert [s.target for s in signals] == [ATTACKER]


# --- repeat suppression ------------------------------------------------------------------------

def test_one_signal_per_source_and_class_per_repeat_interval(cfg: dict[str, Any]) -> None:
    clock = Clock()
    det = make(cfg, StubModel("portscan", 0.95), clock)
    assert len(feed(det, 50)) == 1
    clock.now += cfg["detectors"]["flow_model"]["repeat_s"] * 1000
    assert len(feed(det, 5)) == 1
    assert len(feed(det, 5, OTHER)) == 1  # another source is not suppressed


# --- model loading -----------------------------------------------------------------------------

def test_missing_model_file_is_inert(cfg: dict[str, Any], tmp_path: Path,
                                     caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="agent.detectors.flow_model"):
        det = FlowModelDetector(cfg, model_path=tmp_path / "missing.joblib", clock=Clock())
    assert "Flow model not found" in caplog.text
    assert feed(det, 10) == []


def test_bare_model_with_classes_attribute(cfg: dict[str, Any]) -> None:
    model = StubModel("bruteforce", 0.9)
    model.classes_ = CLASSES  # type: ignore[attr-defined]
    det = FlowModelDetector(cfg, model=model, clock=Clock())
    signals = feed(det, cfg["detectors"]["flow_model"]["min_flows"])
    assert [s.mitre for s in signals] == ["T1110"]


def test_bundle_with_unknown_feature_is_inert(cfg: dict[str, Any]) -> None:
    model = StubModel("dos", 0.99)
    b = bundle(model)
    b["feature_names"] = ["src_ip"]
    det = FlowModelDetector(cfg, model=b, clock=Clock())
    assert feed(det, 10) == [] and model.calls == []


# --- pipeline / scoring ------------------------------------------------------------------------

def test_inbound_attack_blocks_source_ip_in_auto_mode(cfg: dict[str, Any],
                                                      tmp_path: Path) -> None:
    from agent.events import Action

    blocked: list[str] = []

    def block_ip(ip: str) -> Action:
        blocked.append(ip)
        return Action(id="a1", kind="block_ip", target=ip, rule_names=["HomeSOC block"])

    det = make(cfg, StubModel("portscan", 0.95), Clock())
    scorer = Scorer(cfg, mode="auto", allowlist=frozenset())
    published: list[Any] = []
    with Store(tmp_path / "db.sqlite") as store:
        pipeline = Pipeline([NamedDetector("flow_model", det.process)], scorer, store,
                            published.append, firewall_fns={"block_ip": block_ip},
                            proc_lookup=lambda pid, process="": None)
        for i in range(5):
            pipeline.handle(inbound(port=40000 + i))
        alerts = store.list_alerts(10)
    assert blocked == [ATTACKER]
    assert len(alerts) == 1 and alerts[0].action_ids == ["a1"]
