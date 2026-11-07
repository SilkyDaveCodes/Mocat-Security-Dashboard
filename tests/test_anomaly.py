"""Tests for agent.detectors.anomaly: unusual uploads via IsolationForest (CLAUDE.md §6.3).

Every test uses synthetic FlowEvents, a fake clock and (where baselines matter) a real Store on a
tmp_path SQLite file. Traffic randomness is seeded so every run sees the same windows.
"""

from __future__ import annotations

import copy
import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent import config
from agent.detectors.anomaly import AnomalyDetector
from agent.events import FlowEvent, Signal
from agent.store import Store

T0_MS = 1_700_000_040_000  # a multiple of 60 s, so window i spans [T0 + 60i, T0 + 60(i+1))
WINDOW_MS = 60_000
PROC = "freegamecheats.exe"
OTHER = "notepad++.exe"
NEW_PROC = "brandnew.exe"
C2_IP = "192.168.56.20"
MB = 1_000_000


class FakeClock:
    def __init__(self, now_ms: int = T0_MS) -> None:
        self.now_ms = now_ms

    def __call__(self) -> int:
        return self.now_ms

    def advance_s(self, seconds: float) -> None:
        self.now_ms += int(seconds * 1000)

    def at_window(self, index: int, offset_s: float = 1.0) -> None:
        self.now_ms = T0_MS + index * WINDOW_MS + int(offset_s * 1000)


@pytest.fixture
def cfg() -> dict[str, Any]:
    cfg = copy.deepcopy(config.load())
    cfg["calibration"]["minutes"] = 35  # room for >= 30 windows per process during calibration
    return cfg


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "homesoc.db") as s:
        yield s


def flow(
    bytes_out: int,
    process: str = PROC,
    dst_ip: str = "203.0.113.10",
    direction: str = "outbound",
) -> FlowEvent:
    return FlowEvent(
        ts_ms=0,
        end_ms=0,
        process=process,
        pid=4242,
        src_ip="192.168.56.10",
        src_port=50000,
        dst_ip=dst_ip,
        dst_port=443,
        protocol=6,
        bytes_out=bytes_out,
        direction=direction,  # type: ignore[arg-type]
    )


def steady_window(
    det: AnomalyDetector, rng: random.Random, process: str = PROC
) -> list[Signal]:
    """A small, ordinary minute: 3-5 flows of ~20-40 KB each to 1-3 addresses."""
    out: list[Signal] = []
    for i in range(rng.randint(3, 5)):
        dst = f"203.0.113.{10 + i % rng.randint(1, 3)}"
        out += det.process(flow(rng.randint(20_000, 40_000), process=process, dst_ip=dst))
    return out


def calibrate(
    det: AnomalyDetector,
    clock: FakeClock,
    windows: int,
    processes: tuple[str, ...] = (PROC,),
    seed: int = 42,
) -> list[Signal]:
    """Feed ``windows`` steady minutes per process, then move to the next window and close them."""
    rng = random.Random(seed)
    out: list[Signal] = []
    for i in range(windows):
        clock.at_window(i)
        for proc in processes:
            out += steady_window(det, rng, proc)
    clock.at_window(windows)
    det.tick()
    return out


def upload(det: AnomalyDetector, total_bytes: int, process: str = PROC) -> list[Signal]:
    """A big upload to the lab C2 in one flow (like the simulator's single ~20 MB POST)."""
    return det.process(flow(total_bytes, process=process, dst_ip=C2_IP))


def past_calibration(det: AnomalyDetector, clock: FakeClock) -> None:
    """Move the clock (forward only) into a window that starts after calibration ended."""
    start = max(clock.now_ms, det.calibration_end_ms)
    clock.now_ms = (start // WINDOW_MS + 1) * WINDOW_MS + 1000
    det.tick()
    assert not det.calibrating()


# --- acceptance ---------------------------------------------------------------------------------


def test_no_signals_during_calibration(cfg: dict[str, Any], clock: FakeClock) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    assert det.calibrating()
    signals = calibrate(det, clock, windows=31)
    # Even a 20 MB upload inside the calibration period stays silent.
    clock.at_window(31)
    signals += upload(det, 20 * MB)
    assert det.calibrating()
    assert signals == []
    assert len(det.baseline(PROC)) == 31


def test_20mb_upload_after_calibration_signals(cfg: dict[str, Any], clock: FakeClock) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    calibrate(det, clock, windows=33)
    past_calibration(det, clock)

    signals = upload(det, 20 * MB)

    assert len(signals) == 1
    sig = signals[0]
    assert sig.detector == "anomaly"
    assert sig.mitre == "T1041"
    assert 0.6 <= sig.score <= 0.9
    assert sig.process == PROC
    assert sig.pid == 4242
    assert sig.target == C2_IP
    assert sig.reasons[0].startswith("uploaded 20.0 MB in 60 s, far above its usual 0.1 MB")
    assert det.assess(PROC, [20 * MB, 1, 1]).model == "process"


def test_anomalous_window_under_10mb_does_not_signal(
    cfg: dict[str, Any], clock: FakeClock
) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    calibrate(det, clock, windows=33)
    past_calibration(det, clock)

    # The model itself calls a 5 MB minute anomalous...
    assessment = det.assess(PROC, [5 * MB, 1, 1])
    assert assessment is not None and assessment.anomalous
    # ...but it is under the 10 MB bar, so no Signal.
    assert upload(det, 5 * MB) == []
    # Exactly at the threshold is not "over" it either.
    clock.advance_s(60)
    assert upload(det, 10 * MB) == []


def test_thin_process_is_scored_by_global_model(cfg: dict[str, Any], clock: FakeClock) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    calibrate(det, clock, windows=33, processes=(PROC, OTHER))
    # NEW_PROC only shows up for 5 calibration minutes.
    rng = random.Random(7)
    for i in range(33, 38):
        clock.at_window(i)
        steady_window(det, rng, NEW_PROC)
    past_calibration(det, clock)
    assert len(det.baseline(NEW_PROC)) == 5
    assert len(det.baseline(OTHER)) >= 30

    thin = det.assess(NEW_PROC, [20 * MB, 1, 1])
    assert thin is not None and thin.model == "global" and thin.anomalous
    unseen = det.assess("never-seen.exe", [20 * MB, 1, 1])
    assert unseen is not None and unseen.model == "global"
    assert det.assess(OTHER, [20 * MB, 1, 1]).model == "process"

    signals = upload(det, 20 * MB, process=NEW_PROC)
    assert len(signals) == 1
    assert signals[0].process == NEW_PROC
    assert 0.6 <= signals[0].score <= 0.9
    assert "apps on this PC usually upload" in signals[0].reasons[0]


def test_baselines_reload_after_restart(
    cfg: dict[str, Any], clock: FakeClock, tmp_path: Path
) -> None:
    db = tmp_path / "homesoc.db"
    with Store(db) as store:
        det = AnomalyDetector(cfg, store=store, clock=clock)
        calibrate(det, clock, windows=33, processes=(PROC, OTHER))
        saved = det.baseline(PROC)
        calibration_end = det.calibration_end_ms
        assert len(saved) == 33
        assert store.load_baseline(PROC)["windows"] == saved

    # Restart shortly after calibration ended: a fresh detector would calibrate again,
    # the reloaded one must not.
    clock.now_ms = calibration_end + 2 * WINDOW_MS + 1000
    with Store(db) as store:
        restarted = AnomalyDetector(cfg, store=store, clock=clock)
        assert restarted.baseline(PROC) == saved
        assert restarted.baseline(OTHER) == det.baseline(OTHER)
        assert restarted.calibration_end_ms == calibration_end
        assert not restarted.calibrating()

        signals = upload(restarted, 20 * MB)
        assert len(signals) == 1 and signals[0].mitre == "T1041"
        assert restarted.assess(PROC, [20 * MB, 1, 1]).model == "process"


# --- behaviour details --------------------------------------------------------------------------


def test_restart_mid_calibration_resumes_stored_end(
    cfg: dict[str, Any], clock: FakeClock, store: Store
) -> None:
    det = AnomalyDetector(cfg, store=store, clock=clock)
    calibrate(det, clock, windows=3)
    clock.advance_s(5)
    restarted = AnomalyDetector(cfg, store=store, clock=clock)
    assert restarted.calibration_end_ms == det.calibration_end_ms
    assert restarted.calibrating()
    assert upload(restarted, 20 * MB) == []


def test_one_signal_per_process_per_window(cfg: dict[str, Any], clock: FakeClock) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    calibrate(det, clock, windows=33)
    past_calibration(det, clock)
    assert len(upload(det, 20 * MB)) == 1
    assert upload(det, 20 * MB) == []  # same minute: already flagged
    clock.advance_s(60)
    assert len(upload(det, 20 * MB)) == 1  # a new minute can signal again


def test_learns_normal_windows_after_calibration_but_not_flagged_ones(
    cfg: dict[str, Any], clock: FakeClock
) -> None:
    cfg["calibration"]["minutes"] = 10  # the demo setting: <= 10 windows during calibration
    det = AnomalyDetector(cfg, clock=clock)
    calibrate(det, clock, windows=40)
    assert len(det.baseline(PROC)) == 40  # 10 calibration + 30 learned afterwards

    clock.at_window(40)
    assert len(upload(det, 20 * MB)) == 1
    clock.at_window(41)
    det.tick()
    assert len(det.baseline(PROC)) == 40  # the flagged upload minute was not learned


def test_no_baseline_means_no_signal(cfg: dict[str, Any], clock: FakeClock) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    past_calibration(det, clock)
    assert det.assess(PROC, [20 * MB, 1, 1]) is None
    assert upload(det, 20 * MB) == []


def test_inbound_flows_are_ignored(cfg: dict[str, Any], clock: FakeClock) -> None:
    det = AnomalyDetector(cfg, clock=clock)
    calibrate(det, clock, windows=33)
    past_calibration(det, clock)
    assert det.process(flow(20 * MB, direction="inbound")) == []
    clock.advance_s(60)
    det.tick()
    assert len(det.baseline(PROC)) == 33


def test_defaults_when_anomaly_section_absent(cfg: dict[str, Any], clock: FakeClock) -> None:
    del cfg["detectors"]["anomaly"]
    del cfg["calibration"]
    det = AnomalyDetector(cfg, clock=clock)
    assert det.calibration_end_ms == T0_MS + 10 * 60 * 1000
    calibrate(det, clock, windows=40)
    clock.at_window(40)
    signals = upload(det, 20 * MB)
    assert len(signals) == 1 and 0.6 <= signals[0].score <= 0.9
