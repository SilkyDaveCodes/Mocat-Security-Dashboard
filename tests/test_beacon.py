"""Tests for agent.detectors.beacon: the C2 beaconing detector (CLAUDE.md §6.3).

All flows are synthetic FlowEvents; randomness is seeded so every run sees the same intervals.
"""

from __future__ import annotations

import copy
import itertools
import random
import re
from typing import Any

import pytest

from agent import config
from agent.detectors import beacon
from agent.detectors.beacon import BeaconDetector
from agent.events import FlowEvent, Signal

T0_MS = 1_700_000_000_000
C2_IP = "192.168.56.20"
C2_PORT = 8080
PROC = "freegamecheats.exe"


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def detector(cfg: dict[str, Any]) -> BeaconDetector:
    return BeaconDetector(cfg)


_source_ports = itertools.count(50000)


def flow(
    ts_ms: int,
    dst_ip: str = C2_IP,
    dst_port: int = C2_PORT,
    process: str = PROC,
    direction: str = "outbound",
    src_port: int | None = None,
    protocol: int = 6,
) -> FlowEvent:
    """One flow. By default each flow is a new connection (its own source port), like the lab
    sim's check-ins (§9.1); pass ``src_port`` to repeat a connection."""
    return FlowEvent(
        ts_ms=ts_ms,
        end_ms=ts_ms + 50,
        process=process,
        pid=4242,
        src_ip="192.168.56.10",
        src_port=next(_source_ports) if src_port is None else src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        direction=direction,  # type: ignore[arg-type]
    )


def jittered_starts(n: int, interval_s: float, jitter_s: float, seed: int = 42) -> list[int]:
    """``n`` start times ``interval_s`` apart, each shifted by up to ±``jitter_s`` (seeded)."""
    rng = random.Random(seed)
    return [
        T0_MS + int(round((i * interval_s + rng.uniform(-jitter_s, jitter_s)) * 1000))
        for i in range(n)
    ]


def feed(det: BeaconDetector, starts: list[int], **kwargs: Any) -> list[list[Signal]]:
    return [det.process(flow(ts, **kwargs)) for ts in starts]


# --- acceptance ---------------------------------------------------------------------------------


def test_beacon_every_5s_triggers_on_sixth_flow_with_score_0_9(detector: BeaconDetector) -> None:
    results = feed(detector, jittered_starts(6, 5.0, 0.1))

    assert all(r == [] for r in results[:5]), "flows 1-5 must not signal"
    assert len(results[5]) == 1
    sig = results[5][0]
    assert sig.score == pytest.approx(0.9)
    assert sig.detector == "beacon"
    assert sig.mitre == "T1071.001"
    assert sig.process == PROC
    assert sig.pid == 4242
    assert sig.target == C2_IP


def test_beacon_scores_0_95_from_twelfth_start(detector: BeaconDetector) -> None:
    results = feed(detector, jittered_starts(14, 5.0, 0.1))

    assert [r[0].score for r in results[5:11]] == [pytest.approx(0.9)] * 6  # starts 6..11
    assert [r[0].score for r in results[11:]] == [pytest.approx(0.95)] * 3  # starts 12..14


def test_random_intervals_do_not_trigger(detector: BeaconDetector) -> None:
    rng = random.Random(1234)
    ts = T0_MS
    starts = []
    for _ in range(20):
        ts += int(rng.uniform(2.0, 120.0) * 1000)
        starts.append(ts)

    assert all(r == [] for r in feed(detector, starts))


@pytest.mark.parametrize("interval_s", [1.0, 1.9, 601.0, 900.0])
def test_regular_interval_outside_2_to_600s_does_not_trigger(
    detector: BeaconDetector, interval_s: float
) -> None:
    starts = [T0_MS + int(i * interval_s * 1000) for i in range(15)]
    assert all(r == [] for r in feed(detector, starts))


@pytest.mark.parametrize("interval_s", [2.0, 600.0])
def test_regular_interval_at_bounds_triggers(detector: BeaconDetector, interval_s: float) -> None:
    starts = [T0_MS + int(i * interval_s * 1000) for i in range(6)]
    assert feed(detector, starts)[-1][0].score == pytest.approx(0.9)


def test_different_destinations_from_same_process_are_tracked_separately(
    detector: BeaconDetector,
) -> None:
    # Interleave 5 starts to C2:8080 and 5 starts to C2:443 and 5 to another IP:8080. Each pair
    # alone has only 5 starts, so nothing may fire, even though the process made 15 flows.
    a = jittered_starts(5, 5.0, 0.1, seed=1)
    for ts in a:
        assert detector.process(flow(ts)) == []
        assert detector.process(flow(ts + 1000, dst_port=443)) == []
        assert detector.process(flow(ts + 2000, dst_ip="192.168.56.30")) == []

    # The 6th start to C2:8080 fires, and its signal is about that pair only.
    sixth = a[-1] + 5000
    sigs = detector.process(flow(sixth))
    assert len(sigs) == 1
    assert sigs[0].target == C2_IP
    assert "port 8080" in sigs[0].reasons[1]
    assert "5.0 s" in sigs[0].reasons[0]

    # The 6th start to C2:443 fires separately; the other IP still has only 5 starts.
    sigs_443 = detector.process(flow(sixth + 1000, dst_port=443))
    assert len(sigs_443) == 1
    assert "port 443" in sigs_443[0].reasons[1]
    assert detector.process(flow(sixth + 2000, dst_ip="192.168.56.30", dst_port=9999)) == []


def test_same_destination_from_different_processes_is_tracked_separately(
    detector: BeaconDetector,
) -> None:
    starts = jittered_starts(5, 5.0, 0.1)
    for ts in starts:
        assert detector.process(flow(ts, process="a.exe")) == []
        assert detector.process(flow(ts + 1, process="b.exe")) == []
    assert detector.process(flow(starts[-1] + 5000, process="a.exe"))[0].process == "a.exe"


def test_reason_text_has_ip_mean_and_spread_in_spec_format(detector: BeaconDetector) -> None:
    # Intervals 4.8, 5.2, 4.8, 5.2, 4.8 s -> mean 4.96 (prints 5.0), pstdev 0.196 (prints 0.2).
    intervals = [4.8, 5.2, 4.8, 5.2, 4.8]
    starts = [T0_MS]
    for step in intervals:
        starts.append(starts[-1] + round(step * 1000))

    sig = feed(detector, starts)[-1][0]
    assert sig.reasons[0] == "checks in with 192.168.56.20 every 5.0 s (±0.2 s)"
    assert re.fullmatch(r"checks in with \S+ every \d+\.\d s \(±\d+\.\d s\)", sig.reasons[0])


# --- edge cases ---------------------------------------------------------------------------------


def test_signal_ts_ms_is_the_event_ts_ms(detector: BeaconDetector) -> None:
    starts = jittered_starts(6, 5.0, 0.1)
    assert feed(detector, starts)[-1][0].ts_ms == starts[-1]


def test_duplicate_start_times_are_ignored(detector: BeaconDetector) -> None:
    starts = jittered_starts(5, 5.0, 0.1)
    for ts in starts:
        detector.process(flow(ts))
    # Re-sending the 5th start must not count as a 6th start (or add a 0 s interval).
    assert detector.process(flow(starts[-1])) == []
    assert detector.process(flow(starts[-1] + 5000))[0].score == pytest.approx(0.9)


def test_out_of_order_starts_are_sorted(detector: BeaconDetector) -> None:
    starts = jittered_starts(6, 5.0, 0.1)
    shuffled = [starts[0], starts[2], starts[1], starts[4], starts[3], starts[5]]
    results = feed(detector, shuffled)
    assert results[-1][0].score == pytest.approx(0.9)
    assert "every 5.0 s" in results[-1][0].reasons[0]


def test_history_keeps_only_last_n_starts(cfg: dict[str, Any]) -> None:
    cfg["detectors"]["beacon"]["history"] = 6
    det = BeaconDetector(cfg)
    # 6 erratic starts, then regular ones 5 s apart. The last erratic start (200 s) is also the
    # first of the regular run, so after 5 more starts the window holds 6 regular starts and fires.
    erratic = [T0_MS + s * 1000 for s in (0, 3, 40, 47, 120, 200)]
    regular = [erratic[-1] + (i + 1) * 5000 for i in range(8)]
    results = feed(det, erratic + regular)
    assert all(r == [] for r in results[:10])
    # Fires from then on, but never reaches the 0.95 tier: only 6 starts are ever held.
    assert [r[0].score for r in results[10:]] == [pytest.approx(0.9)] * 4


def test_inbound_flows_are_ignored(detector: BeaconDetector) -> None:
    starts = jittered_starts(12, 5.0, 0.1)
    assert all(r == [] for r in feed(detector, starts, direction="inbound"))


def test_thresholds_come_from_config(cfg: dict[str, Any]) -> None:
    b = cfg["detectors"]["beacon"]
    b.update(min_starts=3, score=0.5, high_score=0.6, high_score_min_starts=4, cv_max=0.001)
    det = BeaconDetector(cfg)
    exact = [T0_MS + i * 10_000 for i in range(4)]
    results = feed(det, exact)
    assert results[1] == []
    assert results[2][0].score == pytest.approx(0.5)
    assert results[3][0].score == pytest.approx(0.6)
    # cv_max 0.001 rejects a ±0.1 s jitter that the default config accepts.
    assert all(r == [] for r in feed(BeaconDetector(cfg), jittered_starts(6, 5.0, 0.1)))


# --- one long-lived connection is not a beacon (ticket #49 FP test) ---------------------------


def test_keepalive_on_one_connection_does_not_trigger(detector: BeaconDetector) -> None:
    # A websocket ping every 30.0 s on one connection: NFStream emits a new flow per ping
    # (idle timeout), all on the same source port. That is one connection, not 20 check-ins.
    starts = [T0_MS + i * 30_000 for i in range(20)]
    assert all(r == [] for r in feed(detector, starts, dst_port=443, src_port=52974))


def test_active_timeout_chunks_of_one_download_do_not_trigger(detector: BeaconDetector) -> None:
    # A long download cut every 30 s by NFStream's active timeout: same 5-tuple each time.
    starts = jittered_starts(12, 30.0, 0.05)
    assert all(r == [] for r in feed(detector, starts, dst_port=80, src_port=57291))


def test_new_connections_still_trigger_among_repeats_of_another(detector: BeaconDetector) -> None:
    # A long-lived connection to the same IP:port, opened 5 s before the first check-in, sends
    # a packet every 7 s. Its repeats add no starts: had they been counted, the 7 s ones
    # interleaved with the 5 s check-ins would break the regularity and nothing would fire.
    for i in range(10):
        assert detector.process(flow(T0_MS - 5_000 + i * 7_000, src_port=40000)) == []
    results = feed(detector, jittered_starts(6, 5.0, 0.1))
    assert results[-1] and results[-1][0].score == pytest.approx(0.9)
    # 1 start from the long-lived connection + 6 new ones are held: 7 starts, not 16.
    assert "7 regular connections" in results[-1][0].reasons[1]


def test_same_source_port_over_another_protocol_is_a_new_connection(
    detector: BeaconDetector,
) -> None:
    starts = jittered_starts(6, 5.0, 0.1)
    results = [detector.process(flow(ts, src_port=50123, protocol=6 if i == 0 else 17))
               for i, ts in enumerate(starts)]
    # Starts 2..6 are one UDP connection: TCP start + 1 UDP start = 2 held, no signal.
    assert all(r == [] for r in results)


def test_flows_without_source_port_always_count_as_new(detector: BeaconDetector) -> None:
    # ICMP has no ports (NFStream reports 0): we can't tell connections apart, so each counts.
    results = feed(detector, jittered_starts(6, 5.0, 0.1), src_port=0, protocol=1)
    assert results[-1][0].score == pytest.approx(0.9)


def test_new_connections_only_can_be_turned_off(cfg: dict[str, Any]) -> None:
    cfg["detectors"]["beacon"]["new_connections_only"] = False
    det = BeaconDetector(cfg)
    starts = [T0_MS + i * 30_000 for i in range(6)]
    assert feed(det, starts, dst_port=443, src_port=52974)[-1][0].score == pytest.approx(0.9)


def test_new_connections_only_is_on_in_config(cfg: dict[str, Any]) -> None:
    assert cfg["detectors"]["beacon"]["new_connections_only"] is True


def test_module_level_process_uses_default_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(beacon, "_default_detector", None)
    results = [beacon.process(flow(ts)) for ts in jittered_starts(6, 5.0, 0.1)]
    assert results[-1][0].score == pytest.approx(0.9)
    assert isinstance(beacon._default_detector, BeaconDetector)
