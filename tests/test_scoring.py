"""Tests for agent.scoring: risk combination and the response policy (CLAUDE.md §6.4).

Every test uses synthetic Signals, an explicit allowlist and a fake clock, so no OS calls happen.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from agent import config
from agent.config import Allowlist
from agent.events import Action, Signal
from agent.procinfo import ProcInfo
from agent.scoring import Scorer, combine_risk, finalize_alert, has_risky_context

T0_MS = 1_700_000_000_000
PROC = "freegamecheats.exe"
EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"
C2_IP = "192.168.56.20"
ATTACKER_IP = "192.168.56.30"

SIGNED_SAFE = ProcInfo(pid=42, name=PROC, exe_path=r"C:\Program Files\Game\game.exe",
                       in_risky_dir=False, signed=True)
UNSIGNED = ProcInfo(pid=42, name=PROC, exe_path=r"C:\Program Files\Game\game.exe",
                    in_risky_dir=False, signed=False)
RISKY_DIR = ProcInfo(pid=42, name=PROC, exe_path=EXE, in_risky_dir=True, signed=True)
UNKNOWN = ProcInfo(pid=42, name=PROC, exe_path=None, in_risky_dir=None, signed=None)
CHROME = ProcInfo(pid=7, name="chrome.exe",
                  exe_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                  in_risky_dir=False, signed=True)


class FakeClock:
    def __init__(self, now_ms: int = T0_MS) -> None:
        self.now_ms = now_ms

    def __call__(self) -> int:
        return self.now_ms

    def advance_s(self, seconds: float) -> None:
        self.now_ms += int(seconds * 1000)


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_scorer(cfg: dict[str, Any], clock: FakeClock, mode: str = "auto") -> Scorer:
    allowlist = Allowlist(names=frozenset({"chrome.exe", "msedge.exe"}))
    return Scorer(cfg, allowlist, clock=clock, mode=mode)


def sig(detector: str, score: float, process: str = PROC, target: str = C2_IP,
        mitre: str | None = None) -> Signal:
    return Signal(detector=detector, process=process, pid=42, target=target, score=score,
                  reasons=[f"{detector} reason"], mitre=mitre, ts_ms=T0_MS)


# --- risk combination -----------------------------------------------------------------------


def test_two_detectors_combine_to_0_8(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    scorer.add(sig("dga", 0.5), SIGNED_SAFE)
    decision = scorer.add(sig("beacon", 0.6), SIGNED_SAFE)
    assert decision.risk == pytest.approx(0.8)
    assert sorted(decision.detectors) == ["beacon", "dga"]


def test_same_detector_counts_once_with_highest_score(
    cfg: dict[str, Any], clock: FakeClock
) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    scorer.add(sig("dga", 0.5), SIGNED_SAFE)
    decision = scorer.add(sig("dga", 0.6), SIGNED_SAFE)
    assert decision.risk == pytest.approx(0.6)
    assert decision.detectors == ["dga"]
    # Order does not matter: a later lower score does not replace the higher one.
    decision = scorer.add(sig("dga", 0.3), SIGNED_SAFE)
    assert decision.risk == pytest.approx(0.6)
    assert combine_risk([sig("dga", 0.5), sig("dga", 0.6)]) == pytest.approx(0.6)


# --- context boost --------------------------------------------------------------------------


@pytest.mark.parametrize("proc", [UNSIGNED, RISKY_DIR], ids=["unsigned", "risky_dir"])
def test_context_boost_for_unsigned_or_risky_dir(
    cfg: dict[str, Any], clock: FakeClock, proc: ProcInfo
) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    decision = scorer.add(sig("dga", 0.5), proc)
    assert decision.risk == pytest.approx(0.6)  # 0.5 x 1.2


def test_context_boost_capped_at_1(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    decision = scorer.add(sig("beacon", 0.95), UNSIGNED)  # 0.95 x 1.2 = 1.14
    assert decision.risk == pytest.approx(1.0)
    assert combine_risk([sig("intel", 1.0)], boost=1.2) == 1.0


@pytest.mark.parametrize("proc", [SIGNED_SAFE, UNKNOWN, None], ids=["signed", "unknown", "none"])
def test_no_boost_for_signed_or_unknown_context(
    cfg: dict[str, Any], clock: FakeClock, proc: ProcInfo | None
) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    decision = scorer.add(sig("dga", 0.5), proc)
    assert decision.risk == pytest.approx(0.5)
    assert has_risky_context(proc) is False


# --- severity boundaries --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0.5, "medium"), (0.74, "medium"), (0.75, "high"), (0.89, "high"),
     (0.9, "critical"), (1.0, "critical")],
)
def test_severity_boundaries(
    cfg: dict[str, Any], clock: FakeClock, score: float, severity: str
) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    decision = scorer.add(sig("beacon", score), SIGNED_SAFE)
    assert decision.alert is not None
    assert decision.alert.severity == severity
    assert decision.alert.risk == pytest.approx(score)


def test_severity_boundary_survives_float_error(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock)
    assert scorer.severity_for(0.9 - 1e-12) == "critical"
    assert scorer.severity_for(0.75 - 1e-12) == "high"
    assert scorer.severity_for(0.5 - 1e-12) == "medium"


@pytest.mark.parametrize("score", [0.0, 0.3, 0.49])
def test_risk_below_0_5_makes_no_alert(
    cfg: dict[str, Any], clock: FakeClock, score: float
) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("beacon", score), UNKNOWN)
    assert decision.alert is None
    assert decision.action is None
    assert scorer.severity_for(score) is None


# --- response policy ------------------------------------------------------------------------


def test_auto_intel_hit_requests_quarantine(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("intel", 1.0, mitre="T1071"), RISKY_DIR)
    assert decision.alert is not None
    assert decision.alert.severity == "critical"
    assert decision.alert.exe_path == EXE
    assert decision.action is not None
    assert decision.action.kind == "quarantine_app"
    assert decision.action.target == EXE
    assert "quarantined" in decision.alert.what_we_did


def test_auto_high_risk_single_detector_alerts_only(
    cfg: dict[str, Any], clock: FakeClock
) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("beacon", 0.9), SIGNED_SAFE)
    assert decision.risk == pytest.approx(0.9)
    assert decision.alert is not None
    assert decision.action is None


def test_auto_two_detectors_high_risk_requests_quarantine(
    cfg: dict[str, Any], clock: FakeClock
) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    scorer.add(sig("dga", 0.8), RISKY_DIR)
    decision = scorer.add(sig("beacon", 0.9), RISKY_DIR)
    assert decision.risk >= 0.85
    assert decision.action is not None
    assert decision.action.kind == "quarantine_app"


@pytest.mark.parametrize("mode", ["notify", "off"])
def test_notify_and_off_never_act(cfg: dict[str, Any], clock: FakeClock, mode: str) -> None:
    scorer = make_scorer(cfg, clock, mode=mode)
    first = scorer.add(sig("intel", 1.0), RISKY_DIR)
    second = scorer.add(sig("beacon", 0.95), RISKY_DIR)
    inbound = scorer.add(sig("flow_model", 0.95, process="svchost.exe", target=ATTACKER_IP,
                             mitre="T1110"))
    assert first.alert is not None
    assert all(d.action is None for d in (first, second, inbound))
    assert "Nothing was blocked" in first.alert.what_we_did


def test_allowlisted_process_with_intel_hit_alerts_only(
    cfg: dict[str, Any], clock: FakeClock
) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("intel", 1.0, process="Chrome.EXE"), CHROME)
    assert decision.allowlisted is True
    assert decision.alert is not None
    assert decision.action is None
    assert "trusted apps list" in decision.alert.what_we_did


def test_unknown_exe_path_intel_hit_alerts_only(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("intel", 1.0), UNKNOWN)
    assert decision.alert is not None
    assert decision.action is None


def test_inbound_flow_model_blocks_source_ip(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(
        sig("flow_model", 0.9, process="svchost.exe", target=ATTACKER_IP, mitre="T1110"),
        SIGNED_SAFE,
    )
    assert decision.alert is not None
    assert decision.action is not None
    assert decision.action.kind == "block_ip"
    assert decision.action.target == ATTACKER_IP


def test_inbound_flow_model_never_blocks_loopback(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("flow_model", 0.95, target="127.0.0.1", mitre="T1046"))
    assert decision.alert is not None
    assert decision.action is None


def test_same_action_is_requested_once_per_window(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    first = scorer.add(sig("intel", 1.0), RISKY_DIR)
    again = scorer.add(sig("intel", 1.0), RISKY_DIR)
    assert first.action is not None
    assert again.action is None
    assert again.alert is None  # nothing new: same severity, same detectors


def test_new_detector_raises_a_new_alert(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    assert scorer.add(sig("dga", 0.6), SIGNED_SAFE).alert is not None
    assert scorer.add(sig("dga", 0.6), SIGNED_SAFE).alert is None
    escalated = scorer.add(sig("beacon", 0.9), SIGNED_SAFE)
    assert escalated.alert is not None
    assert escalated.alert.severity == "critical"
    assert len(escalated.alert.signals) == 3


# --- window ---------------------------------------------------------------------------------


def test_signals_older_than_60s_drop_out(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    scorer.add(sig("dga", 0.5), SIGNED_SAFE)
    clock.advance_s(30)
    assert scorer.add(sig("beacon", 0.6), SIGNED_SAFE).risk == pytest.approx(0.8)
    clock.advance_s(31)  # dga signal is now 61 s old; beacon is 31 s old
    decision = scorer.add(sig("anomaly", 0.0), SIGNED_SAFE)
    assert decision.risk == pytest.approx(0.6)
    assert "dga" not in decision.detectors
    clock.advance_s(60)
    assert scorer.risk_of(PROC) == 0.0


def test_expired_window_allows_a_fresh_action(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    assert scorer.add(sig("intel", 1.0), RISKY_DIR).action is not None
    clock.advance_s(61)
    assert scorer.add(sig("intel", 1.0), RISKY_DIR).action is not None


def test_prune_drops_empty_windows(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="notify")
    scorer.add(sig("dga", 0.6), SIGNED_SAFE)
    clock.advance_s(61)
    scorer.prune()
    assert scorer._windows == {}


# --- misc -----------------------------------------------------------------------------------


def test_finalize_alert_attaches_action_ids(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock, mode="auto")
    decision = scorer.add(sig("intel", 1.0), RISKY_DIR)
    action = Action(id="act-1", kind="quarantine_app", target=EXE,
                    rule_names=["HomeSOC quarantine x out"])
    alert = finalize_alert(decision, [action])
    assert alert.action_ids == ["act-1"]
    assert "quarantined" in alert.what_we_did
    failed = finalize_alert(decision, [])
    assert failed.action_ids == []
    assert "Nothing was blocked" in failed.what_we_did


def test_invalid_mode_rejected(cfg: dict[str, Any], clock: FakeClock) -> None:
    scorer = make_scorer(cfg, clock)
    with pytest.raises(ValueError):
        scorer.mode = "panic"


def test_thresholds_come_from_config(cfg: dict[str, Any], clock: FakeClock) -> None:
    cfg["scoring"]["alert_threshold"] = 0.7
    cfg["scoring"]["severity"]["medium"] = 0.7
    scorer = make_scorer(cfg, clock, mode="notify")
    assert scorer.add(sig("dga", 0.6), SIGNED_SAFE).alert is None
    assert scorer.add(sig("beacon", 0.5), SIGNED_SAFE).risk == pytest.approx(0.8)
    assert scorer.severity_for(0.8) == "high"
