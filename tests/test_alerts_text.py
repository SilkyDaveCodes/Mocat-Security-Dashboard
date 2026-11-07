"""Tests for agent/alerts_text.py (ticket #14)."""

import logging

import pytest

from agent.alerts_text import AlertText, build_alert_text, mitre_ids
from agent.events import Action, Alert, Signal

PROC = "freegamecheats.exe"
EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"
C2 = "192.168.56.20"


def _dga() -> Signal:
    return Signal(
        detector="dga",
        process=PROC,
        target="xkqzjwpvtr.com",
        score=0.93,
        reasons=["looked up xkqzjwpvtr.com, which looks machine-generated (DGA model 0.93)"],
        mitre="T1568.002",
    )


def _beacon() -> Signal:
    return Signal(
        detector="beacon",
        process=PROC,
        target=C2,
        score=0.9,
        reasons=[f"checks in with {C2} every 5.0 s (±0.2 s)"],
        mitre="T1071.001",
    )


def _quarantine() -> Action:
    return Action(
        id="a1",
        kind="quarantine_app",
        target=EXE,
        rule_names=["HomeSOC quarantine FreeGameCheats.exe out"],
    )


def _all_text(t: AlertText) -> str:
    return " ".join([t.title, t.what_happened, t.what_we_did, t.what_you_should_do])


# --- AC1: DGA + beacon on freegamecheats.exe ---------------------------------------------


def test_dga_and_beacon_what_happened_names_process_and_both_behaviors() -> None:
    t = build_alert_text(PROC, [_dga(), _beacon()], [_quarantine()], mode="auto")
    text = t.what_happened
    assert PROC in text
    assert "random-looking web addresses" in text  # DGA in plain words
    assert "xkqzjwpvtr.com" in text
    assert f"keeps checking in with {C2} on a regular timer" in text  # beacon in plain words
    assert "every 5.0 s" in text  # detector reason kept as a detail
    assert t.title == f"{PROC} is acting like malware"


# --- AC2: what_we_did ---------------------------------------------------------------------


def test_what_we_did_says_quarantined_with_quarantine_action() -> None:
    t = build_alert_text(PROC, [_dga(), _beacon()], [_quarantine()], mode="auto")
    assert "We quarantined FreeGameCheats.exe" in t.what_we_did
    assert "stops it from using the network" in t.what_we_did
    assert "undo" in t.what_we_did
    assert "Nothing was blocked" not in t.what_we_did
    assert "undo the quarantine" in t.what_you_should_do


def test_what_we_did_says_nothing_blocked_without_actions() -> None:
    t = build_alert_text(PROC, [_dga(), _beacon()], [], mode="auto")
    assert t.what_we_did.startswith("Nothing was blocked")
    assert "quarantined" not in t.what_we_did


def test_nothing_blocked_explains_notify_mode() -> None:
    t = build_alert_text(PROC, [_beacon()], [], mode="notify")
    assert t.what_we_did.startswith("Nothing was blocked")
    assert "Notify mode" in t.what_we_did
    assert "Auto-protect" in t.what_we_did


def test_nothing_blocked_explains_allowlisted_app() -> None:
    t = build_alert_text("chrome.exe", [_beacon()], [], mode="auto", allowlisted=True)
    assert t.what_we_did.startswith("Nothing was blocked")
    assert "chrome.exe is on your trusted apps list" in t.what_we_did
    assert "Notify mode" not in t.what_we_did
    assert "trusted app" in t.what_you_should_do


def test_nothing_blocked_explains_off_mode() -> None:
    t = build_alert_text(PROC, [_beacon()], [], mode="off")
    assert "protection is turned off" in t.what_we_did


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (Action(kind="block_ip", target=C2), f"We blocked all traffic to and from {C2}"),
        (Action(kind="kill_process", target=EXE), "We stopped FreeGameCheats.exe from running"),
        (Action(kind="undo", target=C2), f"We removed an earlier HomeSOC block ({C2})"),
    ],
)
def test_every_action_kind_has_text(action: Action, expected: str) -> None:
    t = build_alert_text(PROC, [_beacon()], [action], mode="auto")
    assert expected in t.what_we_did


def test_undone_action_is_reported_as_undone() -> None:
    action = Action(kind="quarantine_app", target=EXE, undone=True)
    t = build_alert_text(PROC, [_beacon()], [action], mode="auto")
    assert "later undone" in t.what_we_did
    assert "undo this at any time" not in t.what_we_did


# --- AC3: every detector has a template; unknown falls back ------------------------------


@pytest.mark.parametrize(
    ("signal", "phrase", "title"),
    [
        (
            Signal(detector="intel", target="10.9.9.9", mitre="T1071"),
            "known malicious servers",
            f"{PROC} contacted a known malicious server",
        ),
        (_dga(), "random-looking web addresses", f"{PROC} looked up suspicious random"),
        (_beacon(), "regular timer", f"{PROC} is secretly checking in"),
        (
            Signal(detector="anomaly", target="203.0.113.5", mitre="T1041"),
            "unusually large amount of data",
            f"{PROC} sent out an unusual amount of data",
        ),
        (
            Signal(detector="flow_model", target="192.168.56.30", mitre="T1110"),
            "trying to guess a password",
            "Your PC is being attacked from 192.168.56.30",
        ),
    ],
)
def test_every_detector_has_a_template(signal: Signal, phrase: str, title: str) -> None:
    t = build_alert_text(PROC, [signal])
    assert phrase in t.what_happened
    assert signal.target in t.what_happened
    assert t.title.startswith(title)
    assert "flagged by the" not in t.what_happened  # not the generic fallback


@pytest.mark.parametrize(
    ("mitre", "phrase"),
    [("T1046", "port scan"), ("T1110", "brute-force"), ("T1498", "denial-of-service")],
)
def test_flow_model_names_each_attack_kind(mitre: str, phrase: str) -> None:
    t = build_alert_text("unknown", [Signal(detector="flow_model", target="1.2.3.4", mitre=mitre)])
    assert phrase in t.what_happened
    assert "block the attacking address" in t.what_you_should_do


def test_unknown_detector_falls_back_to_generic_text(caplog: pytest.LogCaptureFixture) -> None:
    weird = Signal(target="198.51.100.7", reasons=["odd thing"], mitre="T9999")
    weird.detector = "future_detector"  # type: ignore[assignment]
    with caplog.at_level(logging.WARNING, logger="agent.alerts_text"):
        t = build_alert_text(PROC, [weird])
    assert "flagged by the future_detector check" in t.what_happened
    assert "198.51.100.7" in t.what_happened
    assert t.title == f"Suspicious activity from {PROC}"
    assert t.what_we_did and t.what_you_should_do
    assert "future_detector" in caplog.text


def test_unknown_action_kind_falls_back_to_generic_text() -> None:
    action = Action(target="x")
    action.kind = "sandbox"  # type: ignore[assignment]
    t = build_alert_text(PROC, [_beacon()], [action], mode="auto")
    assert "protective action (sandbox)" in t.what_we_did


def test_no_signals_still_produces_text() -> None:
    t = build_alert_text(PROC, [])
    assert PROC in t.title and PROC in t.what_happened
    assert t.mitre == []


# --- AC4: MITRE IDs ----------------------------------------------------------------------


def test_all_mitre_ids_appear_in_output() -> None:
    signals = [
        _dga(),
        _beacon(),
        Signal(detector="anomaly", target="203.0.113.5", mitre="T1041"),
        Signal(detector="intel", target=C2, mitre="T1071"),
    ]
    t = build_alert_text(PROC, signals, [_quarantine()], mode="auto")
    for mid in ("T1568.002", "T1071.001", "T1041", "T1071"):
        assert mid in t.what_happened
        assert mid in t.mitre
    assert "MITRE ATT&CK: T1568.002, T1071.001, T1041, T1071" in t.what_happened


def test_mitre_ids_are_deduplicated_in_order() -> None:
    signals = [_beacon(), _dga(), _beacon(), Signal(detector="intel", mitre=None)]
    assert mitre_ids(signals) == ["T1071.001", "T1568.002"]
    t = build_alert_text(PROC, signals)
    assert t.what_happened.count("T1071.001") == 1
    assert t.mitre == ["T1071.001", "T1568.002"]


# --- integration with the Alert dataclass ------------------------------------------------


def test_as_fields_fills_an_alert() -> None:
    t = build_alert_text(PROC, [_dga(), _beacon()], [_quarantine()], mode="auto")
    alert = Alert(process=PROC, **t.as_fields())
    assert alert.title == t.title
    assert alert.what_we_did == t.what_we_did
    assert PROC in _all_text(t)
