"""Tests for agent.events: the shared event contract (CLAUDE.md §5) and to_json()."""

from __future__ import annotations

import dataclasses
import json
import typing
from typing import Any, Literal

import pytest

from agent.events import Action, Alert, FlowEvent, Signal, to_json

# --- §5, written out by hand: (name, type, default) in declaration order ---------------------
# A default of `list` / `dict` means "default_factory=list / dict".

FLOW_EVENT_SPEC: list[tuple[str, Any, Any]] = [
    ("type", Literal["flow"], "flow"),
    ("ts_ms", int, 0),
    ("end_ms", int, 0),
    ("process", str, "unknown"),
    ("pid", int, -1),
    ("exe_path", str | None, None),
    ("src_ip", str, ""),
    ("src_port", int, 0),
    ("dst_ip", str, ""),
    ("dst_port", int, 0),
    ("protocol", int, 0),
    ("hostname", str | None, None),
    ("app_proto", str | None, None),
    ("bytes_out", int, 0),
    ("bytes_in", int, 0),
    ("packets", int, 0),
    ("direction", Literal["outbound", "inbound"], "outbound"),
    ("features", dict, dict),
]

SIGNAL_SPEC: list[tuple[str, Any, Any]] = [
    ("type", Literal["signal"], "signal"),
    ("detector", Literal["intel", "dga", "beacon", "anomaly", "flow_model"], "intel"),
    ("process", str, "unknown"),
    ("pid", int, -1),
    ("target", str, ""),
    ("score", float, 0.0),
    ("reasons", list[str], list),
    ("mitre", str | None, None),
    ("ts_ms", int, 0),
]

ALERT_SPEC: list[tuple[str, Any, Any]] = [
    ("type", Literal["alert"], "alert"),
    ("id", str, ""),
    ("ts_ms", int, 0),
    ("severity", Literal["low", "medium", "high", "critical"], "low"),
    ("process", str, "unknown"),
    ("exe_path", str | None, None),
    ("risk", float, 0.0),
    ("title", str, ""),
    ("what_happened", str, ""),
    ("what_we_did", str, ""),
    ("what_you_should_do", str, ""),
    ("signals", list[Signal], list),
    ("action_ids", list[str], list),
]

ACTION_SPEC: list[tuple[str, Any, Any]] = [
    ("type", Literal["action"], "action"),
    ("id", str, ""),
    ("ts_ms", int, 0),
    ("kind", Literal["block_ip", "quarantine_app", "kill_process", "undo"], "block_ip"),
    ("target", str, ""),
    ("rule_names", list[str], list),
    ("undone", bool, False),
]

SPECS = [
    pytest.param(FlowEvent, FLOW_EVENT_SPEC, id="FlowEvent"),
    pytest.param(Signal, SIGNAL_SPEC, id="Signal"),
    pytest.param(Alert, ALERT_SPEC, id="Alert"),
    pytest.param(Action, ACTION_SPEC, id="Action"),
]


def _sample_signal(detector: str = "beacon", target: str = "192.168.56.20") -> Signal:
    return Signal(
        detector=detector,  # type: ignore[arg-type]
        process="freegamecheats.exe",
        pid=4242,
        target=target,
        score=0.9,
        reasons=["checks in with 192.168.56.20 every 5.0 s (±0.2 s)"],
        mitre="T1071.001",
        ts_ms=1_700_000_000_000,
    )


def _sample_alert() -> Alert:
    return Alert(
        id="alert-1",
        ts_ms=1_700_000_005_000,
        severity="critical",
        process="freegamecheats.exe",
        exe_path=r"C:\Users\demo\Downloads\FreeGameCheats.exe",
        risk=0.97,
        title="FreeGameCheats.exe is talking to a command server",
        what_happened="It checked in every 5 seconds.",
        what_we_did="We quarantined the app.",
        what_you_should_do="Delete the file.",
        signals=[
            _sample_signal("beacon"),
            _sample_signal("dga", target="xkqjzvbwpl.example"),
        ],
        action_ids=["action-1"],
    )


SAMPLES = [
    pytest.param(
        FlowEvent(
            ts_ms=1_700_000_000_000,
            end_ms=1_700_000_000_250,
            process="chrome.exe",
            pid=1234,
            exe_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            src_ip="192.168.56.10",
            src_port=50123,
            dst_ip="192.168.56.20",
            dst_port=443,
            protocol=6,
            hostname="example.com",
            app_proto="TLS",
            bytes_out=1200,
            bytes_in=5600,
            packets=14,
            direction="outbound",
            features={"bidirectional_mean_ps": 512.5, "src2dst_packets": 7},
        ),
        "flow",
        id="FlowEvent",
    ),
    pytest.param(_sample_signal(), "signal", id="Signal"),
    pytest.param(_sample_alert(), "alert", id="Alert"),
    pytest.param(
        Action(
            id="action-1",
            ts_ms=1_700_000_005_000,
            kind="quarantine_app",
            target=r"C:\Users\demo\Downloads\FreeGameCheats.exe",
            rule_names=[
                "HomeSOC quarantine FreeGameCheats.exe out",
                "HomeSOC quarantine FreeGameCheats.exe in",
            ],
            undone=False,
        ),
        "action",
        id="Action",
    ),
]


def _rebuild(cls: type, data: dict) -> Any:
    """Reconstruct a dataclass from a to_json() dict (Alert's signals rebuilt as Signals)."""
    if cls is Alert:
        data = {**data, "signals": [Signal(**s) for s in data["signals"]]}
    return cls(**data)


# --- AC1: all four dataclasses exist with the §5 fields, types and defaults -----------------


@pytest.mark.parametrize(("cls", "spec"), SPECS)
def test_fields_match_spec_names_and_order(cls: type, spec: list) -> None:
    assert dataclasses.is_dataclass(cls)
    assert [f.name for f in dataclasses.fields(cls)] == [name for name, _, _ in spec]


@pytest.mark.parametrize(("cls", "spec"), SPECS)
def test_field_types_match_spec(cls: type, spec: list) -> None:
    hints = typing.get_type_hints(cls)
    for name, expected_type, _ in spec:
        assert hints[name] == expected_type, name


@pytest.mark.parametrize(("cls", "spec"), SPECS)
def test_construct_with_defaults_matches_spec(cls: type, spec: list) -> None:
    obj = cls()
    for name, _, default in spec:
        value = getattr(obj, name)
        if default in (list, dict):
            assert type(value) is default and value == default(), name
        else:
            assert type(value) is type(default) and value == default, name


@pytest.mark.parametrize(("cls", "spec"), SPECS)
def test_mutable_fields_use_default_factory(cls: type, spec: list) -> None:
    for f in dataclasses.fields(cls):
        expected = next(d for name, _, d in spec if name == f.name)
        if expected in (list, dict):
            assert f.default_factory is expected, f.name
            assert f.default is dataclasses.MISSING, f.name
        else:
            assert f.default == expected, f.name


# --- AC2: to_json() round-trips to a JSON-serializable dict with the right "type" -----------


@pytest.mark.parametrize(("obj", "expected_type"), SAMPLES)
def test_to_json_returns_dict_with_type(obj: Any, expected_type: str) -> None:
    data = to_json(obj)
    assert isinstance(data, dict)
    assert data["type"] == expected_type
    assert list(data) == [f.name for f in dataclasses.fields(obj)]


@pytest.mark.parametrize("cls", [FlowEvent, Signal, Alert, Action])
def test_to_json_type_for_default_instances(cls: type) -> None:
    expected = {FlowEvent: "flow", Signal: "signal", Alert: "alert", Action: "action"}[cls]
    assert to_json(cls())["type"] == expected


@pytest.mark.parametrize(("obj", "expected_type"), SAMPLES)
def test_to_json_is_json_serializable_and_round_trips(obj: Any, expected_type: str) -> None:
    data = to_json(obj)
    text = json.dumps(data)  # must not raise
    decoded = json.loads(text)
    assert decoded == data
    assert decoded["type"] == expected_type
    rebuilt = _rebuild(type(obj), decoded)
    assert rebuilt == obj


@pytest.mark.parametrize(("obj", "expected_type"), SAMPLES)
def test_to_json_does_not_alias_the_original(obj: Any, expected_type: str) -> None:
    data = to_json(obj)
    for name, value in data.items():
        if isinstance(value, (list, dict)):
            assert value is not getattr(obj, name), name


def test_to_json_rejects_non_dataclass() -> None:
    for bad in ({"type": "flow"}, "flow", 42, None, [Signal()]):
        with pytest.raises(TypeError):
            to_json(bad)


def test_to_json_rejects_dataclass_class_not_instance() -> None:
    with pytest.raises(TypeError):
        to_json(Signal)


def test_to_json_rejects_dataclass_without_type_field() -> None:
    @dataclasses.dataclass
    class NoType:
        x: int = 1

    with pytest.raises(TypeError):
        to_json(NoType())


# --- AC3: an Alert's nested Signals serialize as dicts --------------------------------------


def test_alert_nested_signals_serialize_as_dicts() -> None:
    alert = _sample_alert()
    data = to_json(alert)

    assert isinstance(data["signals"], list)
    assert len(data["signals"]) == 2
    for sig_dict, sig in zip(data["signals"], alert.signals, strict=True):
        assert type(sig_dict) is dict
        assert not isinstance(sig_dict, Signal)
        assert sig_dict == {
            "type": "signal",
            "detector": sig.detector,
            "process": "freegamecheats.exe",
            "pid": 4242,
            "target": sig.target,
            "score": 0.9,
            "reasons": ["checks in with 192.168.56.20 every 5.0 s (±0.2 s)"],
            "mitre": "T1071.001",
            "ts_ms": 1_700_000_000_000,
        }
    assert [s["detector"] for s in data["signals"]] == ["beacon", "dga"]
    assert data["signals"][1]["target"] == "xkqjzvbwpl.example"

    rebuilt = Alert(**{**data, "signals": [Signal(**s) for s in data["signals"]]})
    assert rebuilt == alert
    assert all(isinstance(s, Signal) for s in rebuilt.signals)


def test_alert_with_no_signals_serializes_empty_list() -> None:
    data = to_json(Alert())
    assert data["signals"] == []
    assert data["action_ids"] == []
    json.dumps(data)


# --- AC4: mutable defaults are not shared between instances ---------------------------------

MUTABLE_DEFAULTS = [
    pytest.param(FlowEvent, "features", id="FlowEvent.features"),
    pytest.param(Signal, "reasons", id="Signal.reasons"),
    pytest.param(Alert, "signals", id="Alert.signals"),
    pytest.param(Alert, "action_ids", id="Alert.action_ids"),
    pytest.param(Action, "rule_names", id="Action.rule_names"),
]


@pytest.mark.parametrize(("cls", "attr"), MUTABLE_DEFAULTS)
def test_mutable_defaults_are_not_shared(cls: type, attr: str) -> None:
    a, b = cls(), cls()
    assert getattr(a, attr) is not getattr(b, attr)

    container = getattr(a, attr)
    if isinstance(container, dict):
        container["injected"] = 1
    elif attr == "signals":
        container.append(Signal())
    else:
        container.append("injected")

    assert len(getattr(a, attr)) == 1
    assert getattr(b, attr) == type(container)()
    assert getattr(cls(), attr) == type(container)()
