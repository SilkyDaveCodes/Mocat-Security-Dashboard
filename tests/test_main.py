"""Tests for agent.main: the capture -> detectors -> scoring -> response -> store + bus pipeline.

No NFStream, PowerShell or network: flows are synthetic FlowEvents (or SimpleNamespace NFlows
for the run_agent test), the firewall is patched at ``subprocess.run``, the store is a real SQLite
file in ``tmp_path`` and the bus is a real :class:`agent.bus.Bus` with a real subscriber.

The synthetic traffic mirrors the fake-malware demo (CLAUDE.md §9.1): random-looking DNS lookups
through the lab DNS plus an HTTP check-in to the lab C2 192.168.56.20 every 5 s, each its own flow.
The beacon detector is the real one; the DGA detector is the real one with a stub model (the
trained models/dga.joblib may be missing on a dev machine).
"""

from __future__ import annotations

import asyncio
import copy
import logging
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent import config
from agent.bus import Bus, Subscription
from agent.config import Allowlist
from agent.detectors.beacon import BeaconDetector
from agent.detectors.dga import DgaDetector
from agent.detectors.dga_features import FEATURE_NAMES
from agent.events import Action, Alert, FlowEvent, Signal
from agent.main import (
    CachedProcLookup,
    NamedDetector,
    Pipeline,
    build_detectors,
    run_agent,
)
from agent.procinfo import ProcInfo
from agent.response import firewall
from agent.scoring import Scorer
from agent.store import Store

PROC = "FreeGameCheats.exe"
PID = 4242
EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"
PC_IP = "192.168.56.10"
LAB_C2 = "192.168.56.20"
C2_PORT = 8080
T0_MS = 1_700_000_000_000
CHECKIN_EVERY_MS = 5_000
DGA_HOSTS = ("xkqzjvwpthrb.com", "qwzrtpxlkvbn.net", "zzkqpwxrtvbm.org", "pplxqzkwrtvn.info",
             "vbnmqzxkwrtp.biz", "trkqzwxpvlmn.com")
MALWARE_PROC = ProcInfo(pid=PID, name=PROC, exe_path=EXE, in_risky_dir=True, signed=False)
TIMEOUT_S = 5.0


class StubModel:
    """Stands in for the sklearn DGA classifier: fixed P(dga)."""

    def __init__(self, p_dga: float) -> None:
        self.p_dga = p_dga

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        return [[1.0 - self.p_dga, self.p_dga] for _ in rows]


# --- fixtures and helpers --------------------------------------------------------------------


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "homesoc.db") as db:
        yield db


@pytest.fixture
def powershell(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch the firewall's PowerShell boundary: every call 'succeeds'."""
    run = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0,
                                                             stdout="", stderr=""))
    monkeypatch.setattr(firewall.subprocess, "run", run)
    return run


def dga_detector(cfg: dict[str, Any], tmp_path: Path) -> DgaDetector:
    tranco = tmp_path / "tranco.csv"
    tranco.write_text("1,google.com\n2,microsoft.com\n", encoding="utf-8")
    allow = tmp_path / "domain_allowlist.txt"
    allow.write_text("", encoding="utf-8")
    bundle = {"model": StubModel(0.95), "feature_names": list(FEATURE_NAMES),
              "dga_class_index": 1}
    return DgaDetector(cfg, model=bundle, tranco_path=tranco, domain_allowlist_path=allow)


def real_detectors(cfg: dict[str, Any], tmp_path: Path) -> list[NamedDetector]:
    return [
        NamedDetector("dga", dga_detector(cfg, tmp_path).process),
        NamedDetector("beacon", BeaconDetector(cfg).process),
    ]


def make_scorer(cfg: dict[str, Any], mode: str) -> Scorer:
    return Scorer(cfg, Allowlist(names=frozenset({"chrome.exe"})), mode=mode)


def proc_lookup(pid: int, process: str) -> ProcInfo | None:
    return MALWARE_PROC if pid == PID else None


def dns_flow(host: str, ts_ms: int) -> FlowEvent:
    return FlowEvent(ts_ms=ts_ms, end_ms=ts_ms + 20, process=PROC, pid=PID, src_ip=PC_IP,
                     src_port=50000, dst_ip=LAB_C2, dst_port=53, protocol=17, hostname=host,
                     app_proto="DNS", bytes_out=60, bytes_in=90, packets=2)


def checkin_flow(i: int) -> FlowEvent:
    jitter_ms = (-80, 60, 0, 90, -40, 30)[i % 6]  # ±0.1 s, like a real 5 s timer
    ts = T0_MS + i * CHECKIN_EVERY_MS + jitter_ms
    return FlowEvent(ts_ms=ts, end_ms=ts + 50, process=PROC, pid=PID, src_ip=PC_IP,
                     src_port=51000 + i, dst_ip=LAB_C2, dst_port=C2_PORT, protocol=6,
                     app_proto="HTTP", bytes_out=180, bytes_in=200, packets=6)


def fake_malware_flows() -> list[FlowEvent]:
    """DGA lookups first, then 12 regular check-ins to the lab C2 (the demo order)."""
    dns = [dns_flow(host, T0_MS - 1000 + i * 50) for i, host in enumerate(DGA_HOSTS)]
    return dns + [checkin_flow(i) for i in range(12)]


def drain(sub: Subscription) -> list[Any]:
    items: list[Any] = []
    while True:
        try:
            items.append(sub.get_nowait())
        except asyncio.QueueEmpty:
            return items


async def feed(pipeline: Pipeline, bus: Bus, flows: list[FlowEvent]) -> list[Any]:
    """Publish ``flows`` on the bus, let ``pipeline.run`` consume them, return what a real
    subscriber received (flows excluded)."""
    pipeline_sub = bus.subscribe("pipeline")
    ui_sub = bus.subscribe("ui")
    worker = asyncio.create_task(pipeline.run(pipeline_sub))
    for flow in flows:
        bus.publish(flow)
    pipeline_sub.close()  # queued flows are still delivered, then run() returns
    await asyncio.wait_for(worker, TIMEOUT_S)
    await asyncio.sleep(0)  # deliver publish_threadsafe callbacks from the worker thread
    await asyncio.sleep(0)
    return [e for e in drain(ui_sub) if not isinstance(e, FlowEvent)]


def run_pipeline(cfg: dict[str, Any], store: Store, detectors: list[NamedDetector],
                 mode: str, flows: list[FlowEvent]) -> tuple[Pipeline, list[Any]]:
    async def main() -> tuple[Pipeline, list[Any]]:
        bus = Bus.from_config(cfg, loop=asyncio.get_running_loop())
        pipeline = Pipeline(detectors, make_scorer(cfg, mode), store, bus.publish_threadsafe,
                            proc_lookup=proc_lookup)
        return pipeline, await feed(pipeline, bus, flows)

    return asyncio.run(main())


# --- acceptance 1: auto mode -> Alert + quarantine_app Action, saved and published ----------


def test_beacon_and_dga_quarantine_app_saved_and_published(
    cfg: dict[str, Any], store: Store, powershell: MagicMock, tmp_path: Path
) -> None:
    _, published = run_pipeline(cfg, store, real_detectors(cfg, tmp_path), "auto",
                                fake_malware_flows())

    actions = store.list_actions()
    assert len(actions) == 1
    action = actions[0]
    assert action.kind == "quarantine_app"
    assert action.target == EXE
    assert action.rule_names == [
        f"HomeSOC quarantine FreeGameCheats.exe out #{action.id[:8]}",
        f"HomeSOC quarantine FreeGameCheats.exe in #{action.id[:8]}",
    ]
    assert powershell.call_count == 2  # one PowerShell call per rule (§6.5)
    assert all(EXE in call.args[0][-1] for call in powershell.call_args_list)

    alerts = store.list_alerts()
    quarantine_alerts = [a for a in alerts if action.id in a.action_ids]
    assert len(quarantine_alerts) == 1
    alert = quarantine_alerts[0]
    assert alert.process == PROC
    assert alert.exe_path == EXE
    assert alert.severity == "critical"
    assert {s.detector for s in alert.signals} == {"dga", "beacon"}
    assert "FreeGameCheats.exe" in alert.what_we_did

    published_actions = [e for e in published if isinstance(e, Action)]
    published_alerts = [e for e in published if isinstance(e, Alert)]
    assert [a.id for a in published_actions] == [action.id]
    assert alert.id in {a.id for a in published_alerts}
    assert {a.id for a in published_alerts} == {a.id for a in alerts}
    # The Action goes out before the Alert that refers to it.
    ids = [e.id for e in published]
    assert ids.index(action.id) < ids.index(alert.id)


def test_failed_firewall_call_still_alerts_without_action(
    cfg: dict[str, Any], store: Store, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="",
                                                             stderr="Access is denied."))
    monkeypatch.setattr(firewall.subprocess, "run", run)

    _, published = run_pipeline(cfg, store, real_detectors(cfg, tmp_path), "auto",
                                fake_malware_flows())

    assert run.called
    assert store.list_actions() == []
    assert not any(isinstance(e, Action) for e in published)
    alerts = store.list_alerts()
    assert alerts
    assert all(a.action_ids == [] for a in alerts)
    assert any({s.detector for s in a.signals} == {"dga", "beacon"} for a in alerts)
    assert {a.id for a in alerts} == {e.id for e in published if isinstance(e, Alert)}


# --- acceptance 2: notify mode -> Alert, no firewall call -----------------------------------


def test_notify_mode_alerts_without_firewall_call(
    cfg: dict[str, Any], store: Store, powershell: MagicMock, tmp_path: Path
) -> None:
    quarantine = MagicMock(side_effect=AssertionError("firewall must not be called"))
    detectors = real_detectors(cfg, tmp_path)

    async def main() -> list[Any]:
        bus = Bus.from_config(cfg, loop=asyncio.get_running_loop())
        pipeline = Pipeline(detectors, make_scorer(cfg, "notify"), store, bus.publish_threadsafe,
                            firewall_fns={"quarantine_app": quarantine, "block_ip": quarantine},
                            proc_lookup=proc_lookup)
        return await feed(pipeline, bus, fake_malware_flows())

    published = asyncio.run(main())

    quarantine.assert_not_called()
    powershell.assert_not_called()
    assert store.list_actions() == []
    alerts = store.list_alerts()
    assert alerts
    assert any({s.detector for s in a.signals} == {"dga", "beacon"} for a in alerts)
    assert all(a.action_ids == [] for a in alerts)
    assert not any(isinstance(e, Action) for e in published)
    assert {a.id for a in alerts} == {e.id for e in published if isinstance(e, Alert)}


# --- acceptance 3: a raising detector doesn't stop the others -------------------------------


def test_raising_detector_does_not_stop_other_detectors(
    cfg: dict[str, Any], store: Store, powershell: MagicMock,
    caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[FlowEvent] = []

    def boom(event: FlowEvent) -> list[Signal]:
        calls.append(event)
        raise RuntimeError("detector bug")

    detectors = [NamedDetector("boom", boom), NamedDetector("beacon", BeaconDetector(cfg).process),
                 NamedDetector("boom2", boom)]
    flows = [checkin_flow(i) for i in range(8)]

    with caplog.at_level(logging.ERROR, logger="agent.main"):
        _, published = run_pipeline(cfg, store, detectors, "notify", flows)

    assert len(calls) == 2 * len(flows)  # both broken detectors ran on every flow
    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert {s.detector for s in alerts[0].signals} == {"beacon"}
    assert alerts[0].signals[0].target == LAB_C2
    assert [e.id for e in published if isinstance(e, Alert)] == [alerts[0].id]
    assert "Detector 'boom' raised" in caplog.text
    assert "Detector 'boom2' raised" in caplog.text


def test_detect_returns_signals_of_healthy_detectors(cfg: dict[str, Any], store: Store) -> None:
    sig = Signal(detector="intel", process=PROC, pid=PID, target=LAB_C2, score=1.0)

    def boom(event: FlowEvent) -> list[Signal]:
        raise ValueError("bad")

    pipeline = Pipeline([NamedDetector("boom", boom), NamedDetector("ok", lambda e: [sig])],
                        make_scorer(cfg, "notify"), store, lambda item: None,
                        proc_lookup=proc_lookup)
    assert pipeline.detect(checkin_flow(0)) == [sig]


# --- pipeline details -----------------------------------------------------------------------


def test_handle_never_raises_when_scoring_fails(cfg: dict[str, Any], store: Store) -> None:
    sig = Signal(detector="intel", process=PROC, pid=PID, target=LAB_C2, score=1.0)
    scorer = MagicMock()
    scorer.add.side_effect = RuntimeError("scoring bug")
    pipeline = Pipeline([NamedDetector("ok", lambda e: [sig])], scorer, store, lambda item: None,
                        proc_lookup=proc_lookup)
    assert pipeline.handle(checkin_flow(0)) == []


def test_unknown_exe_alerts_but_never_quarantines(
    cfg: dict[str, Any], store: Store, powershell: MagicMock
) -> None:
    sig = Signal(detector="intel", process=PROC, pid=PID, target=LAB_C2, score=1.0)
    published: list[Any] = []
    pipeline = Pipeline([NamedDetector("intel", lambda e: [sig])], make_scorer(cfg, "auto"),
                        store, published.append, proc_lookup=lambda pid, name: None)
    alerts = pipeline.handle(checkin_flow(0))
    assert len(alerts) == 1
    powershell.assert_not_called()
    assert store.list_actions() == []
    assert published == alerts


def test_handle_logs_each_flow(
    cfg: dict[str, Any], store: Store, caplog: pytest.LogCaptureFixture
) -> None:
    pipeline = Pipeline([], make_scorer(cfg, "notify"), store, lambda item: None,
                        proc_lookup=proc_lookup)
    with caplog.at_level(logging.INFO, logger="agent.main"):
        pipeline.handle(checkin_flow(0))
    assert f"flow {PROC} pid={PID}" in caplog.text
    assert f"{LAB_C2}:{C2_PORT}" in caplog.text


def test_build_detectors_skips_one_that_fails_to_start(
    cfg: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    def broken(_: dict[str, Any], __: Store | None) -> Any:
        raise FileNotFoundError("model missing")

    with caplog.at_level(logging.ERROR, logger="agent.main"):
        detectors = build_detectors(cfg, [("broken", broken),
                                          ("beacon", lambda c, s: BeaconDetector(c).process)])
    assert [d.name for d in detectors] == ["beacon"]
    assert "Detector 'broken' could not start" in caplog.text


def test_default_detector_factories_cover_existing_detectors() -> None:
    from agent.main import DETECTOR_FACTORIES

    assert [name for name, _ in DETECTOR_FACTORIES] == [
        "intel", "dga", "beacon", "flow_model", "anomaly"
    ]


# --- anomaly detector in the default factories (#53) ----------------------------------------

UPLOAD_PROC = "uploader.exe"
UPLOAD_PID = 5151
UPLOAD_PROCINFO = ProcInfo(pid=UPLOAD_PID, name=UPLOAD_PROC,
                           exe_path=r"C:\Users\demo\Downloads\uploader.exe",
                           in_risky_dir=True, signed=False)
EXFIL_IP = "203.0.113.7"


def anomaly_factories() -> list[tuple[str, Any]]:
    from agent.main import DETECTOR_FACTORIES

    return [(name, f) for name, f in DETECTOR_FACTORIES if name == "anomaly"]


def upload_flow(bytes_out: int, direction: str = "outbound") -> FlowEvent:
    return FlowEvent(ts_ms=T0_MS, end_ms=T0_MS + 100, process=UPLOAD_PROC, pid=UPLOAD_PID,
                     src_ip=PC_IP, src_port=52000, dst_ip=EXFIL_IP, dst_port=443, protocol=6,
                     bytes_out=bytes_out, bytes_in=2_000, packets=20, direction=direction)


def seed_calibrated_baseline(store: Store, windows: int = 40) -> None:
    """A finished calibration: ``windows`` small 60 s upload windows for UPLOAD_PROC."""
    store.save_baseline(UPLOAD_PROC, {
        "version": 1,
        "calibration_end_ms": 1,  # long past, by the wall clock
        "windows": [[20_000 + 500 * (i % 7), 4 + i % 3, 1 + i % 2] for i in range(windows)],
    })


@pytest.fixture
def fake_wall_clock(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The anomaly factory uses the detector's default wall clock; drive it from a list (ms)."""
    from agent.detectors import anomaly as anomaly_mod

    now_ms = [T0_MS]
    monkeypatch.setattr(anomaly_mod, "time", SimpleNamespace(time=lambda: now_ms[0] / 1000))
    return now_ms


def test_default_anomaly_detector_builds_with_store_and_processes_flows(
    cfg: dict[str, Any], store: Store
) -> None:
    detectors = build_detectors(cfg, anomaly_factories(), store=store)
    assert [d.name for d in detectors] == ["anomaly"]
    [anomaly] = detectors
    assert anomaly.process(upload_flow(5_000)) == []  # calibrating: collects, never signals
    assert anomaly.process(upload_flow(5_000, direction="inbound")) == []


def test_default_anomaly_detector_saves_its_baseline_to_the_store(
    cfg: dict[str, Any], store: Store, fake_wall_clock: list[int]
) -> None:
    [anomaly] = build_detectors(cfg, anomaly_factories(), store=store)
    anomaly.process(upload_flow(12_345))
    anomaly.process(upload_flow(1_000))
    assert store.load_baseline(UPLOAD_PROC) is None  # window still open
    fake_wall_clock[0] += 61_000  # past the 60 s boundary: the next flow closes the window
    anomaly.process(upload_flow(10, direction="inbound"))
    saved = store.load_baseline(UPLOAD_PROC)
    assert saved is not None
    assert saved["windows"] == [[13_345, 2, 1]]
    assert saved["calibration_end_ms"] > fake_wall_clock[0] - 61_000  # a fresh calibration


def test_default_anomaly_detector_flags_a_big_upload_from_a_calibrated_process(
    cfg: dict[str, Any], store: Store
) -> None:
    seed_calibrated_baseline(store)
    [anomaly] = build_detectors(cfg, anomaly_factories(), store=store)
    assert anomaly.process(upload_flow(30_000)) == []  # a normal-sized flow
    [signal] = anomaly.process(upload_flow(20_000_000))  # a 20 MB upload in the same window
    assert signal.detector == "anomaly"
    assert signal.process == UPLOAD_PROC and signal.pid == UPLOAD_PID
    assert signal.target == EXFIL_IP
    assert signal.mitre == "T1041"
    assert 0.6 <= signal.score <= 0.9


def test_pipeline_from_config_gives_the_anomaly_detector_its_store(
    cfg: dict[str, Any], store: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent import main as main_mod

    seed_calibrated_baseline(store)
    monkeypatch.setattr(main_mod, "DETECTOR_FACTORIES", tuple(anomaly_factories()))
    monkeypatch.setattr(main_mod.procinfo, "info",
                        lambda pid: UPLOAD_PROCINFO if pid == UPLOAD_PID else None)
    published: list[Any] = []
    pipeline = Pipeline.from_config(cfg, store, published.append)
    assert [d.name for d in pipeline.detectors] == ["anomaly"]
    pipeline.scorer.mode = "notify"

    [alert] = pipeline.handle(upload_flow(20_000_000))
    assert [s.detector for s in alert.signals] == ["anomaly"]
    assert alert.process == UPLOAD_PROC
    assert alert.action_ids == []  # notify mode: alert only
    assert store.get_alert(alert.id) is not None
    assert alert in published


def test_default_anomaly_factory_failing_to_start_is_left_out(
    cfg: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    class BrokenStore:
        def load_baselines(self) -> dict[str, Any]:
            raise OSError("disk gone")

    with caplog.at_level(logging.ERROR, logger="agent.main"):
        detectors = build_detectors(cfg, anomaly_factories(), store=BrokenStore())  # type: ignore[arg-type]
    assert detectors == []
    assert "Detector 'anomaly' could not start" in caplog.text


def test_dga_detector_without_model_does_not_crash(cfg: dict[str, Any], tmp_path: Path,
                                                   store: Store) -> None:
    detector = DgaDetector(cfg, model_path=tmp_path / "missing.joblib",
                           tranco_path=tmp_path / "none.csv",
                           domain_allowlist_path=tmp_path / "none.txt")
    pipeline = Pipeline([NamedDetector("dga", detector.process)], make_scorer(cfg, "auto"),
                        store, lambda item: None, proc_lookup=proc_lookup)
    assert pipeline.handle(dns_flow(DGA_HOSTS[0], T0_MS)) == []


def test_cached_proc_lookup_caches_and_rejects_reused_pid() -> None:
    now = [0.0]
    lookup = MagicMock(return_value=MALWARE_PROC)
    cached = CachedProcLookup(30.0, lookup=lookup, clock=lambda: now[0])

    assert cached(PID, PROC) is MALWARE_PROC
    assert cached(PID, PROC.lower()) is MALWARE_PROC  # names compare case-insensitively
    assert lookup.call_count == 1
    assert cached(PID, "notepad.exe") is None  # PID now belongs to another program
    assert cached(-1, PROC) is None
    now[0] = 31.0
    cached(PID, PROC)
    assert lookup.call_count == 2


def test_cached_proc_lookup_survives_lookup_error() -> None:
    cached = CachedProcLookup(30.0, lookup=MagicMock(side_effect=OSError("gone")))
    assert cached(PID, PROC) is None


# --- run_agent: starts capture, logs flows, stops cleanly -----------------------------------


def test_run_agent_runs_capture_through_pipeline(
    cfg: dict[str, Any], store: Store, caplog: pytest.LogCaptureFixture
) -> None:
    nflows = [SimpleNamespace(system_process_name=PROC, system_process_pid=PID, src_ip=PC_IP,
                              dst_ip=LAB_C2, src_port=51000 + i, dst_port=C2_PORT, protocol=6,
                              bidirectional_first_seen_ms=T0_MS + i * CHECKIN_EVERY_MS)
              for i in range(3)]
    seen: list[FlowEvent] = []

    def record(event: FlowEvent) -> list[Signal]:
        seen.append(event)
        return []

    with caplog.at_level(logging.INFO, logger="agent.main"):
        asyncio.run(asyncio.wait_for(
            run_agent(cfg, threading.Event(), streamer_factory=lambda c: iter(nflows),
                      detectors=[NamedDetector("record", record)], store=store),
            TIMEOUT_S,
        ))

    assert [e.src_port for e in seen] == [51000, 51001, 51002]
    assert all(e.process == PROC and e.pid == PID for e in seen)
    assert caplog.text.count(f"flow {PROC} pid={PID}") == 3


# --- main(): the installed agent seeds its data root first (ticket #50) --------------------


def test_main_seeds_the_data_root_before_loading_the_config(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import agent.main as agent_main

    calls: list[str] = []
    monkeypatch.setattr(config, "seed_data_root", lambda: calls.append("seed") or [])

    def fake_load() -> dict:
        calls.append("load")
        raise config.ConfigError("stop here")

    monkeypatch.setattr(config, "load", fake_load)
    with pytest.raises(SystemExit) as excinfo:
        agent_main.main()
    assert excinfo.value.code == 1
    assert calls == ["seed", "load"]


def test_main_exits_cleanly_when_the_data_root_cannot_be_written(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import agent.main as agent_main

    def denied() -> list:
        raise PermissionError("access denied")

    monkeypatch.setattr(config, "seed_data_root", denied)
    monkeypatch.setattr(config, "load", lambda: pytest.fail("must not load after a seed error"))
    with pytest.raises(SystemExit) as excinfo:
        agent_main.main()
    assert excinfo.value.code == 1
