"""Tests for agent.api: the REST endpoints of CLAUDE.md §6.6 and the loopback-only bind (§9.5).

Every test builds the app with :func:`agent.api.create_app` against a real SQLite store in
``tmp_path``, a real :class:`agent.scoring.Scorer` (so ``POST /mode`` is checked on the object the
pipeline reads) and a fake firewall that records its arguments. No PowerShell is ever run.
"""

from __future__ import annotations

import asyncio
import copy
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent import api, config
from agent.api import FlowTracker, create_app, make_server, server_settings
from agent.config import Allowlist
from agent.events import Action, Alert, FlowEvent, Signal
from agent.main import NamedDetector, run_agent
from agent.procinfo import ProcInfo
from agent.response import firewall
from agent.response.firewall import FirewallError
from agent.scoring import Scorer
from agent.store import Store

EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"
PROC = "FreeGameCheats.exe"
LAB_C2 = "192.168.56.20"
PC_IP = "192.168.56.10"
WINDOW_S = 600.0


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeFirewall:
    """Stands in for agent.response.firewall: records calls, returns real-looking Actions."""

    def __init__(self) -> None:
        self.undo_calls: list[Action] = []
        self.undo_all_calls = 0
        self.quarantine_calls: list[str] = []
        self.fail: Exception | None = None

    def undo(self, action: Action) -> Action:
        self.undo_calls.append(copy.deepcopy(action))
        if self.fail:
            raise self.fail
        action.undone = True
        return Action(id="undo-1", ts_ms=5, kind="undo", target=action.id,
                      rule_names=list(action.rule_names))

    def undo_all(self) -> Action:
        self.undo_all_calls += 1
        if self.fail:
            raise self.fail
        return Action(id="undo-all-1", ts_ms=6, kind="undo", target="HomeSOC")

    def quarantine_app(self, exe_path: str) -> Action:
        self.quarantine_calls.append(exe_path)
        if self.fail:
            raise self.fail
        return Action(id="q-new", ts_ms=7, kind="quarantine_app", target=exe_path,
                      rule_names=[f"HomeSOC quarantine x out #{i}" for i in ("aaaa", "bbbb")])

    def fns(self) -> dict[str, Any]:
        return {"undo": self.undo, "undo_all": self.undo_all,
                "quarantine_app": self.quarantine_app}


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "homesoc.db") as db:
        yield db


@pytest.fixture
def scorer(cfg: dict[str, Any]) -> Scorer:
    return Scorer(cfg, Allowlist(frozenset({"chrome.exe"})), mode="notify")


@pytest.fixture
def fw() -> FakeFirewall:
    return FakeFirewall()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def tracker(clock: FakeClock) -> FlowTracker:
    return FlowTracker(WINDOW_S, clock)


@pytest.fixture
def published() -> list[Any]:
    return []


@pytest.fixture
def client(store: Store, scorer: Scorer, tracker: FlowTracker, fw: FakeFirewall,
           clock: FakeClock, published: list[Any]) -> TestClient:
    app = create_app(store, scorer, tracker, firewall_fns=fw.fns(),
                     allowlist=Allowlist(frozenset({"chrome.exe"})),
                     publish=published.append, clock=clock)
    return TestClient(app)


def make_action(action_id: str = "a1", kind: str = "quarantine_app", target: str = EXE,
                undone: bool = False, ts_ms: int = 1) -> Action:
    return Action(id=action_id, ts_ms=ts_ms, kind=kind, target=target, undone=undone,  # type: ignore[arg-type]
                  rule_names=[f"HomeSOC quarantine FreeGameCheats.exe {d} #a1a1a1a1"
                              for d in ("out", "in")])


def make_alert(alert_id: str = "al1", exe_path: str | None = EXE, process: str = PROC,
               ts_ms: int = 10, action_ids: list[str] | None = None) -> Alert:
    sig = Signal(detector="beacon", process=process, pid=42, target=LAB_C2, score=0.9,
                 reasons=[f"checks in with {LAB_C2} every 5.0 s (±0.1 s)"], mitre="T1071.001")
    return Alert(id=alert_id, ts_ms=ts_ms, severity="high", process=process, exe_path=exe_path,
                 risk=0.9, title="t", what_happened="h", what_we_did="Nothing was blocked.",
                 what_you_should_do="s", signals=[sig], action_ids=action_ids or [])


def flow(process: str = PROC, dst_ip: str = LAB_C2, bytes_out: int = 100, bytes_in: int = 10,
         **kw: Any) -> FlowEvent:
    return FlowEvent(process=process, pid=kw.pop("pid", 42), exe_path=kw.pop("exe_path", EXE),
                     src_ip=kw.pop("src_ip", PC_IP), src_port=kw.pop("src_port", 50000),
                     dst_ip=dst_ip, dst_port=kw.pop("dst_port", 8080), protocol=6,
                     bytes_out=bytes_out, bytes_in=bytes_in, **kw)


# --- GET /status, GET /alerts -------------------------------------------------------------


def test_status_reports_mode_counts_and_uptime(client: TestClient, store: Store,
                                               tracker: FlowTracker, clock: FakeClock) -> None:
    store.save_alert(make_alert("al1"))
    store.save_action(make_action("a1"))
    store.save_action(make_action("a2", undone=True))
    store.save_action(make_action("u1", kind="undo", target="a2"))
    tracker.add(flow())
    clock.now += 12.5

    resp = client.get("/status")

    assert resp.status_code == 200
    assert resp.json() == {"status": "running", "mode": "notify", "uptime_s": 12.5,
                           "alerts": 1, "active_actions": 1, "apps": 1}


def test_alerts_returns_stored_alerts_newest_first(client: TestClient, store: Store) -> None:
    store.save_alert(make_alert("old", ts_ms=1))
    store.save_alert(make_alert("new", ts_ms=2))

    resp = client.get("/alerts")

    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    assert [a["id"] for a in alerts] == ["new", "old"]
    first = alerts[0]
    assert first["type"] == "alert" and first["exe_path"] == EXE
    assert first["signals"][0]["detector"] == "beacon"
    assert {"what_happened", "what_we_did", "what_you_should_do", "action_ids"} <= set(first)


def test_alerts_limit_and_empty_store(client: TestClient, store: Store) -> None:
    assert client.get("/alerts").json() == {"alerts": []}
    for i in range(3):
        store.save_alert(make_alert(f"al{i}", ts_ms=i))
    assert [a["id"] for a in client.get("/alerts?limit=2").json()["alerts"]] == ["al2", "al1"]
    assert client.get("/alerts?limit=0").status_code == 422


# --- POST /mode -----------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["off", "notify", "auto"])
def test_mode_sets_the_scorer_mode(client: TestClient, scorer: Scorer, mode: str) -> None:
    resp = client.post("/mode", json={"mode": mode})

    assert resp.status_code == 200
    assert resp.json() == {"mode": mode}
    assert scorer.mode == mode
    assert client.get("/status").json()["mode"] == mode


@pytest.mark.parametrize("body", [{"mode": "panic"}, {"mode": "AUTO"}, {"mode": ""},
                                  {"mode": None}, {"mode": 1}, {}, {"other": "auto"}])
def test_mode_rejects_anything_else_with_422(client: TestClient, scorer: Scorer,
                                             body: dict[str, Any]) -> None:
    resp = client.post("/mode", json=body)

    assert resp.status_code == 422
    assert scorer.mode == "notify"  # unchanged


def test_mode_change_affects_the_next_scoring_decision(client: TestClient,
                                                       scorer: Scorer) -> None:
    # An intel hit on a known exe: notify -> alert only; auto -> quarantine request.
    proc = ProcInfo(pid=42, name=PROC, exe_path=EXE, in_risky_dir=True, signed=False)
    sig = Signal(detector="intel", process=PROC, pid=42, target=LAB_C2, score=1.0)
    assert scorer.add(sig, proc).action is None
    scorer.prune()

    assert client.post("/mode", json={"mode": "auto"}).status_code == 200
    other = Signal(detector="intel", process="Other.exe", pid=43, target=LAB_C2, score=1.0)
    decision = scorer.add(other, ProcInfo(pid=43, name="Other.exe", exe_path=r"C:\Temp\Other.exe",
                                          in_risky_dir=True, signed=False))
    assert decision.action is not None and decision.action.kind == "quarantine_app"


# --- POST /actions/{id}/undo ----------------------------------------------------------------


def test_undo_calls_firewall_with_stored_action_and_marks_it_undone(
    client: TestClient, store: Store, fw: FakeFirewall, published: list[Any]
) -> None:
    stored = make_action("a1")
    store.save_action(stored)

    resp = client.post("/actions/a1/undo")

    assert resp.status_code == 200
    assert [a.id for a in fw.undo_calls] == ["a1"]
    assert fw.undo_calls[0].rule_names == stored.rule_names  # the stored rule names were used
    assert fw.undo_calls[0].undone is False
    body = resp.json()
    assert body["action"]["id"] == "a1" and body["action"]["undone"] is True
    assert body["undo"] == {"type": "action", "id": "undo-1", "ts_ms": 5, "kind": "undo",
                            "target": "a1", "rule_names": stored.rule_names, "undone": False}
    assert store.get_action("a1").undone is True
    assert store.get_action("undo-1").kind == "undo"
    assert [(p.id, p.undone) for p in published] == [("a1", True), ("undo-1", False)]


def test_undo_unknown_id_is_404(client: TestClient, fw: FakeFirewall) -> None:
    resp = client.post("/actions/nope/undo")

    assert resp.status_code == 404
    assert fw.undo_calls == []


def test_undo_firewall_error_is_502_and_action_stays_active(
    client: TestClient, store: Store, fw: FakeFirewall
) -> None:
    store.save_action(make_action("a1"))
    fw.fail = FirewallError("access denied", leftover_rules=["x"])

    resp = client.post("/actions/a1/undo")

    assert resp.status_code == 502
    assert "access denied" in resp.json()["detail"]
    assert store.get_action("a1").undone is False
    assert store.list_actions() == [store.get_action("a1")]  # no undo record saved


def test_undo_already_undone_is_409_without_firewall_call(
    client: TestClient, store: Store, fw: FakeFirewall
) -> None:
    store.save_action(make_action("a1", undone=True))
    store.save_action(make_action("u1", kind="undo", target="x"))

    assert client.post("/actions/a1/undo").status_code == 409
    assert client.post("/actions/u1/undo").status_code == 409
    assert fw.undo_calls == []


def test_undo_through_real_firewall_module_patched_at_subprocess(
    store: Store, scorer: Scorer, tracker: FlowTracker, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default firewall_fns go through agent.response.firewall; PowerShell is faked."""
    commands: list[str] = []

    def fake_run(args: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        commands.append(args[-1])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(firewall.subprocess, "run", fake_run)
    store.save_action(make_action("a1"))
    client = TestClient(create_app(store, scorer, tracker, allowlist=Allowlist(frozenset())))

    assert client.post("/actions/a1/undo").status_code == 200
    assert len(commands) == 2
    assert all("-Group 'HomeSOC'" in c and "-ceq 'HomeSOC quarantine" in c for c in commands)
    assert store.get_action("a1").undone is True


# --- POST /undo-all -------------------------------------------------------------------------


def test_undo_all_calls_firewall_then_marks_everything_undone(
    client: TestClient, store: Store, fw: FakeFirewall
) -> None:
    store.save_action(make_action("a1"))
    store.save_action(make_action("a2", kind="block_ip", target=LAB_C2))

    resp = client.post("/undo-all")

    assert resp.status_code == 200
    assert fw.undo_all_calls == 1
    assert resp.json()["undone"] == 2
    assert resp.json()["undo"]["kind"] == "undo"
    assert store.get_action("a1").undone and store.get_action("a2").undone
    assert client.get("/status").json()["active_actions"] == 0


def test_undo_all_firewall_error_is_502_and_nothing_marked(
    client: TestClient, store: Store, fw: FakeFirewall
) -> None:
    store.save_action(make_action("a1"))
    fw.fail = FirewallError("boom")

    assert client.post("/undo-all").status_code == 502
    assert store.get_action("a1").undone is False


# --- POST /alerts/{id}/quarantine -----------------------------------------------------------


def test_quarantine_creates_action_and_links_it_to_the_alert(
    client: TestClient, store: Store, fw: FakeFirewall, published: list[Any]
) -> None:
    store.save_alert(make_alert("al1"))

    resp = client.post("/alerts/al1/quarantine")

    assert resp.status_code == 200
    assert fw.quarantine_calls == [EXE]
    body = resp.json()
    assert body["action"]["id"] == "q-new" and body["action"]["target"] == EXE
    assert body["alert"]["action_ids"] == ["q-new"]
    saved_alert = store.get_alert("al1")
    assert saved_alert.action_ids == ["q-new"]
    assert "quarantined FreeGameCheats.exe" in saved_alert.what_we_did
    assert store.get_action("q-new").kind == "quarantine_app"
    assert [p.id for p in published] == ["q-new", "al1"]


def test_quarantine_unknown_alert_is_404(client: TestClient, fw: FakeFirewall) -> None:
    assert client.post("/alerts/nope/quarantine").status_code == 404
    assert fw.quarantine_calls == []


def test_quarantine_refuses_unknown_exe_path(client: TestClient, store: Store,
                                             fw: FakeFirewall) -> None:
    store.save_alert(make_alert("al1", exe_path=None))

    resp = client.post("/alerts/al1/quarantine")

    assert resp.status_code == 409
    assert fw.quarantine_calls == []
    assert store.get_alert("al1").action_ids == []


def test_quarantine_refuses_allowlisted_app(client: TestClient, store: Store,
                                            fw: FakeFirewall) -> None:
    chrome = r"C:\Program Files\Google\Chrome\Application\Chrome.exe"
    store.save_alert(make_alert("al1", exe_path=chrome, process="Chrome.exe"))

    assert client.post("/alerts/al1/quarantine").status_code == 409
    assert fw.quarantine_calls == []


def test_quarantine_refuses_when_already_quarantined(client: TestClient, store: Store,
                                                     fw: FakeFirewall) -> None:
    store.save_alert(make_alert("al1"))
    store.save_action(make_action("a1", target=EXE.upper()))

    assert client.post("/alerts/al1/quarantine").status_code == 409
    assert fw.quarantine_calls == []


def test_quarantine_firewall_error_is_502_and_alert_unchanged(
    client: TestClient, store: Store, fw: FakeFirewall
) -> None:
    store.save_alert(make_alert("al1"))
    fw.fail = FirewallError("no powershell")

    assert client.post("/alerts/al1/quarantine").status_code == 502
    assert store.get_alert("al1").action_ids == []
    assert store.list_actions() == []


def test_quarantine_unsafe_path_is_400(client: TestClient, store: Store,
                                       fw: FakeFirewall) -> None:
    store.save_alert(make_alert("al1"))
    fw.fail = ValueError("not absolute")

    assert client.post("/alerts/al1/quarantine").status_code == 400
    assert store.get_alert("al1").action_ids == []


# --- GET /apps and the FlowTracker (fake clock) ---------------------------------------------


def test_apps_aggregates_bytes_and_destinations_per_process(client: TestClient,
                                                            tracker: FlowTracker) -> None:
    tracker.add(flow(bytes_out=100, bytes_in=10, hostname="c2.lab"))
    tracker.add(flow(bytes_out=200, bytes_in=20, dst_port=8081, src_port=50001))
    tracker.add(flow(dst_ip="8.8.8.8", bytes_out=5, bytes_in=5, dst_port=53))
    tracker.add(flow(process="chrome.exe", pid=7, exe_path=None, dst_ip="1.1.1.1",
                     bytes_out=1, bytes_in=1, dst_port=443))

    resp = client.get("/apps")

    assert resp.status_code == 200
    body = resp.json()
    assert body["window_s"] == WINDOW_S
    by_name = {a["process"]: a for a in body["apps"]}
    assert [a["process"] for a in body["apps"]] == [PROC, "chrome.exe"]  # most traffic first
    fgc = by_name[PROC]
    assert (fgc["bytes_out"], fgc["bytes_in"], fgc["flows"]) == (305, 35, 3)
    assert fgc["pids"] == [42] and fgc["exe_path"] == EXE
    assert fgc["destinations"][0] == {"ip": LAB_C2, "hostname": "c2.lab", "ports": [8080, 8081],
                                      "direction": "outbound", "bytes_out": 300,
                                      "bytes_in": 30, "flows": 2}
    assert fgc["destinations"][1]["ip"] == "8.8.8.8"
    assert by_name["chrome.exe"]["destinations"][0]["ip"] == "1.1.1.1"


def test_apps_only_counts_flows_from_the_last_10_minutes(
    client: TestClient, tracker: FlowTracker, clock: FakeClock
) -> None:
    tracker.add(flow(bytes_out=1_000))                      # t = 1000
    clock.now += 300
    tracker.add(flow(dst_ip="10.0.0.9", bytes_out=50))      # t = 1300
    clock.now += 299.9                                      # t = 1599.9: both still inside

    assert client.get("/apps").json()["apps"][0]["bytes_out"] == 1_050

    clock.now += 0.1                                        # t = 1600: first is 600 s old
    app = client.get("/apps").json()["apps"][0]
    assert app["bytes_out"] == 50 and app["flows"] == 1
    assert [d["ip"] for d in app["destinations"]] == ["10.0.0.9"]

    clock.now += 300                                        # t = 1900: all expired
    assert client.get("/apps").json()["apps"] == []
    assert client.get("/status").json()["apps"] == 0


def test_apps_inbound_flow_uses_the_remote_source(tracker: FlowTracker) -> None:
    tracker.add(flow(process="svchost.exe", src_ip=LAB_C2, src_port=4444, dst_ip=PC_IP,
                     dst_port=3389, direction="inbound"))
    dest = tracker.apps()[0]["destinations"][0]
    assert (dest["ip"], dest["ports"], dest["direction"]) == (LAB_C2, [4444], "inbound")


def test_tracker_window_comes_from_config(cfg: dict[str, Any]) -> None:
    assert cfg["api"]["apps_window_s"] == 600
    assert FlowTracker.from_config(cfg).window_s == 600.0
    cfg["api"]["apps_window_s"] = 30
    assert FlowTracker.from_config(cfg).window_s == 30.0
    with pytest.raises(ValueError):
        FlowTracker(0)


# --- host: 127.0.0.1 only -------------------------------------------------------------------


def test_api_host_is_loopback_only(cfg: dict[str, Any]) -> None:
    assert api.API_HOST == "127.0.0.1"
    assert cfg["api"]["host"] == "127.0.0.1"
    assert server_settings(cfg) == ("127.0.0.1", 8765)
    server = make_server(create_app(Store(":memory:"), SimpleNamespace(mode="notify"),
                                    FlowTracker(WINDOW_S), allowlist=Allowlist(frozenset())),
                         cfg)
    assert server.config.host == "127.0.0.1"
    assert server.config.host != "0.0.0.0"
    assert server.config.port == 8765


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "", "localhost", "192.168.56.10"])
def test_server_refuses_any_non_loopback_host(cfg: dict[str, Any], host: str) -> None:
    cfg["api"]["host"] = host
    with pytest.raises(ValueError, match="127.0.0.1"):
        server_settings(cfg)
    with pytest.raises(ValueError):
        make_server(create_app(Store(":memory:"), SimpleNamespace(mode="notify"),
                               FlowTracker(WINDOW_S), allowlist=Allowlist(frozenset())), cfg)


# --- wiring in agent.main.run_agent ---------------------------------------------------------


def test_run_agent_feeds_tracker_and_api_controls_the_pipeline_mode(
    cfg: dict[str, Any], store: Store
) -> None:
    nflows = [SimpleNamespace(system_process_name=PROC, system_process_pid=42, src_ip=PC_IP,
                              dst_ip=LAB_C2, src_port=51000 + i, dst_port=8080, protocol=6,
                              src2dst_bytes=100, dst2src_bytes=10,
                              bidirectional_first_seen_ms=1_700_000_000_000 + i * 5000)
              for i in range(3)]
    tracker = FlowTracker(WINDOW_S)
    started: list[Any] = []

    class FakeServer:
        stopped = False

        def stop(self) -> None:
            FakeServer.stopped = True

    def starter(app: Any, c: dict[str, Any]) -> FakeServer:
        client = TestClient(app)
        assert client.post("/mode", json={"mode": "auto"}).status_code == 200
        started.append(client)
        return FakeServer()

    asyncio.run(asyncio.wait_for(
        run_agent(cfg, threading.Event(), streamer_factory=lambda c: iter(nflows),
                  detectors=[NamedDetector("none", lambda e: [])], store=store,
                  api_starter=starter, tracker=tracker),
        5.0,
    ))

    assert len(started) == 1 and FakeServer.stopped
    assert started[0].get("/status").json()["mode"] == "auto"
    apps = started[0].get("/apps").json()["apps"]
    assert [a["process"] for a in apps] == [PROC]
    assert apps[0]["flows"] == 3
