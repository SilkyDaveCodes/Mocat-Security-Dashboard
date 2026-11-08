"""Tests for agent.evidence and ``GET /alerts/{id}/evidence`` (CLAUDE.md §6.8, ticket #44).

No dumpcap / tshark / mergecap ever runs: the rolling capture gets a fake ``Popen`` and the
exporter a fake ``run`` (and ``subprocess.Popen`` / ``subprocess.run`` are patched to fail the
test if anything reaches them). The ring and evidence directories live in ``tmp_path``.
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

from agent import config, evidence
from agent.api import FlowTracker, create_app
from agent.config import Allowlist
from agent.events import Alert, Signal
from agent.evidence import (
    EvidenceExporter,
    EvidenceSettings,
    RingCapture,
    build_dumpcap_args,
    build_tshark_args,
)
from agent.main import NamedDetector, run_agent
from agent.scoring import Scorer
from agent.store import Store
from tests.api_helpers import local_client

LAB_C2 = "192.168.56.20"
ALERT_ID = "0123456789abcdef0123456789abcdef"  # what scoring makes: uuid4().hex
TIMEOUT_S = 10.0


# --- fakes ----------------------------------------------------------------------------------


class FakeRun:
    """subprocess.run stand-in: records argv + kwargs, writes the ``-w`` file like tshark."""

    def __init__(self, returncode: int = 0, exc: BaseException | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.returncode = returncode
        self.exc = exc

    def __call__(self, args: list[str], **kwargs: Any) -> SimpleNamespace:
        self.calls.append((list(args), kwargs))
        if self.exc is not None:
            raise self.exc
        if self.returncode == 0:
            Path(args[args.index("-w") + 1]).write_bytes(b"pcap")
        return SimpleNamespace(returncode=self.returncode, stdout="", stderr="boom")

    @property
    def argvs(self) -> list[list[str]]:
        return [a for a, _ in self.calls]


class FakeProc:
    def __init__(self, exits_on_terminate: bool = True, exited: int | None = None) -> None:
        self.exits_on_terminate = exits_on_terminate
        self.code = exited
        self.events: list[str] = []

    def poll(self) -> int | None:
        return self.code

    def terminate(self) -> None:
        self.events.append("terminate")
        if self.exits_on_terminate:
            self.code = 0

    def wait(self, timeout: float | None = None) -> int:
        self.events.append(f"wait({timeout})")
        if self.code is None and timeout is not None:
            raise subprocess.TimeoutExpired("dumpcap", timeout)
        return self.code if self.code is not None else -9

    def kill(self) -> None:
        self.events.append("kill")
        self.code = -9


class FakePopen:
    def __init__(self, proc: FakeProc | None = None, exc: BaseException | None = None) -> None:
        self.proc = proc or FakeProc()
        self.exc = exc
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> FakeProc:
        self.calls.append((list(args), kwargs))
        if self.exc is not None:
            raise self.exc
        return self.proc


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anything that reaches the real subprocess functions fails the test."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError(f"a real process was started: {args!r}")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)


# --- fixtures -------------------------------------------------------------------------------


@pytest.fixture
def cfg(tmp_path: Path) -> dict[str, Any]:
    data = copy.deepcopy(config.load())
    data["capture"]["interface"] = "Ethernet 2"
    data["evidence"]["ring_path"] = str(tmp_path / "ring" / "ring.pcapng")
    data["evidence"]["evidence_dir"] = str(tmp_path / "evidence")
    data["evidence"]["dumpcap"] = "dumpcap"
    data["evidence"]["tshark"] = "tshark"
    data["evidence"]["mergecap"] = "mergecap"
    return data


@pytest.fixture
def settings(cfg: dict[str, Any]) -> EvidenceSettings:
    return EvidenceSettings.from_config(cfg)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "homesoc.db") as db:
        yield db


@pytest.fixture
def run() -> FakeRun:
    return FakeRun()


@pytest.fixture
def client(store: Store, cfg: dict[str, Any], settings: EvidenceSettings,
           run: FakeRun) -> TestClient:
    scorer = Scorer(cfg, Allowlist(frozenset()), mode="notify")
    app = create_app(store, scorer, FlowTracker(600.0), allowlist=Allowlist(frozenset()),
                     evidence=EvidenceExporter(settings, run=run))
    return local_client(app)


def make_ring_file(settings: EvidenceSettings, name: str | None = None) -> Path:
    path = settings.ring_path if name is None else settings.ring_path.parent / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"ring")
    return path


def signal(target: str, detector: str = "beacon") -> Signal:
    return Signal(detector=detector, process="FreeGameCheats.exe", pid=42,  # type: ignore[arg-type]
                  target=target, score=0.9, reasons=["r"])


def make_alert(alert_id: str = ALERT_ID, targets: tuple[str, ...] = (LAB_C2,)) -> Alert:
    return Alert(id=alert_id, ts_ms=1, severity="high", process="FreeGameCheats.exe",
                 exe_path=r"C:\Users\demo\Downloads\FreeGameCheats.exe", risk=0.9, title="t",
                 signals=[signal(t) for t in targets])


# --- AC1: dumpcap command (§6.8) with the configured interface --------------------------------


def test_dumpcap_args_match_spec_with_configured_interface(settings: EvidenceSettings) -> None:
    assert build_dumpcap_args(settings) == [
        "dumpcap", "-i", "Ethernet 2", "-b", "filesize:20000", "-b", "files:5",
        "-w", str(settings.ring_path),
    ]


def test_default_config_ring_matches_spec() -> None:
    s = EvidenceSettings.from_config(config.load())
    args = build_dumpcap_args(s)
    assert args[1:8] == ["-i", config.load()["capture"]["interface"],
                         "-b", "filesize:20000", "-b", "files:5", "-w"]
    assert s.ring_path == config.REPO_ROOT / "data" / "ring.pcapng"
    assert s.evidence_dir == config.REPO_ROOT / "data" / "evidence"


def test_ring_capture_starts_dumpcap_as_arg_list_without_shell(settings: EvidenceSettings) -> None:
    popen = FakePopen()
    ring = RingCapture(settings, popen=popen)

    assert ring.start() is True

    [(argv, kwargs)] = popen.calls
    assert argv == build_dumpcap_args(settings)
    assert kwargs.get("shell", False) is False
    assert settings.ring_path.parent.is_dir()
    assert ring.running


def test_ring_capture_missing_dumpcap_warns_and_continues(
    settings: EvidenceSettings, caplog: pytest.LogCaptureFixture
) -> None:
    ring = RingCapture(settings, popen=FakePopen(exc=FileNotFoundError("dumpcap")))

    assert ring.start() is False
    assert not ring.running
    assert "Rolling capture not started" in caplog.text
    ring.stop()  # nothing to stop; must not raise


def test_ring_capture_stop_terminates_then_waits(settings: EvidenceSettings) -> None:
    proc = FakeProc()
    ring = RingCapture(settings, popen=FakePopen(proc))
    ring.start()

    ring.stop()

    assert proc.events == ["terminate", f"wait({settings.stop_timeout_s})"]
    assert not ring.running


def test_ring_capture_stop_kills_a_dumpcap_that_hangs(settings: EvidenceSettings) -> None:
    proc = FakeProc(exits_on_terminate=False)
    ring = RingCapture(settings, popen=FakePopen(proc))
    ring.start()

    ring.stop()

    assert proc.events == ["terminate", f"wait({settings.stop_timeout_s})", "kill", "wait(None)"]


def test_run_agent_starts_ring_capture_and_stops_it_on_shutdown(
    cfg: dict[str, Any], store: Store
) -> None:
    proc = FakeProc()
    popen = FakePopen(proc)
    rings: list[RingCapture] = []

    def ring_starter(c: dict[str, Any]) -> RingCapture:
        rings.append(evidence.start_ring_capture(c, popen=popen))
        return rings[-1]

    asyncio.run(asyncio.wait_for(
        run_agent(cfg, threading.Event(), streamer_factory=lambda c: iter([]),
                  detectors=[NamedDetector("none", lambda e: [])], store=store,
                  ring_starter=ring_starter),
        TIMEOUT_S,
    ))

    [(argv, _)] = popen.calls
    assert argv[:3] == ["dumpcap", "-i", "Ethernet 2"]
    assert proc.events[0] == "terminate"  # stopped when the agent shut down
    assert not rings[0].running


def test_run_agent_keeps_running_when_ring_starter_raises(
    cfg: dict[str, Any], store: Store, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(_: dict[str, Any]) -> None:
        raise RuntimeError("no dumpcap")

    asyncio.run(asyncio.wait_for(
        run_agent(cfg, threading.Event(), streamer_factory=lambda c: iter([]),
                  detectors=[], store=store, ring_starter=broken),
        TIMEOUT_S,
    ))
    assert "Rolling capture could not start" in caplog.text


# --- AC2: evidence command filters on the target IP, writes <alert_id>.pcap -------------------


def test_evidence_runs_tshark_on_target_ip_and_writes_alert_pcap(
    client: TestClient, store: Store, settings: EvidenceSettings, run: FakeRun
) -> None:
    ring = make_ring_file(settings)
    store.save_alert(make_alert())

    resp = client.get(f"/alerts/{ALERT_ID}/evidence")

    assert resp.status_code == 200
    out = settings.evidence_dir.resolve() / f"{ALERT_ID}.pcap"
    assert run.argvs == [["tshark", "-r", str(ring), "-Y", f"ip.addr=={LAB_C2}", "-w", str(out)]]
    assert out.read_bytes() == b"pcap"
    assert resp.json() == {"alert_id": ALERT_ID, "ip": LAB_C2, "path": str(out), "bytes": 4,
                           "ring_files": 1}


def test_build_tshark_args_matches_spec() -> None:
    assert build_tshark_args("tshark", Path("data/ring.pcapng"), "10.0.0.5",
                             Path("data/evidence/abc.pcap")) == [
        "tshark", "-r", str(Path("data/ring.pcapng")), "-Y", "ip.addr==10.0.0.5",
        "-w", str(Path("data/evidence/abc.pcap")),
    ]


def test_evidence_skips_domain_targets_and_canonicalises_ip(
    store: Store, settings: EvidenceSettings, run: FakeRun
) -> None:
    make_ring_file(settings)
    alert = make_alert(targets=("kqzxv7.example", "2001:DB8:0:0::1", LAB_C2))

    result = EvidenceExporter(settings, run=run).export(alert)

    assert result.ip == "2001:db8::1"
    assert run.argvs[0][3:5] == ["-Y", "ipv6.addr==2001:db8::1"]


def test_evidence_filters_each_ring_file_and_merges_in_order(
    settings: EvidenceSettings, run: FakeRun
) -> None:
    # dumpcap's ring names; numbered 10 sorts after 9 by number, not by text.
    newest = make_ring_file(settings, "ring_00010_20261107120500.pcapng")
    oldest = make_ring_file(settings, "ring_00009_20261107120000.pcapng")
    make_ring_file(settings, "other_00001_20261107120000.pcapng")  # not ours

    result = EvidenceExporter(settings, run=run).export(make_alert())

    out = settings.evidence_dir.resolve() / f"{ALERT_ID}.pcap"
    tshark_calls, merge_call = run.argvs[:-1], run.argvs[-1]
    assert [a[2] for a in tshark_calls] == [str(oldest), str(newest)]
    assert all(a[0] == "tshark" and a[3:5] == ["-Y", f"ip.addr=={LAB_C2}"] for a in tshark_calls)
    parts = [a[6] for a in tshark_calls]
    assert merge_call == ["mergecap", "-w", str(out), *parts]
    assert result.ring_files == 2 and out.exists()
    assert [p for p in settings.evidence_dir.iterdir()] == [out]  # temp parts removed


def test_evidence_with_no_ring_files_is_503_and_runs_nothing(
    client: TestClient, store: Store, run: FakeRun
) -> None:
    store.save_alert(make_alert())

    resp = client.get(f"/alerts/{ALERT_ID}/evidence")

    assert resp.status_code == 503
    assert run.calls == []


def test_evidence_tshark_missing_is_503(client: TestClient, store: Store,
                                        settings: EvidenceSettings, run: FakeRun) -> None:
    make_ring_file(settings)
    store.save_alert(make_alert())
    run.exc = FileNotFoundError("tshark")

    assert client.get(f"/alerts/{ALERT_ID}/evidence").status_code == 503


@pytest.mark.parametrize("failure", [{"returncode": 2},
                                     {"exc": subprocess.TimeoutExpired("tshark", 60)}])
def test_evidence_tshark_failure_is_502(store: Store, settings: EvidenceSettings,
                                        cfg: dict[str, Any], failure: dict[str, Any]) -> None:
    make_ring_file(settings)
    store.save_alert(make_alert())
    app = create_app(store, Scorer(cfg, Allowlist(frozenset())), FlowTracker(600.0),
                     allowlist=Allowlist(frozenset()),
                     evidence=EvidenceExporter(settings, run=FakeRun(**failure)))

    resp = local_client(app).get(f"/alerts/{ALERT_ID}/evidence")

    assert resp.status_code == 502


def test_evidence_without_exporter_is_503(store: Store, cfg: dict[str, Any]) -> None:
    store.save_alert(make_alert())
    app = create_app(store, Scorer(cfg, Allowlist(frozenset())), FlowTracker(600.0),
                     allowlist=Allowlist(frozenset()))
    assert local_client(app).get(f"/alerts/{ALERT_ID}/evidence").status_code == 503


# --- AC3: unsafe alert id / non-IP target rejected before any command ------------------------


@pytest.mark.parametrize("bad_id", ["../../x", "..\\..\\x", "..", "a b", "x;rm", "a" * 65, "",
                                    "abc.pcap", "C:\\x"])
def test_exporter_rejects_unsafe_alert_id_before_running(
    settings: EvidenceSettings, run: FakeRun, bad_id: str
) -> None:
    make_ring_file(settings)

    with pytest.raises(evidence.UnsafeAlertIdError):
        EvidenceExporter(settings, run=run).export(make_alert(alert_id=bad_id))

    assert run.calls == []
    assert not settings.evidence_dir.exists()


@pytest.mark.parametrize("encoded", ["..%5C..%5Cx", "x%20y", "a.b", "x%3Bdel"])
def test_api_rejects_unsafe_alert_id_with_400(client: TestClient, store: Store,
                                              settings: EvidenceSettings, run: FakeRun,
                                              encoded: str) -> None:
    make_ring_file(settings)
    store.save_alert(make_alert(alert_id="..\\..\\x"))  # even a stored alert with that id

    resp = client.get(f"/alerts/{encoded}/evidence")

    assert resp.status_code == 400
    assert run.calls == []


@pytest.mark.parametrize("targets", [("kqzxv7.example",), ("",), ("192.168.56.300",),
                                     ("fe80::1%eth0",), ("192.168.56.20; calc",),
                                     ("192.168.56.20 or 1==1",)])
def test_non_ip_target_is_rejected_before_running(
    client: TestClient, store: Store, settings: EvidenceSettings, run: FakeRun,
    targets: tuple[str, ...]
) -> None:
    make_ring_file(settings)
    store.save_alert(make_alert(targets=targets))

    resp = client.get(f"/alerts/{ALERT_ID}/evidence")

    assert resp.status_code == 409
    assert run.calls == []
    with pytest.raises(evidence.NoTargetIpError):
        EvidenceExporter(settings, run=run).export(make_alert(targets=targets))
    assert run.calls == []


def test_evidence_path_stays_inside_evidence_dir(tmp_path: Path) -> None:
    assert evidence.evidence_path(tmp_path, "abc_DEF-1") == tmp_path.resolve() / "abc_DEF-1.pcap"
    with pytest.raises(evidence.UnsafeAlertIdError):
        evidence.evidence_path(tmp_path, "../x")


# --- AC4: unknown alert id -> 404 -------------------------------------------------------------


def test_unknown_alert_id_is_404_and_runs_nothing(client: TestClient, settings: EvidenceSettings,
                                                  run: FakeRun) -> None:
    make_ring_file(settings)

    resp = client.get("/alerts/doesnotexist/evidence")

    assert resp.status_code == 404
    assert run.calls == []


# --- AC5: argument lists, never a shell -------------------------------------------------------


def test_every_command_is_an_arg_list_without_shell(settings: EvidenceSettings,
                                                    run: FakeRun) -> None:
    make_ring_file(settings, "ring_00001_20261107120000.pcapng")
    make_ring_file(settings, "ring_00002_20261107120100.pcapng")
    popen = FakePopen()

    RingCapture(settings, popen=popen).start()
    EvidenceExporter(settings, run=run).export(make_alert())

    calls = popen.calls + run.calls
    assert len(calls) == 4  # dumpcap, tshark x2, mergecap
    for argv, kwargs in calls:
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        assert kwargs.get("shell", False) is False
    # The filter is one argument: no quoting for a shell to strip.
    assert run.argvs[0][4] == f"ip.addr=={LAB_C2}"


def test_ring_files_ignore_unrelated_and_include_literal_ring(settings: EvidenceSettings) -> None:
    assert evidence.ring_files(settings.ring_path) == []
    literal = make_ring_file(settings)
    numbered = make_ring_file(settings, "ring_00003_20261107120000.pcapng")
    make_ring_file(settings, "ring_00004_2026.pcapng")  # malformed date
    make_ring_file(settings, "ring_00005_20261107120000.pcap")  # wrong suffix
    assert evidence.ring_files(settings.ring_path) == [literal, numbered]

