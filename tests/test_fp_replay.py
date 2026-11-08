"""False-positive regression test (ticket #49, docs/fp-test.md).

Every ``tests/fixtures/normal_use_*.jsonl`` recording (``lab/fp_recording.py`` format) is replayed
through the real :class:`agent.main.Pipeline` in ``auto`` mode with the real detectors (intel,
dga, beacon, anomaly) and the real :class:`agent.scoring.Scorer` (``config.yaml``,
``data/allowlist.txt``). Normal use must stay quiet: no medium-or-higher alert, no Action, no
firewall call. Dropping tomorrow's VM recording into tests/fixtures/ adds it automatically.

Like tests/test_smoke.py, only ``subprocess.run`` is patched (here any call fails the test at
once). Injected through the constructor seams:
    * one fake clock driven by each record's ``seen_ms`` (when the flow reached the agent), shared
      by the Pipeline, Scorer, anomaly detector and process lookup, so the anomaly calibration
      (10 min) and the 60 s scoring window behave as they did live;
    * the process lookup: every named process looks like a normal installed app (signed, under
      Program Files, not in a risky directory); ``"unknown"`` flows have no PID, as live;
    * IntelDetector: the real data/test_intel.txt, an empty feed cache and no refresh (no
      network); DgaDetector: the real models/dga.joblib when present, else the feature stub
      from the smoke test, with the real Tranco cache when present, else
      tests/fixtures/tranco_standin.txt. The real data/domain_allowlist.txt either way;
    * AnomalyDetector: the real one (as in agent/main.py's DETECTOR_FACTORIES), with baselines
      in the test's SQLite store and the shared fake clock.

A positive control splices the fake-malware check-ins into the same recording and must be caught,
so the quiet result can't come from a harness that sees nothing.
"""

from __future__ import annotations

import copy
import dataclasses
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent import config
from agent.detectors.anomaly import AnomalyDetector
from agent.detectors.beacon import BeaconDetector
from agent.detectors.dga import DgaDetector
from agent.detectors.dga_features import FEATURE_NAMES
from agent.detectors.intel import IntelDetector
from agent.events import Action, Alert, FlowEvent, Signal
from agent.main import CachedProcLookup, NamedDetector, Pipeline
from agent.procinfo import ProcInfo
from agent.scoring import Scorer
from agent.store import Store
from lab import fp_recording
from lab.fake_malware import freegamecheats as fgc
from tests.test_smoke import FeatureStubModel

FIXTURE_DIR = Path(__file__).parent / "fixtures"
NORMAL_USE_FIXTURES = sorted(FIXTURE_DIR.glob("normal_use_*.jsonl"))
SYNTHETIC_FIXTURE = FIXTURE_DIR / "normal_use_synthetic.jsonl"
TRANCO_STANDIN = FIXTURE_DIR / "tranco_standin.txt"
REAL_DGA_MODEL = config.REPO_ROOT / "models" / "dga.joblib"
REAL_TRANCO_CACHE = config.REPO_ROOT / "data" / "cache" / "tranco"
BASE_MS = 1_700_000_000_000  # recordings start at t = 0; replay them at a fixed epoch time
MEDIUM_OR_HIGHER = frozenset({"medium", "high", "critical"})

MALWARE = "FreeGameCheats.exe"
MALWARE_PID = 4242
MALWARE_EXE = r"C:\Program Files\HomeSOC-Replay\Downloads\FreeGameCheats.exe"
PC_IP = "192.168.1.50"


def fixture_id(path: Path) -> str:
    return path.stem


@dataclasses.dataclass
class Replay:
    alerts: list[Alert]
    actions: list[Action]
    published: list[Any]
    signals: list[Signal]
    anomaly: AnomalyDetector
    flows: int


def normal_app(pid: int, name: str) -> ProcInfo:
    """How an installed app looks on a normal PC: signed, under Program Files."""
    stem = name.rsplit(".", 1)[0]
    return ProcInfo(pid=pid, name=name, exe_path=rf"C:\Program Files\{stem}\{name}",
                    in_risky_dir=False, signed=True)


def build_detectors(
    cfg: dict[str, Any], tmp_path: Path, store: Store, clock_ms: Callable[[], int]
) -> tuple[list[NamedDetector], AnomalyDetector]:
    """The agent's detectors, offline (no network, no real model needed)."""
    intel = IntelDetector(cfg, cache_dir=tmp_path / "cache", spawn=lambda task: None,
                          clock=lambda: clock_ms() / 1000)
    model = None if REAL_DGA_MODEL.exists() else {
        "model": FeatureStubModel(), "feature_names": list(FEATURE_NAMES), "dga_class_index": 1,
    }
    tranco = REAL_TRANCO_CACHE if REAL_TRANCO_CACHE.exists() else TRANCO_STANDIN
    dga = DgaDetector(cfg, model=model, tranco_path=tranco)
    anomaly = AnomalyDetector(cfg, store, clock=clock_ms)
    detectors = [
        NamedDetector("intel", intel.process),
        NamedDetector("dga", dga.process),
        NamedDetector("beacon", BeaconDetector(cfg).process),
        NamedDetector("anomaly", anomaly.process),
    ]
    return detectors, anomaly


def replay(
    records: list[dict[str, Any]],
    tmp_path: Path,
    extra: list[tuple[int, FlowEvent]] | None = None,
    procs: dict[int, ProcInfo] | None = None,
    beacon_overrides: dict[str, Any] | None = None,
) -> Replay:
    """Replay ``records`` (plus ``extra`` (seen_ms, FlowEvent) pairs) through the pipeline."""
    cfg = copy.deepcopy(config.load())
    cfg["mode"] = "auto"
    cfg["detectors"]["beacon"].update(beacon_overrides or {})
    now_ms = [BASE_MS]
    events = [(seen, dataclasses.replace(ev, ts_ms=ev.ts_ms + BASE_MS, end_ms=ev.end_ms + BASE_MS))
              for seen, ev in fp_recording.replay_events(records)]
    events = sorted([(seen + BASE_MS, ev) for seen, ev in events] + (extra or []),
                    key=lambda pair: pair[0])
    names = {ev.pid: ev.process for _, ev in events if ev.pid >= 0}
    known = dict(procs or {})

    def lookup(pid: int) -> ProcInfo:
        return known.get(pid) or normal_app(pid, names[pid])

    signals: list[Signal] = []
    published: list[Any] = []
    with Store(tmp_path / "homesoc.db") as store:
        detectors, anomaly = build_detectors(cfg, tmp_path, store, lambda: now_ms[0])

        def watched(det: NamedDetector) -> NamedDetector:
            def run(event: FlowEvent) -> list[Signal]:
                out = det.process(event)
                signals.extend(out)
                return out
            return NamedDetector(det.name, run)

        pipeline = Pipeline(
            [watched(d) for d in detectors],
            Scorer(cfg, clock=lambda: now_ms[0]),
            store,
            published.append,
            proc_lookup=CachedProcLookup(30.0, lookup=lookup, clock=lambda: now_ms[0] / 1000),
            clock=lambda: now_ms[0] / 1000,
        )
        assert pipeline.scorer.mode == "auto"
        for seen, event in events:
            now_ms[0] = seen
            pipeline.handle(event)
        anomaly.tick()
        return Replay(store.list_alerts(limit=10_000), store.list_actions(limit=10_000),
                      published, signals, anomaly, len(events))


def describe(signals: list[Signal]) -> str:
    return "\n".join(f"  {s.detector} {s.process} -> {s.target} score={s.score:.2f}: "
                     f"{'; '.join(s.reasons)}" for s in signals[:20])


@pytest.fixture
def no_firewall(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Patch the PowerShell boundary: any subprocess call fails the test immediately."""
    calls: list[list[str]] = []

    def run(args: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        calls.append(list(args))
        pytest.fail(f"normal use ran a subprocess (firewall?): {args!r}")  # BaseException

    monkeypatch.setattr(subprocess, "run", run)
    return calls


# --- acceptance: normal use is quiet in auto mode ---------------------------------------------


def test_there_is_a_normal_use_fixture() -> None:
    assert NORMAL_USE_FIXTURES, "no tests/fixtures/normal_use_*.jsonl to replay"
    assert SYNTHETIC_FIXTURE in NORMAL_USE_FIXTURES


@pytest.mark.parametrize("fixture", NORMAL_USE_FIXTURES, ids=fixture_id)
def test_normal_use_replay_raises_no_alert_and_no_action_in_auto_mode(
    fixture: Path, tmp_path: Path, no_firewall: list[list[str]]
) -> None:
    records = fp_recording.load_records(fixture)
    result = replay(records, tmp_path)

    loud = [a for a in result.alerts if a.severity in MEDIUM_OR_HIGHER]
    assert loud == [], (
        f"{len(loud)} medium+ alert(s) on normal use, e.g. {loud[0].severity} "
        f"{loud[0].process}: {loud[0].title}\nsignals:\n{describe(result.signals)}"
    )
    assert result.actions == []
    assert [e for e in result.published if isinstance(e, Action | Alert)] == []
    assert no_firewall == []
    assert result.flows == len(records)


@pytest.mark.parametrize("fixture", NORMAL_USE_FIXTURES, ids=fixture_id)
def test_normal_use_fixture_outlasts_the_anomaly_calibration(fixture: Path) -> None:
    """The replay really exercises the post-calibration detectors, not just calibration."""
    records = fp_recording.load_records(fixture)
    span_ms = max(r["seen_ms"] for r in records) - min(r["seen_ms"] for r in records)
    calibration_ms = config.load()["calibration"]["minutes"] * 60_000
    assert span_ms > 2 * calibration_ms


def test_keepalives_would_alert_if_each_flow_counted_as_a_check_in(
    tmp_path: Path, no_firewall: list[list[str]]
) -> None:
    """Why ``detectors.beacon.new_connections_only`` is on: with it off, one long-lived
    connection cut into many flows by NFStream (Spotify's pings, a long download) is a
    'beacon' and normal use raises critical alerts. ``allowlisted_score`` is turned off too,
    so this shows the keepalive rule on its own."""
    result = replay(fp_recording.load_records(SYNTHETIC_FIXTURE), tmp_path,
                    beacon_overrides={"new_connections_only": False, "allowlisted_score": None})
    loud = [a for a in result.alerts if a.severity in MEDIUM_OR_HIGHER]
    assert loud
    assert {s.detector for a in loud for s in a.signals} == {"beacon"}
    assert {"spotify.exe", "chrome.exe"} <= {a.process for a in loud}
    assert result.actions == []  # allowlisted apps: alert only, even in auto mode
    assert no_firewall == []


VM_FIXTURE = FIXTURE_DIR / "normal_use_vm.jsonl"


@pytest.mark.skipif(not VM_FIXTURE.exists(), reason="no VM recording")
def test_vm_recording_would_alert_without_the_49_beacon_fixes(
    tmp_path: Path, no_firewall: list[list[str]]
) -> None:
    """Why ``skip_non_unicast`` and ``allowlisted_score`` exist: without them the real hour
    raised critical beacon alerts on Chrome's ad-server polling and Windows' IGMP/MLD reports."""
    result = replay(fp_recording.load_records(VM_FIXTURE), tmp_path,
                    beacon_overrides={"skip_non_unicast": False, "allowlisted_score": None})
    loud = [a for a in result.alerts if a.severity in MEDIUM_OR_HIGHER]
    assert {s.detector for a in loud for s in a.signals} == {"beacon"}
    assert "chrome.exe" in {a.process for a in loud}
    assert {"224.0.0.22", "ff02::16"} & {s.target for a in loud for s in a.signals}
    assert result.actions == []  # allowlisted / unknown exe: alert only, even in auto mode


def test_replay_harness_catches_malware_spliced_into_normal_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control: the lab sim's check-ins hidden in the synthetic hour are caught."""
    calls: list[list[str]] = []

    def run(args: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        calls.append(list(args))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    start_ms = BASE_MS + 1_500_000  # 25 min in: after the anomaly calibration
    every_ms = int(fgc.CHECKIN_INTERVAL_S * 1000)
    extra = []
    for i in range(12):
        ts = start_ms + i * every_ms + (-80, 60, 0, 90, -40, 30)[i % 6]
        flow = FlowEvent(ts_ms=ts, end_ms=ts + 50, process=MALWARE, pid=MALWARE_PID,
                         src_ip=PC_IP, src_port=51000 + i, dst_ip=fgc.DEFAULT_LAB_C2,
                         dst_port=fgc.DEFAULT_C2_PORT, protocol=6, app_proto="HTTP",
                         bytes_out=180, bytes_in=200, packets=6)
        extra.append((flow.end_ms + 10_000, flow))
    malware = ProcInfo(pid=MALWARE_PID, name=MALWARE, exe_path=MALWARE_EXE, in_risky_dir=True,
                       signed=False)

    result = replay(fp_recording.load_records(SYNTHETIC_FIXTURE), tmp_path, extra=extra,
                    procs={MALWARE_PID: malware})

    assert result.alerts and {a.process for a in result.alerts} == {MALWARE}
    assert {s.detector for a in result.alerts for s in a.signals} >= {"intel", "beacon"}
    assert [(a.kind, a.target) for a in result.actions] == [("quarantine_app", MALWARE_EXE)]
    assert len(calls) == 2  # the two quarantine rules, nothing else
    assert not result.anomaly.calibrating()
