"""HomeSOC never quarantines its own executable (#69).

From source the agent runs on ``python.exe`` (the venv launcher hands off to the base
interpreter); a fake-malware script started with the same interpreter has the same exe path, and
quarantining it would cut off HomeSOC's own traffic. Scoring must alert only, and the manual
``POST /alerts/{id}/quarantine`` must refuse it with a 409.
"""

from __future__ import annotations

import copy
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent import config
from agent.api import FlowTracker, create_app
from agent.config import Allowlist
from agent.events import Action, Alert, FlowEvent, Signal
from agent.main import NamedDetector, Pipeline
from agent.procinfo import ProcInfo
from agent.scoring import (
    Scorer,
    finalize_alert,
    is_own_executable,
    normalize_exe_path,
    own_executables,
)
from agent.store import Store

T0_MS = 1_700_000_000_000
C2_IP = "192.168.56.20"
VENV_PY = r"C:\Users\demo\Mocat-Security-Dashboard\.venv\Scripts\python.exe"
BASE_PY = r"C:\Users\demo\AppData\Local\Programs\Python\Python312\python.exe"
FROZEN_AGENT = r"C:\Program Files\HomeSOC\HomeSOC-Agent.exe"
MALWARE_EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"
SELF_EXES = frozenset({VENV_PY, BASE_PY})

# The fake malware run from source: its process is the base interpreter the agent runs on.
SOURCE_RUN = ProcInfo(pid=4242, name="python.exe", exe_path=BASE_PY, in_risky_dir=False,
                      signed=True)
# Same file, different spelling (case, separators, "..") as Windows may report it.
SOURCE_RUN_ODD_CASE = ProcInfo(
    pid=4242, name="python.exe",
    exe_path=r"c:/users/DEMO/AppData/Local/Programs/Python/Python312/Lib/..\PYTHON.EXE",
    in_risky_dir=False, signed=True,
)
MALWARE = ProcInfo(pid=4243, name="FreeGameCheats.exe", exe_path=MALWARE_EXE,
                   in_risky_dir=True, signed=False)
OWN_EXE_TEXT = "the program MoCat itself runs on"


class FakeClock:
    def __init__(self, now_ms: int = T0_MS) -> None:
        self.now_ms = now_ms

    def __call__(self) -> int:
        return self.now_ms


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


def make_scorer(cfg: dict[str, Any], mode: str = "auto") -> Scorer:
    return Scorer(cfg, Allowlist(frozenset({"chrome.exe"})), clock=FakeClock(), mode=mode,
                  self_exes=SELF_EXES)


def sig(detector: str, score: float, process: str = "python.exe", pid: int = 4242) -> Signal:
    return Signal(detector=detector, process=process, pid=pid, target=C2_IP, score=score,
                  reasons=[f"{detector} reason"], mitre="T1071", ts_ms=T0_MS)


# --- the own-executable set ---------------------------------------------------------------


def test_own_executables_from_source_include_the_base_interpreter() -> None:
    fake_sys = SimpleNamespace(executable=VENV_PY, _base_executable=BASE_PY)
    own = own_executables(fake_sys)
    assert normalize_exe_path(VENV_PY) in own
    assert normalize_exe_path(BASE_PY) in own


def test_own_executables_when_frozen_ignore_the_base_interpreter() -> None:
    fake_sys = SimpleNamespace(executable=FROZEN_AGENT, _base_executable=BASE_PY, frozen=True)
    own = own_executables(fake_sys)
    assert normalize_exe_path(FROZEN_AGENT) in own
    assert normalize_exe_path(BASE_PY) not in own
    assert is_own_executable(FROZEN_AGENT, own)
    assert not is_own_executable(BASE_PY, own)


def test_own_executables_skip_missing_attributes() -> None:
    assert own_executables(SimpleNamespace(executable="", frozen=False)) == frozenset()


def test_own_executables_default_is_the_real_interpreter() -> None:
    import sys

    assert is_own_executable(sys.executable)
    assert is_own_executable(sys.executable, own_executables())


def test_own_executable_match_is_case_insensitive_and_normalised() -> None:
    assert is_own_executable(SOURCE_RUN_ODD_CASE.exe_path, SELF_EXES)
    assert is_own_executable(BASE_PY.upper(), SELF_EXES)
    assert not is_own_executable(MALWARE_EXE, SELF_EXES)
    assert not is_own_executable(None, SELF_EXES)
    assert not is_own_executable("", SELF_EXES)


# --- scoring ------------------------------------------------------------------------------


@pytest.mark.parametrize("proc", [SOURCE_RUN, SOURCE_RUN_ODD_CASE], ids=["exact", "odd_case"])
def test_auto_intel_hit_on_own_exe_alerts_but_never_quarantines(
    cfg: dict[str, Any], proc: ProcInfo
) -> None:
    scorer = make_scorer(cfg)
    decision = scorer.add(sig("intel", 1.0), proc)
    assert decision.own_exe is True
    assert decision.alert is not None
    assert decision.alert.severity == "critical"
    assert decision.action is None
    assert OWN_EXE_TEXT in decision.alert.what_we_did
    assert "Nothing was blocked" in decision.alert.what_we_did
    assert "without blocking itself" in decision.alert.what_you_should_do
    # finalize_alert (what the pipeline calls) keeps the explanation.
    final = finalize_alert(decision, [])
    assert OWN_EXE_TEXT in final.what_we_did
    assert final.action_ids == []


def test_auto_strong_multi_detector_risk_on_own_exe_never_quarantines(
    cfg: dict[str, Any]
) -> None:
    scorer = make_scorer(cfg)
    decisions = [scorer.add(sig("dga", 0.95), SOURCE_RUN),
                 scorer.add(sig("beacon", 0.95), SOURCE_RUN),
                 scorer.add(sig("anomaly", 0.9), SOURCE_RUN)]
    assert decisions[-1].risk >= 0.85
    assert any(d.alert is not None for d in decisions)
    assert all(d.action is None for d in decisions)


def test_other_exe_paths_are_still_quarantined(cfg: dict[str, Any]) -> None:
    scorer = make_scorer(cfg)
    decision = scorer.add(sig("intel", 1.0, process="FreeGameCheats.exe", pid=4243), MALWARE)
    assert decision.own_exe is False
    assert decision.action is not None
    assert decision.action.kind == "quarantine_app"
    assert decision.action.target == MALWARE_EXE
    assert decision.alert is not None
    assert OWN_EXE_TEXT not in decision.alert.what_we_did


def test_scorer_default_self_exes_protect_the_running_interpreter(cfg: dict[str, Any]) -> None:
    import sys

    scorer = Scorer(cfg, Allowlist(frozenset()), clock=FakeClock(), mode="auto")
    me = ProcInfo(pid=os.getpid(), name="python.exe", exe_path=sys.executable,
                  in_risky_dir=False, signed=True)
    decision = scorer.add(sig("intel", 1.0), me)
    assert decision.alert is not None
    assert decision.action is None


# --- pipeline: no PowerShell for the own exe -----------------------------------------------


class PowerShellRecorder:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append(list(args))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")


def test_pipeline_never_runs_a_firewall_command_for_the_own_exe(
    cfg: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    powershell = PowerShellRecorder()
    monkeypatch.setattr(subprocess, "run", powershell)

    def intel(event: FlowEvent) -> list[Signal]:
        return [sig("intel", 1.0, process=event.process, pid=event.pid)]

    procs = {4242: SOURCE_RUN, 4243: MALWARE}
    published: list[Any] = []
    with Store(tmp_path / "homesoc.db") as store:
        pipeline = Pipeline([NamedDetector("intel", intel)], make_scorer(cfg), store,
                            published.append, proc_lookup=lambda pid, _name: procs[pid])
        alerts = pipeline.handle(FlowEvent(process="python.exe", pid=4242, dst_ip=C2_IP))
        assert len(alerts) == 1
        assert alerts[0].action_ids == []
        assert OWN_EXE_TEXT in alerts[0].what_we_did
        assert powershell.calls == []
        assert store.list_actions() == []

        # Another app in the same run is still quarantined through the real firewall module.
        alerts = pipeline.handle(FlowEvent(process="FreeGameCheats.exe", pid=4243, dst_ip=C2_IP))
        assert len(alerts) == 1
        assert len(alerts[0].action_ids) == 1
        assert len(powershell.calls) == 2  # one PowerShell call per rule (out + in)
        assert all(MALWARE_EXE in " ".join(call) for call in powershell.calls)
        assert [a.kind for a in store.list_actions()] == ["quarantine_app"]


# --- API: manual quarantine ---------------------------------------------------------------


class FakeFirewall:
    def __init__(self) -> None:
        self.quarantine_calls: list[str] = []

    def quarantine_app(self, exe_path: str) -> Action:
        self.quarantine_calls.append(exe_path)
        return Action(id="q-new", ts_ms=7, kind="quarantine_app", target=exe_path,
                      rule_names=["HomeSOC quarantine x out #aaaa"])

    def fns(self) -> dict[str, Any]:
        return {"undo": lambda a: a, "undo_all": lambda: None,
                "quarantine_app": self.quarantine_app}


def make_alert(alert_id: str, exe_path: str, process: str) -> Alert:
    return Alert(id=alert_id, ts_ms=10, severity="high", process=process, exe_path=exe_path,
                 risk=0.9, title="t", what_happened="h", what_we_did="Nothing was blocked.",
                 what_you_should_do="s", signals=[sig("beacon", 0.9, process=process)])


@pytest.fixture
def api_env(cfg: dict[str, Any], tmp_path: Path) -> Any:
    fw = FakeFirewall()
    with Store(tmp_path / "homesoc.db") as store:
        app = create_app(store, make_scorer(cfg, mode="notify"), FlowTracker(600.0, lambda: 0.0),
                         firewall_fns=fw.fns(), allowlist=Allowlist(frozenset()),
                         self_exes=SELF_EXES)
        yield SimpleNamespace(client=TestClient(app), store=store, fw=fw)


@pytest.mark.parametrize("exe_path", [BASE_PY, VENV_PY.lower(), SOURCE_RUN_ODD_CASE.exe_path],
                         ids=["base", "venv_lower", "odd_case"])
def test_manual_quarantine_of_own_exe_is_409_with_no_firewall_call(
    api_env: Any, exe_path: str
) -> None:
    api_env.store.save_alert(make_alert("al1", exe_path, "python.exe"))
    response = api_env.client.post("/alerts/al1/quarantine")
    assert response.status_code == 409
    assert OWN_EXE_TEXT in response.json()["detail"]
    assert api_env.fw.quarantine_calls == []
    assert api_env.store.list_actions() == []
    assert api_env.store.get_alert("al1").action_ids == []


def test_manual_quarantine_of_another_exe_still_works(api_env: Any) -> None:
    api_env.store.save_alert(make_alert("al2", MALWARE_EXE, "FreeGameCheats.exe"))
    response = api_env.client.post("/alerts/al2/quarantine")
    assert response.status_code == 200
    assert api_env.fw.quarantine_calls == [MALWARE_EXE]
    assert [a.id for a in api_env.store.list_actions()] == ["q-new"]


def test_create_app_default_refuses_the_running_interpreter(
    cfg: dict[str, Any], tmp_path: Path
) -> None:
    import sys

    fw = FakeFirewall()
    with Store(tmp_path / "homesoc.db") as store:
        app = create_app(store, make_scorer(cfg, mode="notify"), FlowTracker(600.0, lambda: 0.0),
                         firewall_fns=fw.fns(), allowlist=Allowlist(frozenset()))
        store.save_alert(make_alert("al3", sys.executable, "python.exe"))
        response = TestClient(app).post("/alerts/al3/quarantine")
    assert response.status_code == 409
    assert fw.quarantine_calls == []
