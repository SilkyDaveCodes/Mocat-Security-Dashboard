"""End-to-end smoke test of the demo path (CLAUDE.md §12 step 3-6, ticket #19).

Replays what ``lab/fake_malware/freegamecheats.py`` looks like on the wire (its own
``generate_domains`` names resolved through the lab DNS, then an HTTP check-in to the lab C2
192.168.56.20:8080 every 5 s, each its own flow) through the real pipeline in ``auto`` mode:

    FlowEvents -> real intel / dga / beacon detectors -> real Scorer (config.yaml, real
    data/allowlist.txt) -> real firewall.quarantine_app -> real SQLite Store -> Alert
    -> real firewall.undo -> Store.mark_undone

Patched: only ``subprocess.run`` (every PowerShell call "succeeds" and is recorded).
Injected through the existing constructor seams (dependency injection, not patching):
    * a fake clock for the Scorer and Pipeline, advanced to each flow's time (no sleeping),
    * the process lookup: a :class:`CachedProcLookup` over a function that returns the ProcInfo
      of ``C:\\Users\\demo\\Downloads\\FreeGameCheats.exe`` (no real PID exists in a test),
    * IntelDetector: an empty lab test list and a no-op refresh spawner (no network). With the
      shipped data/test_intel.txt, 192.168.56.20 is "known bad" and intel alone would quarantine
      on the first check-in; that path is covered in test_scoring.py. Here the list is empty so
      the smoke test guards the DGA + beacon path the demo checklist walks through.
    * DgaDetector: the real models/dga.joblib when it exists; otherwise (it is not checked in,
      so on CI / a fresh checkout) a stub classifier that thresholds the real
      ``dga_features`` vector (bigram rarity + length), the same pattern as tests/test_main.py.
      The Tranco cache is a tmp file, so nothing is downloaded.

Runs on any OS with no Npcap, admin rights, network or real PowerShell.
"""

from __future__ import annotations

import copy
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from agent import config
from agent.detectors.beacon import BeaconDetector
from agent.detectors.dga import DgaDetector
from agent.detectors.dga_features import FEATURE_NAMES
from agent.detectors.intel import IntelDetector
from agent.events import Action, Alert, FlowEvent
from agent.main import CachedProcLookup, NamedDetector, Pipeline
from agent.procinfo import ProcInfo
from agent.response import firewall
from agent.scoring import Scorer
from agent.store import Store
from lab.fake_malware import freegamecheats as fgc

pytestmark = pytest.mark.smoke

PROC = "FreeGameCheats.exe"
PID = 4242
EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"
PC_IP = "192.168.56.10"
LAB_C2 = fgc.DEFAULT_LAB_C2
C2_PORT = fgc.DEFAULT_C2_PORT
CHECKIN_EVERY_MS = int(fgc.CHECKIN_INTERVAL_S * 1000)
CHECKINS = 12
DOMAIN_SEED = 19
BENIGN_HOST = "www.microsoft.com"  # in the (tmp) Tranco cache -> never scored
T0_MS = 1_700_000_000_000
MAX_RUNTIME_S = 10.0
REAL_DGA_MODEL = config.REPO_ROOT / "models" / "dga.joblib"

# Matches one PowerShell single-quoted literal ('' is an escaped quote inside it).
PS_LITERAL = re.compile(r"'((?:[^']|'')*)'")


class FeatureStubModel:
    """Stands in for the trained DGA classifier when models/dga.joblib is absent.

    Works on the real feature vector: a long label made of rare bigrams scores as DGA.
    """

    def __init__(self) -> None:
        self._length = FEATURE_NAMES.index("length")
        self._rarity = FEATURE_NAMES.index("bigram_rarity")

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        out = []
        for row in rows:
            p = 0.97 if row[self._length] >= 10 and row[self._rarity] >= 9.5 else 0.03
            out.append([1.0 - p, p])
        return out


class PowerShellRecorder:
    """Fake ``subprocess.run``: records every argv, always exits 0."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append(list(args))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    def firewall_commands(self) -> list[str]:
        """The ``-Command`` text of every firewall PowerShell call, in order."""
        return [c[-1] for c in self.calls
                if tuple(c[:-1]) == firewall.POWERSHELL_ARGV and "NetFirewallRule" in c[-1]]


def homesoc_literals(cmd: str) -> set[str]:
    """Every rule display name (a literal starting with 'HomeSOC ') in a PowerShell command."""
    return {m.replace("''", "'") for m in PS_LITERAL.findall(cmd) if m.startswith("HomeSOC ")}


# --- the replay ------------------------------------------------------------------------------


def fake_malware_flows() -> list[FlowEvent]:
    """A benign lookup, the sim's DGA lookups, then 12 check-ins every 5 s (±0.1 s jitter)."""
    flows: list[FlowEvent] = []
    hosts = [BENIGN_HOST, *fgc.generate_domains(DOMAIN_SEED)]
    for i, host in enumerate(hosts):
        ts = T0_MS + i * 150
        flows.append(FlowEvent(
            ts_ms=ts, end_ms=ts + 20, process=PROC, pid=PID, src_ip=PC_IP, src_port=50000 + i,
            dst_ip=LAB_C2, dst_port=53, protocol=17, hostname=host, app_proto="DNS",
            bytes_out=60, bytes_in=90, packets=2,
        ))
    start = T0_MS + 2_000
    for i in range(CHECKINS):
        jitter = (-80, 60, 0, 90, -40, 30)[i % 6]
        ts = start + i * CHECKIN_EVERY_MS + jitter
        flows.append(FlowEvent(
            ts_ms=ts, end_ms=ts + 50, process=PROC, pid=PID, src_ip=PC_IP, src_port=51000 + i,
            dst_ip=LAB_C2, dst_port=C2_PORT, protocol=6, hostname=LAB_C2, app_proto="HTTP",
            bytes_out=180, bytes_in=200, packets=6,
        ))
    return flows


def build_detectors(cfg: dict[str, Any], tmp_path: Path) -> list[NamedDetector]:
    """The same three detectors as agent.main.DETECTOR_FACTORIES, offline."""
    empty_intel = tmp_path / "test_intel.txt"
    empty_intel.write_text("# empty for the smoke test\n", encoding="utf-8")
    intel = IntelDetector(cfg, cache_dir=tmp_path / "cache", test_intel_path=empty_intel,
                          spawn=lambda task: None)
    tranco = tmp_path / "tranco.csv"
    tranco.write_text("1,google.com\n2,microsoft.com\n", encoding="utf-8")
    model = None if REAL_DGA_MODEL.exists() else {
        "model": FeatureStubModel(), "feature_names": list(FEATURE_NAMES), "dga_class_index": 1,
    }
    dga = DgaDetector(cfg, model=model, tranco_path=tranco)
    return [
        NamedDetector("intel", intel.process),
        NamedDetector("dga", dga.process),
        NamedDetector("beacon", BeaconDetector(cfg).process),
    ]


def test_fake_malware_alert_quarantine_undo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = time.perf_counter()
    powershell = PowerShellRecorder()
    monkeypatch.setattr(subprocess, "run", powershell)  # the only patch

    cfg = copy.deepcopy(config.load())
    cfg["mode"] = "auto"
    now_ms = [T0_MS]
    malware = ProcInfo(pid=PID, name=PROC, exe_path=EXE, in_risky_dir=True, signed=False)
    lookups: list[int] = []

    def lookup(pid: int) -> ProcInfo:
        lookups.append(pid)
        return malware

    published: list[Any] = []
    with Store(tmp_path / "homesoc.db") as store:
        pipeline = Pipeline(
            build_detectors(cfg, tmp_path),
            Scorer(cfg, clock=lambda: now_ms[0]),  # real config.yaml + data/allowlist.txt
            store,
            published.append,
            proc_lookup=CachedProcLookup(30.0, lookup=lookup, clock=lambda: now_ms[0] / 1000),
            clock=lambda: now_ms[0] / 1000,
        )
        assert pipeline.scorer.mode == "auto"

        # --- replay ----------------------------------------------------------------------
        for flow in fake_malware_flows():
            now_ms[0] = flow.end_ms  # NFStream hands a flow over once it ends
            pipeline.handle(flow)

        # Cached per PID for 30 s: the ~1 min replay needs at most two lookups, not one per signal.
        assert lookups == [PID, PID]

        # --- the alert -------------------------------------------------------------------
        alerts = store.list_alerts()
        assert alerts
        assert all(a.process == PROC for a in alerts)
        assert all(BENIGN_HOST not in {s.target for s in a.signals} for a in alerts)
        demo = [a for a in alerts if {"dga", "beacon"} <= {s.detector for s in a.signals}]
        assert demo, "no alert carries both a dga and a beacon signal"
        quarantine_alert = next(a for a in demo if a.action_ids)
        assert quarantine_alert.severity in {"high", "critical"}
        assert quarantine_alert.process == PROC
        assert quarantine_alert.exe_path == EXE
        beacon = next(s for s in quarantine_alert.signals if s.detector == "beacon")
        assert beacon.target == LAB_C2
        assert "every 5.0 s" in " ".join(beacon.reasons)
        assert PROC in quarantine_alert.what_we_did

        # --- the quarantine action -------------------------------------------------------
        actions = store.list_actions()
        assert len(actions) == 1
        action = actions[0]
        assert action.kind == "quarantine_app"
        assert action.target == EXE
        assert action.undone is False
        assert quarantine_alert.action_ids == [action.id]
        assert len(action.rule_names) == 2
        assert all(name.startswith("HomeSOC ") for name in action.rule_names)
        assert len(set(action.rule_names)) == 2

        # Nothing but the firewall ran a subprocess.
        create_cmds = powershell.firewall_commands()
        assert len(powershell.calls) == len(create_cmds) == 2
        for name, cmd in zip(action.rule_names, create_cmds, strict=True):
            assert cmd.startswith("New-NetFirewallRule ")
            assert f"-DisplayName '{name}'" in cmd
            assert "-Group 'HomeSOC'" in cmd
            assert f"-Program '{EXE}'" in cmd
            assert "-Action Block" in cmd
            assert homesoc_literals(cmd) == {name}
        assert "-Direction Outbound" in create_cmds[0]
        assert "-Direction Inbound" in create_cmds[1]

        # Published to the bus (UI) too: the Action before the Alert that refers to it.
        ids = [e.id for e in published if isinstance(e, Action | Alert)]
        assert action.id in ids and quarantine_alert.id in ids
        assert ids.index(action.id) < ids.index(quarantine_alert.id)

        # --- undo (what POST /actions/{id}/undo will do) ---------------------------------
        powershell.calls.clear()
        stored = store.get_action(action.id)
        assert stored is not None
        undo_action = firewall.undo(stored)
        store.save_action(undo_action)
        assert store.mark_undone(action.id) is True

        remove_cmds = powershell.firewall_commands()
        assert len(powershell.calls) == len(remove_cmds) == 2
        for name, cmd in zip(action.rule_names, remove_cmds, strict=True):
            assert "New-NetFirewallRule" not in cmd
            assert "Get-NetFirewallRule -Group 'HomeSOC'" in cmd
            assert f"$_.DisplayName -ceq '{name}'" in cmd
            assert "Remove-NetFirewallRule -InputObject $match" in cmd
            assert homesoc_literals(cmd) == {name}  # exactly this rule, no other

        assert undo_action.kind == "undo"
        assert undo_action.target == action.id
        assert undo_action.rule_names == action.rule_names
        reloaded = store.get_action(action.id)
        assert reloaded is not None and reloaded.undone is True
        assert store.list_actions(undone=False) == [store.get_action(undo_action.id)]

    elapsed = time.perf_counter() - started
    assert elapsed < MAX_RUNTIME_S, f"smoke test took {elapsed:.1f} s"
