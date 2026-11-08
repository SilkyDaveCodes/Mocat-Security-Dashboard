"""End-to-end test of inbound attack detection: portscan / bruteforce -> alert -> block IP -> undo.

Ticket #61 (the automated twin of the live run in ``docs/inbound-test.md``). The lab VM
(192.168.56.20) attacks the Windows VM (192.168.56.10) the way ``lab/traffic/portscan.py`` and
``lab/traffic/bruteforce.py`` do on the wire, and the flows go through the real path:

    inbound FlowEvents -> agent.main.build_detectors (real intel, beacon, flow_model)
    -> real Pipeline -> real Scorer (config.yaml, data/allowlist.txt) -> real firewall.block_ip
    -> real SQLite Store -> Alert; then the app's Undo buttons through the real API
    (POST /actions/{id}/undo, POST /undo-all) -> real firewall.undo / undo_all

Patched: only ``subprocess.run``. It is replaced by :class:`FakeWindowsFirewall`, which keeps a
rule table and applies the PowerShell commands HomeSOC sends (create, exact-name removal inside a
group, whole-group removal), so the tests check the resulting firewall state (what
``Get-NetFirewallRule -Group HomeSOC`` would list), not just that a call was made.

Injected through constructor seams:
    * one fake clock (ms) shared by the flow_model detector, the Scorer, intel and the Pipeline,
      advanced to each flow's end (no sleeping);
    * the flow model: ``models/flow.joblib`` is not in git, so a bundle in its exact format is
      trained here with the real ``models/train_flow.py`` functions (RandomForest,
      random_state=42) on synthetic per-flow NFStream statistics of the four lab classes. The
      replayed flows are drawn with another seed, so detection goes through real
      ``predict_proba`` on unseen rows;
    * intel: the real ``data/test_intel.txt`` (it lists 192.168.56.20, like the live lab), an
      empty feed cache and a no-op refresh spawner (no network).

Runs on any OS with no Npcap, admin rights, network or real PowerShell.
"""

from __future__ import annotations

import copy
import random
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent import api, config
from agent.detectors.beacon import BeaconDetector
from agent.detectors.flow_model import FlowModelDetector
from agent.detectors.intel import IntelDetector
from agent.events import Action, Alert, FlowEvent, Signal
from agent.main import CachedProcLookup, Pipeline, build_detectors
from agent.response import firewall
from agent.scoring import Scorer
from agent.store import Store
from lab.traffic import bruteforce as lab_bruteforce
from lab.traffic import portscan as lab_portscan
from models import train_flow

ATTACKER = "192.168.56.20"  # the lab VM (lab.traffic._guard.DEFAULT_LAB_TARGET)
PC_IP = "192.168.56.10"     # the Windows VM running the agent
T0_MS = 1_700_000_000_000
TRAIN_SEED = 42
REPLAY_SEED = 61
TRAIN_ROWS_PER_CLASS = 80
N_ESTIMATORS = 25
OTHER_RULE = "Core Networking - DNS (UDP-Out)"  # a Windows rule HomeSOC must never touch

PS_LITERAL = r"'((?:[^']|'')*)'"


# --- synthetic NFStream statistics -----------------------------------------------------------


def _raw(packets: int, out_packets: int, total_bytes: int, duration_ms: float, *,
         syn: int, rst: int = 0, fin: int = 0, psh: int = 0) -> dict[str, float]:
    """One flow's raw NFStream statistics (the keys ``capture.py`` copies to ``features``)."""
    in_packets = packets - out_packets
    out_bytes = total_bytes * out_packets // packets
    return {
        "bidirectional_duration_ms": duration_ms,
        "bidirectional_packets": packets,
        "bidirectional_bytes": total_bytes,
        "src2dst_duration_ms": duration_ms,
        "src2dst_packets": out_packets,
        "src2dst_bytes": out_bytes,
        "dst2src_duration_ms": duration_ms if in_packets else 0,
        "dst2src_packets": in_packets,
        "dst2src_bytes": total_bytes - out_bytes,
        "bidirectional_mean_ps": total_bytes / packets,
        "bidirectional_min_ps": 54,
        "bidirectional_max_ps": max(54, 2 * total_bytes / packets),
        "bidirectional_mean_piat_ms": duration_ms / max(packets - 1, 1),
        "bidirectional_syn_packets": syn,
        "bidirectional_rst_packets": rst,
        "bidirectional_fin_packets": fin,
        "bidirectional_psh_packets": psh,
        "bidirectional_ack_packets": max(packets - 1, 0),
    }


def flow_stats(label: str, rng: random.Random) -> dict[str, float]:
    """Per-flow statistics typical of each lab class (``lab/traffic/*.py`` against a host)."""
    j = rng.uniform(0.85, 1.15)
    if label == "portscan":    # connect to a closed port: SYN, RST back, nothing else
        return _raw(2, 1, int(114 * j), 1.0 * j, syn=1, rst=1)
    if label == "bruteforce":  # handshake, "LOGIN user:pw" line, rejection, close
        pk = rng.randint(9, 11)
        return _raw(pk, pk // 2 + 1, int(1_400 * j), 60.0 * j, syn=2, fin=2, psh=2)
    if label == "dos":         # a burst of small client packets, very fast
        pk = int(300 * j)
        return _raw(pk, pk - 5, int(18_000 * j), 200.0 * j, syn=50, rst=5)
    pk = int(40 * j)           # benign: a longer two-way exchange with real payloads
    return _raw(pk, pk // 2, int(30_000 * j), 4_000.0 * j, syn=2, fin=2, psh=10)


@pytest.fixture(scope="module")
def flow_bundle() -> dict[str, Any]:
    """A model bundle in the exact ``flow.joblib`` format, from the real training code."""
    rng = random.Random(TRAIN_SEED)
    flows = {label: [flow_stats(label, rng) for _ in range(TRAIN_ROWS_PER_CLASS)]
             for label in train_flow.CLASSES}
    X, y = train_flow.build_dataset(flows)
    model = train_flow.train(X, y, n_estimators=N_ESTIMATORS, random_state=TRAIN_SEED)
    bundle = train_flow.make_bundle(model, TRAIN_ROWS_PER_CLASS)
    assert set(bundle) >= {"model", "feature_names", "classes", "class_index"}
    return bundle


# --- what lab/traffic/*.py looks like to the agent ------------------------------------------


def _inbound(ts: int, src_port: int, dst_port: int, raw: dict[str, float]) -> FlowEvent:
    """An inbound flow as capture.py builds it: started by the lab VM, no local owner."""
    return FlowEvent(
        ts_ms=ts, end_ms=ts + int(raw["bidirectional_duration_ms"]) + 1,
        process="unknown", pid=-1,
        src_ip=ATTACKER, src_port=src_port, dst_ip=PC_IP, dst_port=dst_port, protocol=6,
        bytes_out=int(raw["src2dst_bytes"]), bytes_in=int(raw["dst2src_bytes"]),
        packets=int(raw["bidirectional_packets"]), direction="inbound", features=raw,
    )


def portscan_flows(start_ms: int, ports: tuple[int, ...] = lab_portscan.DEFAULT_PORTS
                   ) -> list[FlowEvent]:
    """``python -m lab.traffic.portscan --target 192.168.56.10``: one connect per port, in turn,
    each a new source port; a filtered port waits out the connect timeout."""
    rng = random.Random(REPLAY_SEED)
    step = int(lab_portscan.DEFAULT_TIMEOUT_S * 1000)
    return [_inbound(start_ms + i * step, 45_000 + i, port, flow_stats("portscan", rng))
            for i, port in enumerate(ports)]


def bruteforce_flows(start_ms: int, attempts: int = lab_bruteforce.DEFAULT_ATTEMPTS
                     ) -> list[FlowEvent]:
    """``python -m lab.traffic.bruteforce --target 192.168.56.10``: ``attempts`` short login
    connections in a row to one port (8080), each a new source port."""
    rng = random.Random(REPLAY_SEED + 1)
    return [_inbound(start_ms + i * 120, 46_000 + i, lab_bruteforce.DEFAULT_PORT,
                     flow_stats("bruteforce", rng))
            for i in range(attempts)]


# --- the only patch: subprocess.run -> a fake Windows Firewall ------------------------------


@dataclass
class Rule:
    name: str
    group: str
    direction: str
    remote_address: str | None


def _unquote(literal: str) -> str:
    return literal.replace("''", "'")


class FakeWindowsFirewall:
    """Stands in for ``subprocess.run``: applies HomeSOC's PowerShell firewall commands to an
    in-memory rule table. Anything it does not understand fails the test."""

    NEW = re.compile(
        rf"^New-NetFirewallRule -DisplayName {PS_LITERAL} -Group {PS_LITERAL} "
        rf"-Direction (Inbound|Outbound) -RemoteAddress {PS_LITERAL} -Action Block "
        r"-ErrorAction Stop \| Out-Null$"
    )
    GROUP = re.compile(rf"Get-NetFirewallRule -Group {PS_LITERAL} -ErrorAction Stop")
    BY_NAME = re.compile(rf"Where-Object \{{ \$_\.DisplayName -ceq {PS_LITERAL} \}}")

    def __init__(self) -> None:
        self.rules: dict[str, Rule] = {
            OTHER_RULE: Rule(OTHER_RULE, "Core Networking", "Outbound", None),
        }
        self.commands: list[str] = []

    def __call__(self, args: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        assert tuple(args[:-1]) == firewall.POWERSHELL_ARGV, f"unexpected subprocess {args!r}"
        cmd = args[-1]
        self.commands.append(cmd)
        if (m := self.NEW.match(cmd)) is not None:
            name, group, direction, addr = (_unquote(m[1]), _unquote(m[2]), m[3], _unquote(m[4]))
            assert name not in self.rules, f"duplicate rule name {name!r}"
            self.rules[name] = Rule(name, group, direction, addr)
        elif (g := self.GROUP.search(cmd)) is not None:
            group = _unquote(g[1])
            in_group = [r for r in self.rules.values() if r.group == group]
            if in_group:  # empty group = ObjectNotFound = exit 0, nothing removed
                if (n := self.BY_NAME.search(cmd)) is not None:
                    doomed = [r for r in in_group if r.name == _unquote(n[1])]
                else:
                    assert "$match = $rules;" in cmd, f"unknown removal script: {cmd}"
                    doomed = in_group
                for rule in doomed:
                    del self.rules[rule.name]
        else:
            pytest.fail(f"unexpected PowerShell command: {cmd}")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    def group(self, group: str = firewall.RULE_GROUP) -> dict[str, Rule]:
        """What ``Get-NetFirewallRule -Group <group>`` would list."""
        return {name: r for name, r in self.rules.items() if r.group == group}


# --- harness ---------------------------------------------------------------------------------


@dataclass
class Harness:
    cfg: dict[str, Any]
    pipeline: Pipeline
    store: Store
    fw: FakeWindowsFirewall
    published: list[Any]
    now_ms: list[int]

    def replay(self, flows: list[FlowEvent]) -> None:
        for flow in flows:
            self.now_ms[0] = flow.end_ms  # NFStream hands a flow over once it ends
            self.pipeline.handle(flow)

    def wait_s(self, seconds: float) -> None:
        self.now_ms[0] += int(seconds * 1000)

    def flow_model_alerts(self) -> list[Alert]:
        return [a for a in self.store.list_alerts()
                if any(s.detector == "flow_model" for s in a.signals)]

    def api_client(self) -> TestClient:
        tracker = api.FlowTracker.from_config(self.cfg, clock=lambda: self.now_ms[0] / 1000)
        app = api.create_app(self.store, self.pipeline.scorer, tracker,
                             allowlist=api.allowlist_from_config(self.cfg),
                             publish=self.published.append)  # default (real) firewall functions
        return TestClient(app)


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def make_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cfg: dict[str, Any],
                 flow_bundle: dict[str, Any]):
    fw = FakeWindowsFirewall()
    monkeypatch.setattr(subprocess, "run", fw)  # the only patch
    stores: list[Store] = []

    def make(mode: str) -> Harness:
        cfg["mode"] = mode
        now_ms = [T0_MS]

        def clock_ms() -> int:
            return now_ms[0]

        cache = tmp_path / "cache"
        cache.mkdir(exist_ok=True)
        factories = (
            ("intel", lambda c, s: IntelDetector(
                c, cache_dir=cache,
                test_intel_path=config.REPO_ROOT / c["paths"]["test_intel"],
                clock=lambda: now_ms[0] / 1000, spawn=lambda task: None).process),
            ("beacon", lambda c, s: BeaconDetector(c).process),
            ("flow_model", lambda c, s: FlowModelDetector(c, model=flow_bundle,
                                                          clock=clock_ms).process),
        )
        store = Store(tmp_path / f"homesoc-{mode}.db")
        stores.append(store)
        published: list[Any] = []

        def no_lookup(pid: int) -> Any:
            pytest.fail(f"process lookup for PID {pid}: inbound flows have no local owner")

        pipeline = Pipeline(
            build_detectors(cfg, factories, store=store),
            Scorer(cfg, clock=clock_ms),  # real config.yaml + data/allowlist.txt
            store,
            published.append,             # default firewall functions: the real firewall.py
            proc_lookup=CachedProcLookup(30.0, lookup=no_lookup, clock=lambda: now_ms[0] / 1000),
            clock=lambda: now_ms[0] / 1000,
        )
        assert pipeline.scorer.mode == mode
        return Harness(cfg, pipeline, store, fw, published, now_ms)

    yield make
    for store in stores:
        store.close()


def _flow_model_signal(alert: Alert) -> Signal:
    return next(s for s in alert.signals if s.detector == "flow_model")


def _assert_blocked(h: Harness, action: Action, ip: str) -> None:
    """``action`` is a stored block_ip whose two rules exist in group HomeSOC, out and in."""
    assert action.kind == "block_ip" and action.target == ip and not action.undone
    out_name, in_name = action.rule_names
    assert out_name.startswith(f"HomeSOC block {ip} out #")
    assert in_name.startswith(f"HomeSOC block {ip} in #")
    rules = h.fw.group()
    assert {out_name, in_name} <= set(rules)
    assert rules[out_name].direction == "Outbound" and rules[in_name].direction == "Inbound"
    assert rules[out_name].remote_address == rules[in_name].remote_address == ip
    for name in action.rule_names:
        cmd = next(c for c in h.fw.commands if f"-DisplayName '{name}'" in c)
        assert cmd.startswith("New-NetFirewallRule ")
        assert "-Group 'HomeSOC'" in cmd and f"-RemoteAddress '{ip}'" in cmd
        assert "-Action Block" in cmd


def _attack_window_s(cfg: dict[str, Any]) -> float:
    """Long enough for every flow_model and scoring window of an earlier run to empty."""
    return max(cfg["detectors"]["flow_model"]["window_s"], cfg["detectors"]["flow_model"][
        "repeat_s"], cfg["scoring"]["window_s"]) + 1


# --- criterion 1: portscan -> T1046 alert + IP block ----------------------------------------


def test_portscan_raises_t1046_alert_and_blocks_the_attacker(make_harness) -> None:
    h = make_harness("auto")
    h.replay(portscan_flows(T0_MS))

    alerts = h.flow_model_alerts()
    assert len(alerts) == 1, "one alert per attack episode"
    alert = alerts[0]
    sig = _flow_model_signal(alert)
    assert sig.mitre == "T1046" and sig.target == ATTACKER
    assert sig.score >= h.cfg["detectors"]["flow_model"]["probability_threshold"]
    assert alert.severity in {"high", "critical"}
    assert alert.title == f"Your PC is being attacked from {ATTACKER}"
    assert "port scan" in alert.what_happened and ATTACKER in alert.what_happened
    assert "T1046" in alert.what_happened
    assert "behaving like malware" not in alert.what_happened  # the victim is not malware
    assert f"We blocked all traffic to and from {ATTACKER}" in alert.what_we_did

    actions = h.store.list_actions()
    assert [a.kind for a in actions] == ["block_ip"], "nothing quarantined, one block"
    action = actions[0]
    assert alert.action_ids == [action.id]
    _assert_blocked(h, action, ATTACKER)
    assert len(h.fw.group()) == 2
    assert OTHER_RULE in h.fw.rules

    # The UI got the Action before the Alert that refers to it.
    ids = [e.id for e in h.published if isinstance(e, Action | Alert)]
    assert ids.index(action.id) < ids.index(alert.id)


def test_portscan_signal_fires_once_min_flows_is_reached(make_harness) -> None:
    h = make_harness("auto")
    min_flows = h.cfg["detectors"]["flow_model"]["min_flows"]
    flows = portscan_flows(T0_MS)
    h.replay(flows[:min_flows])
    assert len(h.flow_model_alerts()) == 1
    assert f"{min_flows} flows" in " ".join(_flow_model_signal(h.flow_model_alerts()[0]).reasons)
    h.replay(flows[min_flows:])  # the rest of the scan adds no alert and no second block
    assert len(h.flow_model_alerts()) == 1
    assert len(h.store.list_actions()) == 1


def test_intel_hit_on_inbound_lab_flows_never_quarantines(make_harness) -> None:
    """192.168.56.20 is in data/test_intel.txt, so intel flags the inbound flows too (as in the
    live lab); with no local process behind them that is an alert only, never a quarantine."""
    h = make_harness("auto")
    h.replay(portscan_flows(T0_MS))
    intel = [a for a in h.store.list_alerts() if {s.detector for s in a.signals} == {"intel"}]
    assert intel and all(a.action_ids == [] for a in intel)
    assert all(a.kind != "quarantine_app" for a in h.store.list_actions())


# --- criterion 2: bruteforce -> T1110 (after undoing the portscan block) --------------------


def test_bruteforce_after_undo_raises_t1110_and_blocks_again(make_harness) -> None:
    h = make_harness("auto")
    client = h.api_client()
    h.replay(portscan_flows(T0_MS))
    (scan_block,) = h.store.list_actions()

    # Step 4: undo the portscan block first (the app's Undo button).
    assert client.post(f"/actions/{scan_block.id}/undo").status_code == 200
    assert h.fw.group() == {}

    h.wait_s(_attack_window_s(h.cfg))
    h.replay(bruteforce_flows(h.now_ms[0]))

    brute = [a for a in h.flow_model_alerts() if _flow_model_signal(a).mitre == "T1110"]
    assert len(brute) == 1
    alert = brute[0]
    sig = _flow_model_signal(alert)
    assert sig.target == ATTACKER
    assert "brute-force" in alert.what_happened and ATTACKER in alert.what_happened
    assert {s.mitre for s in alert.signals} == {"T1110"}  # the old scan is out of the window

    blocks = [a for a in h.store.list_actions() if a.kind == "block_ip"]
    assert len(blocks) == 2
    fresh = next(a for a in blocks if a.id != scan_block.id)
    assert alert.action_ids == [fresh.id]
    assert set(fresh.rule_names).isdisjoint(scan_block.rule_names)
    _assert_blocked(h, fresh, ATTACKER)
    assert set(h.fw.group()) == set(fresh.rule_names)


# --- criterion 3: undo removes the rules -----------------------------------------------------


def test_undo_through_the_api_removes_exactly_the_stored_rules(make_harness) -> None:
    h = make_harness("auto")
    client = h.api_client()
    h.replay(portscan_flows(T0_MS))
    (action,) = h.store.list_actions()
    h.fw.commands.clear()

    response = client.post(f"/actions/{action.id}/undo")
    assert response.status_code == 200

    # Get-NetFirewallRule -Group HomeSOC now lists nothing; the Windows rule is untouched.
    assert h.fw.group() == {}
    assert OTHER_RULE in h.fw.rules
    assert len(h.fw.commands) == len(action.rule_names)
    for name, cmd in zip(action.rule_names, h.fw.commands, strict=True):
        assert "New-NetFirewallRule" not in cmd
        assert "Get-NetFirewallRule -Group 'HomeSOC'" in cmd
        assert f"$_.DisplayName -ceq '{name}'" in cmd
        assert {m for m in re.findall(PS_LITERAL, cmd) if m.startswith("HomeSOC ")} == {name}

    stored = h.store.get_action(action.id)
    assert stored is not None and stored.undone is True
    undo = h.store.get_action(response.json()["undo"]["id"])
    assert undo is not None and undo.kind == "undo"
    assert undo.target == action.id and undo.rule_names == action.rule_names
    assert client.get("/status").json()["active_actions"] == 0
    assert client.post(f"/actions/{action.id}/undo").status_code == 409  # not twice


def test_undo_all_removes_every_homesoc_rule_and_nothing_else(make_harness) -> None:
    h = make_harness("auto")
    client = h.api_client()
    h.replay(portscan_flows(T0_MS))
    h.wait_s(_attack_window_s(h.cfg))
    h.replay(bruteforce_flows(h.now_ms[0]))  # second block without undoing the first
    blocks = h.store.list_actions(undone=False)
    assert [a.kind for a in blocks] == ["block_ip", "block_ip"]
    assert len(h.fw.group()) == 4
    h.fw.commands.clear()

    response = client.post("/undo-all")
    assert response.status_code == 200
    assert response.json()["undone"] == 2

    assert h.fw.group() == {}
    assert OTHER_RULE in h.fw.rules  # undo-all only touches group HomeSOC
    (cmd,) = h.fw.commands
    assert "Get-NetFirewallRule -Group 'HomeSOC'" in cmd
    assert set(re.findall(PS_LITERAL, cmd)) == {"HomeSOC", "ObjectNotFound"}
    assert all(h.store.get_action(a.id).undone for a in blocks)  # type: ignore[union-attr]
    remaining = h.store.list_actions(undone=False)
    assert [a.kind for a in remaining] == ["undo"]
    assert client.get("/status").json()["active_actions"] == 0


# --- step-6 note: below min_flows nothing fires; notify mode alerts only ---------------------


def test_fewer_than_min_flows_gives_no_signal_alert_or_block(make_harness) -> None:
    h = make_harness("auto")
    min_flows = h.cfg["detectors"]["flow_model"]["min_flows"]
    flows = portscan_flows(T0_MS)[: min_flows - 1]
    signals = []
    for flow in flows:
        h.now_ms[0] = flow.end_ms
        signals += h.pipeline.detect(flow)
    assert [s for s in signals if s.detector == "flow_model"] == []

    h2 = make_harness("auto")
    h2.replay(flows)
    assert h2.flow_model_alerts() == []
    assert h2.store.list_actions() == []
    assert h2.fw.group() == {}
    assert all("New-NetFirewallRule" not in c for c in h2.fw.commands)


def test_min_flows_window_is_per_source_time(make_harness) -> None:
    """Flows spread wider than window_s never add up to min_flows."""
    h = make_harness("auto")
    fm = h.cfg["detectors"]["flow_model"]
    step_ms = int(fm["window_s"] * 1000) // (fm["min_flows"] - 1) + 1000
    flows = portscan_flows(T0_MS)[: fm["min_flows"] * 2]
    for i, flow in enumerate(flows):
        flow.ts_ms = T0_MS + i * step_ms
        flow.end_ms = flow.ts_ms + 2
    h.replay(flows)
    assert h.flow_model_alerts() == []
    assert h.store.list_actions() == []


def test_notify_mode_alerts_on_the_portscan_but_blocks_nothing(make_harness) -> None:
    h = make_harness("notify")
    h.replay(portscan_flows(T0_MS))

    alerts = h.flow_model_alerts()
    assert len(alerts) == 1
    alert = alerts[0]
    assert _flow_model_signal(alert).mitre == "T1046"
    assert _flow_model_signal(alert).target == ATTACKER
    assert alert.action_ids == []
    assert "Notify mode" in alert.what_we_did
    assert "block the attacking address" in alert.what_you_should_do
    assert h.store.list_actions() == []
    assert h.fw.commands == [] and h.fw.group() == {}
