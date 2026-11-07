# CLAUDE.md — HomeSOC

> Project memory for Claude Code. Read this whole file before writing code.
> Hackathon project: 36 hours, 2 people. Keep things simple, working, and demo-able.

---

## 1. What we are building

**HomeSOC** is a personal network-security app for home Windows PCs. You install it like a VPN, flip it on,
and it:

1. **Watches** every network connection the PC makes and tags it with the **app** that made it.
2. **Detects** malware-like behavior with AI models and rules (DGA domains, beaconing, known-bad IPs,
   unusual uploads, inbound scans/brute force).
3. **Contains** the threat by adding Windows Firewall rules (block an IP, or "quarantine" an app).
   Every action can be undone.
4. **Explains** every alert in plain English: *What happened / What we did / What you should do*.

Everything runs locally on the PC. The only outbound request HomeSOC makes is a blocklist refresh.

**Target platform:** Windows 10/11 x64, Python 3.12. The dev/test environment is a Windows 11 VM.

---

## 2. Team and ownership

| Owner | Role | Owns |
|---|---|---|
| **CE** | Computer Engineering | `agent/capture.py`, `agent/procinfo.py`, `agent/bus.py`, `agent/api.py`, `agent/store.py`, `agent/response/`, `agent/detectors/flow_model.py`, `app/`, `installer/` |
| **CS** | Cybersecurity | `agent/detectors/intel.py`, `dga.py`, `beacon.py`, `anomaly.py`, `agent/scoring.py`, `agent/alerts_text.py`, `models/train_dga.py`, `lab/` |
| Both | — | `agent/events.py` (the event schema), `config.yaml`, `tests/` |

When asked to work on a file, stay inside that owner's area unless told otherwise. Never change
`agent/events.py` without saying so clearly in the response, because both people depend on it.

---

## 3. Architecture

```
Apps on PC ⇄ Internet
     │ (Npcap copies packets)
     ▼
agent/capture.py      NFStream live capture → FlowEvent (with process name/PID, DNS/TLS hostname)
     │
     ▼
agent/detectors/*     intel, dga, beacon, anomaly, flow_model → Signal(score 0..1, reasons)
     │
     ▼
agent/scoring.py      combine signals per process (+ context: unsigned / Downloads / Temp) → risk
     │
     ├─► agent/response/firewall.py   block_ip / quarantine_app / undo  (PowerShell, group "HomeSOC")
     ├─► agent/store.py               SQLite: alerts, actions, baselines
     └─► agent/bus.py → agent/api.py  FastAPI WebSocket on 127.0.0.1:8765
                                          │
                                          ▼
                                   app/ (pywebview window + pystray tray + toasts)
```

- The **agent** runs elevated (admin): it needs Npcap capture and firewall changes.
- The **app** runs as a normal user and only talks to `127.0.0.1:8765`.
- The API must **never** bind to `0.0.0.0`.

---

## 4. Repo layout

```
homesoc/
├── CLAUDE.md
├── README.md
├── config.yaml                 # interface name, thresholds, mode, allowlist
├── requirements.txt
├── agent/
│   ├── main.py                 # starts capture → detectors → scoring → response → api
│   ├── events.py               # dataclasses: FlowEvent, Signal, Alert, Action  (SHARED CONTRACT)
│   ├── capture.py              # NFStream live capture → FlowEvent
│   ├── procinfo.py             # exe path, signed?, in Downloads/Temp?, kill
│   ├── bus.py                  # asyncio queue fan-out
│   ├── api.py                  # FastAPI: REST + /ws
│   ├── store.py                # SQLite
│   ├── scoring.py              # risk combination + response policy
│   ├── alerts_text.py          # plain-English templates + MITRE IDs
│   ├── detectors/
│   │   ├── intel.py
│   │   ├── dga.py
│   │   ├── dga_features.py     # shared by training and live
│   │   ├── beacon.py
│   │   ├── anomaly.py
│   │   └── flow_model.py       # inbound attack classifier (from lab plan)
│   └── response/
│       └── firewall.py
├── app/
│   ├── main.py                 # pywebview window + pystray tray
│   ├── notify.py               # Windows toast notifications
│   └── ui/                     # index.html, app.js, styles.css (Home, Apps, Alerts, Settings)
├── models/
│   ├── train_dga.py
│   ├── train_flow.py           # from lab plan
│   ├── dga.joblib
│   └── flow.joblib
├── data/
│   ├── allowlist.txt           # exe names never auto-quarantined
│   ├── test_intel.txt          # lab IPs that act as "known bad" for demos
│   └── cache/                  # downloaded blocklists
├── lab/
│   ├── c2_server.py            # fake C2 on the lab Ubuntu VM
│   ├── dnsmasq.conf            # answers all lookups inside the lab
│   └── fake_malware/
│       └── freegamecheats.py   # HARMLESS demo "malware" (see §9)
├── installer/
│   ├── homesoc.spec            # PyInstaller
│   └── homesoc.iss             # Inno Setup
└── tests/
```

---

## 5. The shared contract: `agent/events.py`

All modules talk through these types. The WebSocket sends them as JSON (`asdict()` + `"type"`).

```python
from dataclasses import dataclass, field
from typing import Literal, Optional

@dataclass
class FlowEvent:
    type: Literal["flow"] = "flow"
    ts_ms: int = 0                    # bidirectional_first_seen_ms
    end_ms: int = 0                   # bidirectional_last_seen_ms
    process: str = "unknown"          # e.g. "chrome.exe"
    pid: int = -1
    exe_path: Optional[str] = None
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: int = 0
    hostname: Optional[str] = None    # NFStream requested_server_name (DNS query / TLS SNI)
    app_proto: Optional[str] = None   # NFStream application_name
    bytes_out: int = 0                # src2dst_bytes
    bytes_in: int = 0                 # dst2src_bytes
    packets: int = 0
    direction: Literal["outbound", "inbound"] = "outbound"
    features: dict = field(default_factory=dict)   # raw NFStream stats for flow_model

@dataclass
class Signal:
    type: Literal["signal"] = "signal"
    detector: Literal["intel", "dga", "beacon", "anomaly", "flow_model"] = "intel"
    process: str = "unknown"
    pid: int = -1
    target: str = ""                  # IP or domain the signal is about
    score: float = 0.0                # 0..1
    reasons: list[str] = field(default_factory=list)   # short, human-readable
    mitre: Optional[str] = None       # e.g. "T1071.001"
    ts_ms: int = 0

@dataclass
class Alert:
    type: Literal["alert"] = "alert"
    id: str = ""
    ts_ms: int = 0
    severity: Literal["low", "medium", "high", "critical"] = "low"
    process: str = "unknown"
    exe_path: Optional[str] = None
    risk: float = 0.0
    title: str = ""
    what_happened: str = ""
    what_we_did: str = ""
    what_you_should_do: str = ""
    signals: list[Signal] = field(default_factory=list)
    action_ids: list[str] = field(default_factory=list)

@dataclass
class Action:
    type: Literal["action"] = "action"
    id: str = ""
    ts_ms: int = 0
    kind: Literal["block_ip", "quarantine_app", "kill_process", "undo"] = "block_ip"
    target: str = ""                  # IP or exe path
    rule_names: list[str] = field(default_factory=list)
    undone: bool = False
```

---

## 6. Module specs

### 6.1 `agent/capture.py` (CE)
- Use `nfstream.NFStreamer` on the interface from `config.yaml` (the name shown in Wireshark's
  interface list).
- Settings: `statistical_analysis=True`, `system_visibility_mode=1` (process name/PID),
  `idle_timeout=10`, `active_timeout=30`. **Keep `n_dissections` at its default (20)**, because
  `requested_server_name` (the DNS/TLS hostname) needs it.
- Map each NFlow → `FlowEvent`. `direction="outbound"` if `src_ip` is **one of this PC's own
  addresses** (from `psutil.net_if_addrs()`, re-read every `capture.local_ips_refresh_s`) or
  loopback; otherwise `"inbound"`. "Local" means *this host*, not "any private IP": a flow started
  by another LAN/lab machine (e.g. the lab attacker `192.168.56.20`) is inbound, so `flow_model`
  sees it.
- Fallback when `system_process_name` is empty: use `psutil.net_connections(kind="inet")` to map
  the local port → PID.
- Put events on the bus. Never block the capture loop on slow work.

### 6.2 `agent/procinfo.py` (CE)
- `info(pid) -> ProcInfo` (frozen dataclass; `.as_dict()` gives the dict): `pid`, `name`, `exe_path`,
  `in_risky_dir` (Downloads, `%TEMP%`, `AppData\Local\Temp`), `signed` (via PowerShell
  `Get-AuthenticodeSignature`, cached by path).
- When the exe path can't be read (process gone / access denied), `exe_path`, `in_risky_dir` and
  `signed` are `None`, meaning **unknown, not unsigned**. Scoring (§6.4) must not apply the
  unsigned/risky-dir boost for `None`. `info()` never raises for a vanished process.
- `kill(pid)`: only called after the user confirms in the UI.

### 6.3 Detectors (CS, except `flow_model`)
Each detector exposes `def process(event: FlowEvent) -> list[Signal]`.

**`intel.py`**
- Source: abuse.ch Feodo Tracker *recommended* list
  `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` (skip `#` lines).
- Refresh hourly into `data/cache/`. If offline, use the cache. Also load `data/test_intel.txt`.
- Hit → `Signal(score=1.0, detector="intel", mitre="T1071")`.

**`dga.py`** + **`dga_features.py`**
- Score `event.hostname` from DNS flows (`dst_port == 53`, or `app_proto` contains "DNS").
- Features (shared with training): length of the registered-domain label, Shannon entropy, vowel
  ratio, digit ratio, longest consonant run, count of unique characters, bigram-rarity score.
- Skip: hostnames on the Tranco top-100k list (cached), `*.local`, `*.arpa`, and allowlisted domains.
- `model.predict_proba ≥ 0.8` → `Signal(score=p, mitre="T1568.002")`.
- Raise the score if the same process makes ≥ 5 DGA-looking lookups in 60 s.

**`beacon.py`**
- Per `(process, dst_ip, dst_port)`, keep the last 20 flow start times (`ts_ms`).
- With ≥ 6 starts: compute intervals; if the mean is 2–600 s and the coefficient of variation is
  < 0.1 → beacon. `score = 0.9` (0.95 if ≥ 12 starts). `mitre="T1071.001"`.
- Reason text example: `"checks in with 192.168.56.20 every 5.0 s (±0.2 s)"`.

**`anomaly.py`** (CS + CE)
- Calibration period (configurable; 10 min for the demo) learns per-process 60-second windows:
  `bytes_out`, `flows`, `unique_dst_ips`, `new_countries` (optional).
- After calibration: an `IsolationForest` per process with ≥ 30 windows; a brand-new process uses a
  global model. An anomalous window with `bytes_out > 10 MB` → `Signal(score 0.6–0.9, mitre="T1041")`.
- Implementation notes (`AnomalyDetector(cfg, store, clock)`): windows are cut on 60 s boundaries
  of the injected clock (processing time, not `FlowEvent.ts_ms`), outbound flows only. The open
  window is scored as flows arrive, once past 10 MB; one Signal per process per window. Features
  are `log1p` of the counters; `random_state=42`. Baselines are saved per process through
  `store.save_baseline` as `{"version", "calibration_end_ms", "windows": [[bytes_out, flows,
  unique_dst_ips], ...]}`; on restart they are reloaded, the stored calibration end is kept and
  models are refitted from them. After calibration, normal (unflagged, ≤ 10 MB) windows keep being
  learned (`learn_after_calibration`), so a process can reach 30 windows after the 10-min demo
  calibration. The global model needs `global_min_windows` pooled windows, else no Signal.

**`flow_model.py`** (CE)
- Port the lab plan's `features.py` + `WindowTracker` + `flow.joblib` (labels: benign, portscan,
  bruteforce, dos). Only applies to `direction == "inbound"`.
- Non-benign with probability ≥ 0.85 → `Signal(target=src_ip, mitre="T1046"/"T1110"/"T1498")`.

### 6.4 `agent/scoring.py` (CS)
- Keep a 60-second window of signals per process.
- `risk = 1 - Π(1 - s.score)` over distinct detectors.
- Context boost: × 1.2 if the exe is unsigned **or** in a risky directory (cap at 1.0).
- Policy (mode from `config.yaml`: `off | notify | auto`):
  - `risk ≥ 0.5` → Alert (severity: medium ≥ 0.5, high ≥ 0.75, critical ≥ 0.9).
  - `auto` mode and (`intel` hit **or** (`risk ≥ 0.85` **and** ≥ 2 detectors)) → quarantine the
    app (or block the IP for inbound `flow_model` signals).
  - Never quarantine anything in `data/allowlist.txt` (browsers, Windows Update, Steam, Discord,
    Spotify, Defender…). Alert only.
  - Alerts are raised in every mode (`off` and `notify` included); only `auto` acts.
- Implementation notes (`Scorer.add(signal, procinfo) -> Decision`):
  - Distinct detectors: each detector counts once, with its highest score in the window.
  - The window uses the clock time a signal was added, not `Signal.ts_ms`.
  - Unknown exe path (`ProcInfo.exe_path is None`) → alert only, never quarantine (§9.6).
  - Inbound `flow_model` signals are windowed per attacker IP (`signal.target`), get no context
    boost, and in `auto` with risk ≥ `scoring.auto_block_ip.risk` (0.85) request `block_ip` on
    that IP (never loopback/unspecified). The exe allowlist doesn't apply: no app is touched.
  - Repeat suppression: until a key's window empties, a new alert is raised only when severity
    rises, a new detector joins, or a new action is requested; each (kind, target) action is
    requested once.
  - Scoring returns a request; the pipeline carries it out, then `finalize_alert(decision, actions)`
    fills `action_ids` and rewrites the text with what really happened.
- Build the text with `alerts_text.py`.

### 6.5 `agent/response/firewall.py` (CE)
Run PowerShell with `subprocess.run(["powershell", "-NoProfile", "-Command", cmd], check=False,
capture_output=True)`. Rule names start with `HomeSOC` and every rule is in group `HomeSOC`.

Every literal (rule name, group, IP, exe path) is a PowerShell **single-quoted** string built with
`agent.procinfo.ps_quote` (`'` doubled; `$`, backticks, `"`, `;` stay literal). `<tag>` is `#` + the
first 8 hex chars of the new Action's id, so every action's rule names are unique (two `update.exe`
in different folders, or the same IP blocked twice, never share names). One PowerShell call per rule.

```powershell
# block_ip(ip)          ip is validated + canonicalised with ipaddress (loopback/unspecified refused)
New-NetFirewallRule -DisplayName 'HomeSOC block <ip> out <tag>' -Group 'HomeSOC' -Direction Outbound -RemoteAddress '<ip>' -Action Block -ErrorAction Stop | Out-Null
New-NetFirewallRule -DisplayName 'HomeSOC block <ip> in <tag>'  -Group 'HomeSOC' -Direction Inbound  -RemoteAddress '<ip>' -Action Block -ErrorAction Stop | Out-Null

# quarantine_app(exe_path)    exe_path must be an absolute Windows path, no NUL/CR/LF
New-NetFirewallRule -DisplayName 'HomeSOC quarantine <exe> out <tag>' -Group 'HomeSOC' -Direction Outbound -Program '<exe_path>' -Action Block -ErrorAction Stop | Out-Null
New-NetFirewallRule -DisplayName 'HomeSOC quarantine <exe> in <tag>'  -Group 'HomeSOC' -Direction Inbound  -Program '<exe_path>' -Action Block -ErrorAction Stop | Out-Null

# undo(action)  one call per stored rule name. Exact match (-ceq, no wildcards: -DisplayName would
# treat [ ] * ? as a pattern), only inside group HomeSOC. An empty group (ObjectNotFound) = nothing
# to remove = exit 0; any other error = exit 1. Remove-NetFirewallRule never runs on empty input.
try { $rules = @(Get-NetFirewallRule -Group 'HomeSOC' -ErrorAction Stop) } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { exit 0 }; [Console]::Error.WriteLine($_); exit 1 }; $match = @($rules | Where-Object { $_.DisplayName -ceq '<rule name>' }); if ($match.Count -gt 0) { try { Remove-NetFirewallRule -InputObject $match -ErrorAction Stop } catch { [Console]::Error.WriteLine($_); exit 1 } }

# undo_all()    same error handling, every rule in group HomeSOC
try { $rules = @(Get-NetFirewallRule -Group 'HomeSOC' -ErrorAction Stop) } catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { exit 0 }; [Console]::Error.WriteLine($_); exit 1 }; $match = $rules; if ($match.Count -gt 0) { try { Remove-NetFirewallRule -InputObject $match -ErrorAction Stop } catch { [Console]::Error.WriteLine($_); exit 1 } }
```
- Any non-zero exit / timeout / missing PowerShell is logged and raised as `FirewallError`, never
  treated as success. A failed second rule rolls back the first. A failed undo leaves
  `action.undone = False`.
- Escape/quote paths safely and never pass unchecked user text into PowerShell.
- Return an `Action` and save it in the store. Undo must work after an agent restart (rule names
  are stored).

### 6.5a `agent/store.py` (CE)
- SQLite at `store.path` in `config.yaml` (default `data/homesoc.db`; relative to the repo root).
  `Store(path)` (context manager / `close()`), one lock-guarded connection, safe across threads.
- Tables `alerts` (whole Alert + nested Signals as JSON), `actions` (every field, `rule_names` as
  JSON), `baselines` (one JSON-serialisable dict per process).
- `save_alert/get_alert/list_alerts(limit)`, `save_action/get_action/list_actions(limit, undone)`,
  `mark_undone(id) -> bool` (False for an unknown id), `mark_all_undone()`,
  `save_baseline(process, dict)/load_baseline(process)/load_baselines()`. Saves are upserts;
  lists are newest first (`ts_ms` desc, then latest inserted).

### 6.5b `agent/main.py` — the pipeline (CE)
- `Pipeline(detectors, scorer, store, publish, firewall_fns=, proc_lookup=)`: every dependency is
  injected so tests run without NFStream/PowerShell. `handle(event)` runs every detector (one that
  raises is logged and skipped), feeds each Signal + `ProcInfo` to `Scorer.add`, carries out the
  requested action (`FirewallError`/`ValueError` → logged, no Action), saves + publishes the
  Action, then `finalize_alert` → saves + publishes the Alert. Never raises.
- Capture runs in a daemon thread (`publish_threadsafe`); the pipeline reads its own bus
  subscription and runs `handle` in a worker thread, one event at a time, so capture never waits.
- `ProcInfo` is cached per PID for `pipeline.procinfo_cache_ttl_s`; a PID whose process name no
  longer matches the signal's is treated as unknown (alert only, §9.6). The scorer is pruned every
  `pipeline.prune_interval_s`.
- Adding a detector = one `(name, factory)` entry in `DETECTOR_FACTORIES`; one that fails to start
  is logged and left out.

### 6.6 `agent/api.py` (CE)
- `GET /status`, `GET /apps` (per-process bytes and destinations, last 10 min), `GET /alerts`,
  `GET /actions?limit=N&undone=B` (stored actions, newest first; the tray reads it),
  `POST /actions/{id}/undo`, `POST /undo-all`, `POST /mode` (`off|notify|auto`),
  `POST /alerts/{id}/quarantine`, `GET /alerts/{id}/evidence` (writes a pcap; see §6.8).
- `WS /ws`: pushes every Alert, Action, and a throttled FlowEvent summary (≤ 5 per second).
- Bind `127.0.0.1:8765` only.
- Implementation notes (`create_app(store, mode_holder, tracker, firewall_fns=, allowlist=,
  publish=, clock=)`, every dependency injected; `main.py` starts it in a daemon thread via
  `api.start_in_thread`, and `server_settings` refuses any host but `127.0.0.1`):
  - `POST /mode` body `{"mode": "off|notify|auto"}` (else 422) sets the pipeline Scorer's mode
    (takes effect on the next signal; not persisted, a restart uses `config.yaml`).
  - `GET /apps` counts flows seen in the last `api.apps_window_s` (600 s), fed from the bus;
    `GET /alerts?limit=N` (default 100) → `{"alerts": [...]}`.
  - Errors: 404 unknown id; 409 action already undone / an `undo` record, alert with no exe
    path, allowlisted app, or app already quarantined; 400 unsafe exe path; 502 the firewall
    call failed (nothing is marked undone / no Action saved).
  - Undo and undo-all save the returned `kind="undo"` Action; manual quarantine saves the Action,
    appends its id to the alert's `action_ids` and rewrites "What we did".
  - `WS /ws` (`create_app(..., bus=, ws_flow_rate_per_s=)`; `main.py` passes the agent's bus):
    one bus subscription per connection, made before the handshake is accepted and closed on
    disconnect. Alerts and Actions are sent whole (`to_json`) and never throttled; FlowEvents
    become a `{"type": "flow", ts_ms, process, pid, src_ip, dst_ip, dst_port, hostname,
    app_proto, bytes_out, bytes_in, direction}` summary, at most `api.ws_flow_rate_limit_per_s`
    (5) per sliding 1 s window per client (injected clock); Signals are not sent. The bus lives
    on the agent loop and uvicorn on its own, so reads cross loops via `run_coroutine_threadsafe`.
  - CORS: the app's window is served from `http://127.0.0.1:<port>/` (pywebview `http_server`),
    a different origin, so responses carry CORS headers for loopback `http` origins only
    (`CORS_ORIGIN_REGEX`: `127.0.0.1` / `localhost`, any port; never `null` or a remote origin).

### 6.7 `app/` (CE)
- `pywebview` window loading `app/ui/index.html`; screens Home, Apps, Alerts, Settings.
  Reuse the look of the MiniSOC dashboard prototype.
- `pystray` tray icon: green (ok), yellow (alerts), red (active high/critical); menu:
  Open, Mode ▸, Undo all, Quit.
- Toast notification for every high/critical alert.
- Implementation notes: `app/main.py` holds `API_BASE_URL = "http://127.0.0.1:8765"` (and
  `validate_api_url`, which refuses any other host); `app/ui/app.js` holds the same `API_BASE`
  (a test keeps them equal and fails on any other host in the UI). `webview` is imported lazily;
  `run(on_started=)` is the hook for the tray/toasts. `index.html` sets a CSP that only allows
  `self` and the agent; no external resources. JS tests: `tests/js/test_app.mjs` (run by
  `tests/test_app_ui.py` through `node`; skipped if `node` is missing).
- Tray (`app/tray.py`, started by `app.main.main()` through `run(on_started=start_tray)`):
  pure `tray_state(alerts, actions)` → red if any *active* high/critical alert, yellow if any
  active alert, else green. An alert is **active** unless it has ≥ 1 `action_id` and every one
  of those actions is known and `undone` (alerts with no action stay active; an unknown action id
  counts as in force). Polls `GET /alerts`, `GET /actions`, `GET /status` every
  `app.tray_refresh_s`; Mode ▸ → `POST /mode`, Undo all → `POST /undo-all`, through an injected
  HTTP client (httpx) to `API_BASE_URL` only. `pystray`/`PIL`/`httpx` are imported lazily.

### 6.8 Evidence export (CE)
- The agent runs a rolling capture: `dumpcap -i <iface> -b filesize:20000 -b files:5 -w data/ring.pcapng`.
- Evidence = `tshark -r data/ring.pcapng -Y "ip.addr==<ip>" -w data/evidence/<alert_id>.pcap`.

---

## 7. Models

| Model | Script | Data | Output |
|---|---|---|---|
| DGA classifier | `models/train_dga.py` | Benign: Tranco top 100k (`pip install tranco`). DGA: ~100k domains generated from a handful of families in `github.com/baderj/domain_generation_algorithms` (GPL-2.0; used for training only, never shipped). | `models/dga.joblib` |
| Flow classifier | `models/train_flow.py` | Lab pcaps (benign, portscan, bruteforce, dos) | `models/flow.joblib` |
| Anomaly | trained live during calibration | The user's own traffic | in memory + `store` |

Training scripts must print: class counts, a classification report, a confusion matrix, and the top
features. Use `random_state=42`. A balanced cap per class: 20,000 rows (flow), 100,000 (DGA).
Never use IP addresses or ports as model features.

---

## 8. Commands

```powershell
# one-time setup (Windows VM, admin PowerShell)
#   1. Install Wireshark (includes Npcap) and Python 3.12
py -3.12 -m venv .venv
.venv\Scripts\pip install nfstream psutil scikit-learn pandas joblib fastapi uvicorn httpx pywebview pystray pillow pyyaml tranco winotify pytest

# train
.venv\Scripts\python models\train_dga.py
.venv\Scripts\python models\train_flow.py

# run (agent needs an ADMIN terminal; app runs in a normal one)
.venv\Scripts\python -m agent.main
.venv\Scripts\python -m app.main

# tests
.venv\Scripts\python -m pytest -q

# emergency: remove every HomeSOC firewall rule
Remove-NetFirewallRule -Group "HomeSOC"

# package
.venv\Scripts\pyinstaller installer\homesoc.spec
#  then compile installer\homesoc.iss with Inno Setup → HomeSOC-Setup.exe
```

Lab VM (Ubuntu, host-only network `192.168.56.0/24`, C2 at `192.168.56.20`):

```bash
python3 lab/c2_server.py            # logs check-ins and uploads on :8080
sudo dnsmasq -C lab/dnsmasq.conf    # answers all DNS lookups inside the lab
```

---

## 9. Safety rules (Claude Code must follow these)

1. **No real malware, ever.** `lab/fake_malware/freegamecheats.py` is a harmless simulator. It may only:
   - resolve made-up random-looking domain names (through the lab DNS),
   - send HTTP GET check-ins to `LAB_C2 = "192.168.56.20"` every 5 s, **opening a new connection each
     time** (no keep-alive, so each check-in is its own flow),
   - POST ~20 MB of random bytes to the lab C2 once.
   It must refuse to run unless `LAB_C2` is inside `192.168.56.0/24` **and** the env var
   `HOMESOC_LAB=1` is set. No persistence, no file encryption, no credential access, no spreading, no
   anti-analysis tricks.
2. Never write code that connects to IPs from real threat-intel feeds. Demo the intel path with
   `data/test_intel.txt`.
3. Every firewall rule is created in group `HomeSOC` with a stored rule name, and every action has
   Undo. Never modify or delete firewall rules outside that group.
4. Never disable Windows Defender or the firewall globally. A Defender exclusion for our own build
   folder is allowed in the test VM only, and must be documented in `README.md`.
5. The API binds to `127.0.0.1` only. No telemetry. No uploading user data anywhere.
6. Check the allowlist before any automatic block. In doubt → alert, don't block.

---

## 10. Coding conventions

- Python 3.12, type hints, `dataclasses`, `logging` (no bare `print` in `agent/` except the CLI).
- Config lives in `config.yaml`; no magic numbers inside detectors. Thresholds go in config.
- Every detector gets unit tests in `tests/` with synthetic `FlowEvent`s (e.g. a fake beacon every
  5 s ± 0.1 s must trigger; random intervals must not).
- Keep functions small; one detector per file; detectors must not import each other.
- Windows-only code (PowerShell, toasts) stays in `agent/response/`, `agent/procinfo.py`, `app/notify.py`
  so the rest can be tested on any OS.
- When a change affects the demo flow, update the "Demo checklist" below.

---

## 11. Milestones

- [ ] **H1** Event schema agreed; skeleton repo; `config.yaml`
- [ ] **H10** `capture.py` prints FlowEvents with process names on the Windows VM
- [ ] **H10** `dga.joblib` trained; confusion matrix saved
- [ ] **H15** intel + beacon detectors pass unit tests
- [ ] **H16** **First end-to-end:** fake malware → alert → quarantine → Undo (ugly is fine)
- [ ] **H22** App window + tray + toasts wired to the WebSocket; FP test (1 h of normal use) done
- [ ] **H30** Feature freeze. Installer builds.
- [ ] **H36** Demo

## 12. Demo checklist

1. Fresh Windows VM snapshot → run `HomeSOC-Setup.exe` → tray shield green.
2. Apps screen shows Chrome/Discord/Spotify traffic.
3. Run `Downloads\FreeGameCheats.exe` (with `HOMESOC_LAB=1`).
4. DGA toast → beacon detection → app quarantined (Auto-protect) → C2 log shows check-ins stop.
5. Open the alert (What happened / What we did / What you should do) → Export evidence → Wireshark.
6. Undo → rule removed.
7. Show the model metrics slide.

---

## 13. How to work with Claude Code on this repo

- Start a task with the owner and file: *"I'm CE. Implement `agent/response/firewall.py` per §6.5 with
  tests."*
- Ask for tests with every detector or response change.
- If a spec here is ambiguous, ask before guessing. If you change a spec, update this file in the
  same change.

---

## Checks
Single source of truth for "does the project still work". The test-gate and verifiers run
exactly these. An empty entry means that layer is unguarded. The skeleton ticket fills these in;
the pytest suite must run on any OS (Windows-only code is mocked at the PowerShell boundary).

| Layer | Build | Test | Lint/typecheck |
|-------|-------|------|----------------|
| agent | none (pure Python) | `.venv/bin/python -m pytest -q` (Windows: `.venv\Scripts\python -m pytest -q`) | `.venv/bin/ruff check .` (Windows: `.venv\Scripts\ruff check .`) |
| app | none (pure Python) | covered by the same pytest run (app tickets add their tests to `tests/`) | covered by the same ruff run |

Setup for the checks on macOS/Linux: `python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`.

**Smoke test:** `.venv/bin/python -m pytest -q tests/test_smoke.py` (Windows:
`.venv\Scripts\python -m pytest -q tests/test_smoke.py`; also selectable with `-m smoke`, and part
of the normal pytest run) — exercises the main user path end to end (fake-malware flows → alert →
quarantine → undo) through the real pipeline in `auto` mode with only `subprocess.run` patched.

## Branches
- **Working branch: `dev`.** All work happens here; `main` only receives merges once
  `/test-gate full` returns APPROVE.

## Team
| Person | Role (§2) | GitHub | Label |
|---|---|---|---|
| David | CE — Computer Engineering | `SilkyDaveCodes` | `owner:david` |
| Jake | CS — Cybersecurity | `jakefernan` | `owner:jake` |
