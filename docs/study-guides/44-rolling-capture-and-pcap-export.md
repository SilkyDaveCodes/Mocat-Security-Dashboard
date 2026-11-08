# Study guide: Rolling capture and per-alert pcap export

**Ticket:** #44 · **Date:** 2026-11-07 · **Gate:** APPROVE

## The big picture

Before this change HomeSOC could spot a threat and explain it, but it kept no proof. If you
wanted to show *what the packets looked like* (for the demo: "Export evidence, open in
Wireshark"), there was nothing to show. Now the agent starts a tool called **dumpcap**
(part of Wireshark) when it starts. It records all network traffic into a small set of files
that keep getting overwritten, oldest first. When someone asks for evidence on an alert, the
agent uses another Wireshark tool, **tshark**, to cut out only the packets that involve the
alert's IP address and saves them as `data/evidence/<alert_id>.pcap`.

Think of a security camera that loops over the last few hours of tape. Nobody watches it
live, but when something happens you pull the tape, cut the minutes that show the culprit and
hand that clip to the police.

A "pcap" is simply a file of recorded network packets. Wireshark opens it.

## Map of the changes

```mermaid
flowchart LR
  subgraph Config
    CFG["config.yaml<br/>+ evidence: section<br/>(tool paths, ring size, timeouts)"]:::changed
  end
  subgraph Agent
    EV["agent/evidence.py<br/>+ RingCapture (dumpcap)<br/>+ EvidenceExporter (tshark/mergecap)<br/>+ id and IP validation"]:::new
    MAIN["agent/main.py<br/>~ run_agent(ring_starter=)<br/>~ main() starts/stops ring"]:::changed
    API["agent/api.py<br/>+ GET /alerts/id/evidence<br/>~ create_app(evidence=)"]:::changed
    STORE["agent/store.py"]:::untouched
  end
  subgraph Tools
    DUMP["dumpcap"]:::untouched
    TSH["tshark / mergecap"]:::untouched
  end
  subgraph Tests
    T["tests/test_evidence.py<br/>+ 40 tests"]:::new
  end
  DOC["CLAUDE.md<br/>~ section 6.8 notes"]:::changed

  CFG ==>|settings| EV
  MAIN ==>|start / stop| EV
  EV ==>|spawns, ring files| DUMP
  MAIN ==>|EvidenceExporter| API
  API ==>|export(alert)| EV
  EV ==>|filter + merge| TSH
  API -->|get_alert| STORE
  T -.->|fake launchers| EV

  classDef new fill:#d4f8d4,stroke:#2a7a2a,color:#000
  classDef changed fill:#fff3c4,stroke:#a07800,color:#000
  classDef removed fill:#f8d4d4,stroke:#a02a2a,color:#000,stroke-dasharray:4 3
  classDef untouched fill:#eee,stroke:#999,color:#000
```

**How to read it:** green = new, yellow = changed, grey = existing; thick arrows were added by this ticket.

## File by file

### `config.yaml` - changed

**What it's for:** every tunable setting of the project.
**What changed and why:** a new `evidence:` section so no path or limit is hard-coded.

```yaml
evidence:
  dumpcap: "C:\\Program Files\\Wireshark\\dumpcap.exe"
  ring_filesize_kb: 20000   # size of each ring file
  ring_files: 5             # how many files to keep
  evidence_dir: data/evidence
```

The Wireshark installer does not put its tools on `PATH`, so the defaults point to its
install folder. There are also timeouts for tshark runs and for stopping dumpcap.

### `agent/evidence.py` - new

**What it's for:** everything about recording and exporting packets.
**What changed and why:** this is the whole feature, so it lives in one new file.

**`EvidenceSettings`** reads the `evidence` section plus `capture.interface` into one frozen
(unchangeable) object, with defaults for missing keys.

**`RingCapture`** runs dumpcap for the agent's whole life.

```python
["dumpcap", "-i", iface, "-b", "filesize:20000", "-b", "files:5", "-w", "data/ring.pcapng"]
```

`start()` launches it; if dumpcap is missing it only logs a warning, so the agent still
works. `stop()` politely terminates it, waits a few seconds, then kills it if needed. Its
output is discarded, so a wrong interface name only shows when it stops.

**`ring_files()`** finds the recording. With `-b`, dumpcap does not write `ring.pcapng`; it
writes `ring_00001_20261107120000.pcapng`, `ring_00002_...` and so on. This function lists
them oldest first by their number.

**Validation** happens before anything touches a file name or command.

```python
ALERT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
```

`evidence_path()` also checks that the final path stays inside the evidence folder, so an id
like `../../x` cannot escape. `alert_target_ip()` picks the first signal target that is a real
IP (domains from DGA signals are skipped) and rewrites it in canonical form.

**`EvidenceExporter.export(alert)`** does the cut. Worked example: the alert targets
`192.168.56.20`.
- One ring file: run the exact spec command
  `tshark -r ring_..pcapng -Y ip.addr==192.168.56.20 -w data/evidence/<id>.pcap`.
- Three ring files: run tshark on each into a temporary part, then
  `mergecap -w <id>.pcap part0 part1 part2` joins them in time order, and the parts are deleted.
IPv6 targets use `ipv6.addr` instead of `ip.addr`. Every command is a list of arguments run
without a shell, so text in an argument is never interpreted as a command. A lock allows one
export at a time. The launchers (`popen`, `run`) can be swapped in, which is how tests avoid
needing Wireshark.

### `agent/main.py` - changed

**What it's for:** starts and stops the agent's parts.
**What changed and why:** the ring must run from start to shutdown.

`run_agent` gets a `ring_starter` argument; if given, it is called once and its result's
`stop()` is called in the `finally` block. Errors in either step are logged, never fatal.
It also passes `EvidenceExporter.from_config(cfg)` into the API. `main()` passes
`evidence.start_ring_capture`; tests pass nothing.

### `agent/api.py` - changed

**What it's for:** the local web API the app talks to.
**What changed and why:** the new route that the "Export evidence" button will call.

`GET /alerts/{id}/evidence` checks in order: id is safe (400), alert exists (404), alert has an
IP target (409), exporter exists (503), then exports. Tool trouble becomes 503 (not installed
or no ring files yet) or 502 (tool failed). On success it returns the id, IP, file path, byte
size and number of ring files used. Cheap checks come first so a bad request runs no command.

### `CLAUDE.md` - changed

Adds `evidence.py` to the CE ownership row and repo layout, and documents the design in
section 6.8 (file names, one-vs-many files, status codes).

### `tests/test_evidence.py` - new (test)

Fake `dumpcap` and `tshark` launchers record what they were asked to run; the temp folder holds
fake ring files; a real `TestClient` calls the API. Any attempt to start a real process fails
the test.
- Dumpcap command matches the spec; start, missing-tool and stop/kill behaviour.
- `run_agent` starts and stops the ring, and survives a failing starter.
- Export: right tshark command, domain targets skipped, IP canonicalised, several files merged in order.
- Error codes: 400, 404, 409, 502, 503, and nothing runs for 400/404/409.
- Safety: path stays in the evidence folder; every command is a list without a shell.

## How you know it works

- The command-shape tests prove the exact commands from section 6.8 are used.
- The status-code tests prove each failure maps to the right HTTP error.
- The validation tests prove bad ids and non-IP targets never reach a command.
- Gate: APPROVE. 837 passed (797 before + 40 new), ruff clean, smoke test passed.

## Try it yourself

1. Read `agent/evidence.py` top docstring, then `EvidenceExporter.export`.
2. Run only these tests: `.venv/bin/python -m pytest -q tests/test_evidence.py`
   (Windows: `.venv\Scripts\python -m pytest -q tests/test_evidence.py`).
3. Lint: `.venv/bin/ruff check .`
4. On the Windows VM with Wireshark, run the agent, trigger an alert, then open
   `http://127.0.0.1:8765/alerts/<id>/evidence`.

## Open questions / risks

- Needs an extra tool, `mergecap`, beyond the dumpcap and tshark in the spec.
- dumpcap's error output is thrown away, so a wrong interface name only shows at shutdown.
- The exported file is pcapng content with a `.pcap` name; Wireshark opens it anyway.
- Reading a ring file that dumpcap is still writing might give a 502.
- Nothing has run against the real Wireshark tools on Windows yet.
