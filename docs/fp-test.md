# False-positive test (ticket #49)

Goal: an hour of normal use on the PC, replayed through the full pipeline in `auto` mode, must
raise **no medium-or-higher alert and no firewall action**. The recording stays in the repo as
a regression test, so a later threshold change can't bring the false positives back.

> **Status: both fixtures are in.** `tests/fixtures/normal_use_vm.jsonl` is the real one-hour
> recording from the Windows 11 VM (~21,900 flows: Chrome, Edge, Spotify, Discord, OneDrive,
> Windows Update, Defender), recorded 2026-11-07. `normal_use_synthetic.jsonl` stays as a
> second, generated hour. Both replay with no alert and no action (see §4 for what it took).

## 1. Record (Windows VM, admin terminal)

Use the PC normally while it records: browse in Chrome and Edge, Discord and Spotify open,
let Windows Update and Defender do their thing. Don't run the lab malware.

```powershell
.venv\Scripts\python -m lab.fp_recording --minutes 60
#   writes tests\fixtures\normal_use_vm.jsonl (refuses to overwrite; add --force)
#   --out <file.jsonl> to write elsewhere, --config <yaml> for another config
```

It runs the same live capture as the agent (`agent.capture.run`: interface, NFStream settings
and process lookup from `config.yaml`) but no detectors or firewall, so it can run on its own or
next to the agent. Each flow is written as soon as it arrives; Ctrl+C keeps what was recorded.

### What a record holds (and what it doesn't)

One JSON object per line, with exactly these keys (`lab.fp_recording.ALLOWED_KEYS`; the tests
use the same set):

| key | meaning |
|---|---|
| `seen_ms` | when the flow reached the agent, ms since recording started |
| `ts_ms`, `end_ms` | flow start / end, same time base (`ts_ms` < 0 = already open at start) |
| `process` | exe name only (`chrome.exe`), never a path |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` | the 5-tuple |
| `hostname` | DNS query / TLS SNI, or `null` |
| `app_proto` | NFStream `application_name`, or `null` |
| `bytes_out`, `bytes_in`, `packets` | volume |
| `direction` | `outbound` / `inbound` |

Dropped: `pid`, `exe_path` (holds the Windows user name), the raw NFStream `features`, the
`type` tag. Times are rebased to the start of the recording, so the file doesn't say when it was
made. `.local` hostnames (mDNS names like `Jakes-iPhone.local`) are blanked; the DGA detector
skips them anyway, so replay is unaffected. A record that still looks like it holds a Windows or
user path is skipped, not written.

**Before committing the VM recording**, skim it once: IPs and hostnames are kept on purpose
(the detectors need them), so make sure nothing in it is something you'd rather not publish.

## 2. Replay (any OS)

```powershell
.venv\Scripts\python -m pytest -q tests/test_fp_replay.py tests/test_fp_recording.py
```

`tests/test_fp_replay.py` replays **every** `tests/fixtures/normal_use_*.jsonl` (drop the VM
recording in and it is picked up) through the real `Pipeline` with the real intel, dga, beacon
and anomaly detectors and the real `Scorer` in `auto` mode:

- One fake clock driven by each record's `seen_ms`, shared by the pipeline, scorer, anomaly
  detector and process lookup, so the 10-minute anomaly calibration and the 60 s scoring
  window behave as they did live.
- Every named process looks like a normal installed app (signed, under Program Files, not in
  Downloads/Temp). Each process name gets one fake PID; `unknown` flows get none, as live.
- Only `subprocess.run` is patched; any call fails the test at once (no firewall, ever).
- Intel uses the real `data/test_intel.txt` (lab IP only) and no downloaded feed. DGA uses the
  real `models/dga.joblib` and `data/cache/tranco` when present; otherwise the smoke test's
  feature stub and `tests/fixtures/tranco_standin.txt` (popular domains only).
- Asserts: zero medium/high/critical alerts, zero Actions, nothing published, no subprocess.
- A positive control splices the lab sim's 5 s check-ins into the synthetic hour: they must
  be caught (intel + beacon, quarantined), so "quiet" can't come from a blind harness.

`tests/test_fp_recording.py` fails if any record in any normal-use fixture has a key outside
the allowed set or a value that looks like a Windows/user path (`\Users\`, `C:\`, ...), and
tests the recorder itself (keys, stripped `pid`/`exe_path`/`features`, rebased times, stop
after the duration, Ctrl+C, no overwrite).

## 3. The synthetic stand-in

`python -m lab.synth_normal_use` regenerates `tests/fixtures/normal_use_synthetic.jsonl`
(seed 49; a test checks the committed file matches). About 1,000 flows over 60 minutes:
Chrome browsing ~10 popular sites (many hosts per page, connection reuse), a YouTube video
over one QUIC connection, Chrome's push connection, Edge (Bing/MSN/Outlook), the Discord
gateway (41.25 s heartbeat + events), API and CDN, Spotify (access point ping every 120 s,
dealer websocket ping every 30 s, per-track API and audio), svchost DNS for every lookup, NTP,
telemetry, a Windows Update check plus a ~60 MB download, SSDP, Defender cloud lookups,
OneDrive, and inbound router broadcasts. Flows are cut like NFStream cuts them
(`capture.idle_timeout` / `active_timeout`), and only the first flow of a TLS connection has
the SNI hostname. IPs are private or RFC 5737 documentation addresses, never from a
threat-intel feed. It has no upload over 10 MB in a minute, so the anomaly detector only
calibrates on it.

## 4. What was tuned

**One detector change, no threshold values changed.**

`detectors.beacon.new_connections_only: true` (new key, `agent/detectors/beacon.py`, spec in
CLAUDE.md §6.3). A beacon start now has to be a *new connection*: a flow on the same
`(src_ip, src_port, protocol)` as a start already held for that `(process, dst_ip, dst_port)`
is the same connection again and adds no start. Flows with no source port (ICMP) always count.

Why: NFStream cuts one long-lived connection into many flows (a new flow after 10 s of
silence, and every 30 s while it's busy). A websocket ping, a push-channel keepalive or a long
download then looks like a perfectly regular "check-in". Replaying the synthetic hour without
this rule gave critical beacon alerts on spotify.exe (pings every 30 s and 120 s),
chrome.exe (Google push on :5228, and the YouTube QUIC stream cut every 30 s) and svchost.exe
(the Windows Update download cut every 30 s). Any real PC with Spotify or a long download
would do the same, so this is a genuine false positive, not tuning to the synthetic data.
`test_keepalives_would_alert_if_each_flow_counted_as_a_check_in` keeps that evidence.

Trade-off: a C2 implant that keeps **one** connection open and talks on it at a fixed rate is
no longer a beacon to this detector (it looks exactly like Spotify's websocket). The lab sim
opens a new connection per check-in (§9.1), as do most HTTP beacons; the smoke test still
passes.

### Found by the real VM recording

The first replay of `normal_use_vm.jsonl` raised **10 critical beacon alerts**, nothing from
the other detectors:

- **chrome.exe → ad servers every 30.0 s** (`htlb.casalemedia.com`, `68.67.x.x`, ...), each
  time a *new* connection (new source port), so `new_connections_only` can't help. These are
  ad slots refreshing in tabs left open on ad-heavy pages. As regular as any C2 (±0.1 s over
  20 check-ins), so tightening `cv_max` / `min_starts` would not fix it.
  → `detectors.beacon.allowlisted_score: 0.3`: an app in `data/allowlist.txt` gets 0.3 instead
  of 0.9/0.95. That is below the 0.5 alert line even with the ×1.2 context boost, so a beacon
  alone is quiet for a browser, but it still combines (beacon 0.3 + a DGA hit 0.8 → 0.86).
  Trade-off: the allowlist matches by exe name, so malware calling itself `chrome.exe` gets the
  low beacon score too. The allowlist already makes that trade for quarantine (§6.4).
- **unknown → 224.0.0.22 / ff02::16 every ~300 s**: Windows' IGMP / MLD multicast membership
  reports. → `detectors.beacon.skip_non_unicast: true`: multicast, broadcast and unspecified
  destinations are ignored. No server answers there, so there is nothing to lose.

`test_vm_recording_would_alert_without_the_49_beacon_fixes` keeps that evidence.

Not tuned: `cv_max`, `min_starts`, the DGA threshold, the anomaly settings and every scoring
threshold are unchanged.

Also seen: ~30 % of the VM flows have process `unknown` (short connections whose owner
`PortHistory` missed). They are alert-only by design (§9.6), but a beacon from a mis-attributed
Chrome flow would not get the allowlisted score. Worth a capture ticket if it shows up.

## 5. Things to check against the VM recording

- **Jittered pollers that open a new connection each time.** An early draft of the synthetic
  data had OneDrive polling every 60 s +/-25 % (uniform). Its true CV is about 0.14, but with
  only 6 starts (5 intervals, `min_starts`) the sample CV dipped under 0.1 twice in an hour and
  raised a beacon alert. The draft was replaced by irregular polling because that jitter model
  was invented, not observed. If the VM recording shows a real app like this, the candidates
  are a higher `min_starts` or a lower `cv_max`, checked against the smoke test.
- **Large legitimate uploads** (OneDrive photo sync, a Drive upload in Chrome) of more than
  10 MB in a minute after calibration are what the anomaly detector flags. The synthetic hour
  has none.
- **Hostnames the stand-in Tranco list doesn't know.** Without `models/dga.joblib` and
  `data/cache/tranco` the DGA check falls back to a crude stub, which may flag a real but
  unusual hostname in the VM recording. Train the model and cache Tranco first
  (`models/train_dga.py`), or add the domain to `tests/fixtures/tranco_standin.txt` if it really
  is a top-100k domain.
- The anomaly detector is in `agent/main.py`'s `DETECTOR_FACTORIES` (#53), with its baselines
  in the agent's store; the replay runs the same detector on the fake clock, so a live false
  positive from it would show up here too.
