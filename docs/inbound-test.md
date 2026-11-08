# Inbound attack test (portscan / bruteforce -> block IP -> undo)

Live run of ticket #61, for two people at the workstation. Lab range only: every command
targets `192.168.56.0/24` (CLAUDE.md §9); the `lab/traffic` generators refuse anything else
and need `HOMESOC_LAB=1`.

| Machine | IP | Who |
|---|---|---|
| Windows VM (agent + app) | `<WIN_IP>`, e.g. `192.168.56.101` | David |
| Ubuntu lab VM (attacker) | `192.168.56.20` | Jake |

`<WIN_IP>` is the Windows VM's host-only address, handed out by VirtualBox DHCP. Check it first:
`Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -like '192.168.56.*'`. In the
#61 run it was `192.168.56.101`; a scan at a wrong address prints `No route to host` / times
out and HomeSOC sees nothing.

Windows on the Windows VM: (1) admin PowerShell = agent, (2) normal = app, (3) normal = the lab
listener for step 2, (4) normal = checks (`Get-NetFirewallRule`, `netstat`).

The automated version of this run is `tests/test_inbound_e2e.py` (same flows, real pipeline,
only `subprocess.run` faked). If it fails, fix that first.

## Preconditions (Windows VM)

1. `models\flow.joblib` exists. If not, train it (lab pcaps in `lab\pcaps\`, see
   `lab/pcaps/README.md`):
   ```powershell
   .venv\Scripts\python models\train_flow.py
   ```
2. `capture.interface` in `config.yaml` is the host-only adapter (the name in Wireshark's list).
   Installed agent: edit `C:\ProgramData\HomeSOC\config.yaml`, not the repo copy.
3. Take `192.168.56.20` out of the intel test list for this run: put a `#` in front of it in
   `data\test_intel.txt` (installed: `C:\ProgramData\HomeSOC\data\test_intel.txt`). Otherwise
   intel also flags every inbound flow from the lab VM, and in auto mode it quarantines the
   bruteforce listener on its first connection, so the rest of the attempts look like a scan.
   **Put the line back afterwards** (the demo's intel path uses it).
4. Start the agent in an **ADMIN** terminal and the app in a normal one:
   ```powershell
   .venv\Scripts\python -m agent.main
   .venv\Scripts\python -m app.main
   ```
   The agent log must show `Detectors running: ... flow_model ...` and **no**
   `Flow model not found`.
5. Mode **auto**: Settings screen in the app, or
   ```powershell
   Invoke-RestMethod -Method Post http://127.0.0.1:8765/mode -ContentType application/json -Body '{"mode":"auto"}'
   ```
6. No HomeSOC rules left over:
   ```powershell
   Get-NetFirewallRule -Group HomeSOC | Select DisplayName   # expect nothing
   ```

## Step 1: portscan -> T1046 + block

Lab VM:
```bash
HOMESOC_LAB=1 python3 -m lab.traffic.portscan --target <WIN_IP>
```
NFStream reports a flow after 10 s idle, so allow ~20 s after the scan finishes.
Windows VM, expect within a few seconds:
- an alert "Your PC is being attacked from 192.168.56.20", What happened mentions a port scan
  and `MITRE ATT&CK: T1046`, What we did "We blocked all traffic to and from 192.168.56.20";
- agent log: `Alert critical: unknown risk=...` and `block_ip 192.168.56.20 for ...`;
- the rules:
  ```powershell
  Get-NetFirewallRule -Group HomeSOC | Select DisplayName
  # HomeSOC block 192.168.56.20 out #xxxxxxxx
  # HomeSOC block 192.168.56.20 in #xxxxxxxx
  ```

## Step 2: undo, then bruteforce -> T1110

1. Undo the block: the alert's Undo button in the app, or
   ```powershell
   Invoke-RestMethod "http://127.0.0.1:8765/actions?undone=false"      # find the block_ip id
   Invoke-RestMethod -Method Post http://127.0.0.1:8765/actions/<id>/undo
   Get-NetFirewallRule -Group HomeSOC | Select DisplayName             # expect nothing
   ```
2. A brute force needs a listening service, or every attempt is a dropped SYN and the model
   calls it a scan. Start the lab listener on the Windows VM (normal terminal; click "Allow" if
   Windows Firewall asks):
   ```powershell
   .venv\Scripts\python lab\c2_server.py --host <WIN_IP> --port 8080
   ```
   Check it before attacking: `netstat -ano | findstr ":8080"` must show
   `<WIN_IP>:8080 ... LISTENING`. In the agent log the bruteforce flows must then show `in=` > 0B;
   `out=74B in=0B` on every flow means nothing answered and the model (correctly) calls it a scan.
3. **Wait at least 65 s after the scan ended.** The flow_model window, its repeat limit and the
   scoring window are all 60 s; inside them the bruteforce flows mix with the scan's and the
   same IP is not blocked twice in one episode (an undone block is not re-requested).
4. Lab VM:
   ```bash
   HOMESOC_LAB=1 python3 -m lab.traffic.bruteforce --target <WIN_IP> --port 8080
   ```
5. Expect an alert mentioning brute-force attempts and `T1110`, and a **new** pair of
   `HomeSOC block 192.168.56.20 in/out #...` rules (a different `#` tag than step 1).

## Step 3: undo everything

App tray menu **Undo all**, or
```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8765/undo-all
Get-NetFirewallRule -Group HomeSOC | Select DisplayName    # expect nothing
```
Then stop the listener, restore `192.168.56.20` in `test_intel.txt`, and set the mode back if
needed. Emergency: `Remove-NetFirewallRule -Group "HomeSOC"`.

## If nothing fires

A source needs `>= detectors.flow_model.min_flows` (3) inbound flows within
`detectors.flow_model.window_s` (60 s) and a mean attack probability
`>= detectors.flow_model.probability_threshold` (0.85), then risk
`>= scoring.auto_block_ip.risk` (0.85) to block. All in `config.yaml`; restart the agent after
a change.

1. Agent log (console; installed: `C:\ProgramData\HomeSOC\agent.log`): look for
   `Flow model not found` / `Could not load flow model` at start-up, and for the per-flow lines
   `flow ... 192.168.56.20:<port> -> <WIN_IP>:<port> (inbound, ...)`. No such lines =
   capture is on the wrong interface. `(outbound, ...)` = direction is wrong (§6.1).
2. Probabilities are not logged below the threshold. Score the attack straight from the rolling
   capture (`data\ring_*.pcapng`; installed: under `C:\ProgramData\HomeSOC\data\`), from the
   repo root:
   ```powershell
   @'
   import glob, joblib
   from nfstream import NFStreamer
   from agent.detectors.flow_features import RAW_FIELDS, features
   b = joblib.load("models/flow.joblib")
   for path in sorted(glob.glob("data/ring_*.pcapng")):
       for f in NFStreamer(source=path, statistical_analysis=True):
           if f.src_ip == "192.168.56.20":
               x = features({n: getattr(f, n, None) for n in RAW_FIELDS})
               p = b["model"].predict_proba([[x[n] for n in b["feature_names"]]])[0]
               print(f.dst_port, {c: round(float(p[i]), 2) for c, i in b["class_index"].items()})
   '@ | .venv\Scripts\python -
   ```
   Post that output and the log lines on the ticket.
3. Mostly `benign` or the wrong class usually means the training pcaps don't look like this
   target (e.g. they were captured against the Ubuntu VM, which answers closed ports with RST,
   while Windows Firewall drops the SYNs silently). This is what happened in #61: the Ubuntu-only
   model scored the Windows scan below the threshold. Record `portscan_win.pcapng` and
   `bruteforce_win.pcapng` on the Windows VM ("Windows-target captures" in
   `lab/pcaps/README.md`; both are already in `labels.yaml`), run
   `.venv\Scripts\python models\train_flow.py`, and restart the agent.

## #61 live run (2026-11-07)

Windows VM `192.168.56.101`, model retrained with the Windows-target captures (300 rows per
class, test accuracy 0.99).

- Portscan: `flow_model` fired on the 3rd flow (p=1.00), T1046, `HomeSOC block 192.168.56.20
  in/out #375c0804`.
- Bruteforce (listener up, after Undo): T1110 (p=1.00, 3 flows), a fresh `HomeSOC block 192.168.56.20 in/out` pair.
  A first attempt with no listener running was (correctly) classified as a portscan.
- Undo (single) and `POST /undo-all`: `Get-NetFirewallRule -Group HomeSOC` lists nothing.
- Seen on the way: creating the two rules takes ~15-18 s; `192.168.56.20` in `test_intel.txt`
  also raises intel alerts naming the listening service (`svchost.exe`, `System`,
  `python.exe`) as having "contacted" a malicious server (alert only, no action).

## Results (copy to the ticket)

- [ ] Portscan -> T1046 alert + `HomeSOC block 192.168.56.20 in/out` rules
- [ ] Bruteforce -> T1110 alert (+ a fresh block)
- [ ] Undo / Undo all -> `Get-NetFirewallRule -Group HomeSOC` lists nothing
