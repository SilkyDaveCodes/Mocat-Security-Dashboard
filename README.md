# HomeSOC

HomeSOC is a personal network-security app for home Windows PCs. It watches every network
connection the PC makes, tags it with the app that made it, detects malware-like behavior
(DGA domains, beaconing, known-bad IPs, unusual uploads, inbound scans), contains threats with
undoable Windows Firewall rules, and explains every alert in plain English. Everything runs
locally; the only outbound request is a blocklist refresh.

See `CLAUDE.md` for the full project spec.

## Setup (Windows 10/11 x64, Python 3.12)

In an admin PowerShell on the Windows VM:

```powershell
# 1. Install Wireshark (includes Npcap) and Python 3.12
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

Set `capture.interface` in `config.yaml` to the interface name shown in Wireshark's interface
list. All detector and scoring thresholds and the response mode (`off | notify | auto`) also live
in `config.yaml`.

Run the tests:

```powershell
.venv\Scripts\python -m pytest -q
```

## Running the tests on macOS / Linux

The test suite does not need the Windows-only packages (nfstream, pywebview, winotify, ...).
Install only the dev requirements:

```bash
python3.12 -m venv .venv          # 3.12 is the target; 3.13 also works for the tests
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
```

## False-positive test (record an hour of normal use)

On the Windows VM, in an admin terminal, use the PC normally for an hour while this records
every flow (only process names, IPs, hostnames, ports, byte counts and rebased timestamps; no
PIDs, exe paths or user names):

```powershell
.venv\Scripts\python -m lab.fp_recording --minutes 60
# -> tests\fixtures\normal_use_vm.jsonl (add --force to overwrite, --out to pick another file)
```

`tests/test_fp_replay.py` replays every `tests/fixtures/normal_use_*.jsonl` through the full
pipeline in `auto` mode and fails on any medium-or-higher alert or firewall action. Until the VM
recording lands, the only fixture is the synthetic `normal_use_synthetic.jsonl`
(`python -m lab.synth_normal_use` regenerates it). Details: `docs/fp-test.md`.

## Building the installer (HomeSOC-Setup.exe)

On the Windows build VM, from the repo root, with the models already trained (§8):

```powershell
.venv\Scripts\pip install pyinstaller
.venv\Scripts\python models\train_dga.py ...      # -> models\dga.joblib
.venv\Scripts\python models\train_flow.py         # -> models\flow.joblib
.venv\Scripts\pyinstaller --noconfirm installer\homesoc.spec
#   -> dist\HomeSOC\  (HomeSOC-Agent.exe, HomeSOC.exe, _internal\)
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\homesoc.iss
#   -> dist\HomeSOC-Setup.exe
```

- `installer/homesoc.spec` builds two executables in one folder: `HomeSOC-Agent.exe` (manifest
  `uac_admin`, elevated) and `HomeSOC.exe` (the app, normal user). It bundles `config.yaml`,
  `data/allowlist.txt`, `data/test_intel.txt`, `data/domain_allowlist.txt`, `models/dga.joblib`,
  `models/flow.joblib` and `app/ui/`. It never bundles `lab/`, `tests/`, the training scripts
  `models/train_*.py` or any DGA generator source (the baderj generators are GPL-2.0 and used
  for training only, CLAUDE.md §7, §9). `tests/test_installer.py` checks this.
- `installer/homesoc.iss` (Inno Setup 6) installs into `C:\Program Files\HomeSOC`, registers a
  scheduled task `HomeSOC Agent` that runs the agent as SYSTEM with highest privileges at
  startup (and starts it now), and adds the app to the Start menu and the all-users Startup
  folder; the app is launched after setup as the user who ran setup, not elevated. Setup warns
  if Npcap is missing (install Wireshark first).
- **Where the data goes:** Program Files is read-only, so everything writable (`config.yaml`,
  `data/homesoc.db`, `data/cache/`, `data/evidence/`, the ring pcap, `agent.log`) lives in
  `%PROGRAMDATA%\HomeSOC` (usually `C:\ProgramData\HomeSOC`), which both the agent and the app
  can read. On every start the agent copies the bundled `config.yaml` and data lists there if
  they are missing (your edits are kept) and refreshes the models. **Edit
  `C:\ProgramData\HomeSOC\config.yaml`** to set `capture.interface`, then restart the agent (admin PowerShell:
  `Stop-ScheduledTask "HomeSOC Agent"; Start-ScheduledTask "HomeSOC Agent"`).
  Running from source is unchanged: every path is still relative to the repo.
- **Uninstall** deletes the scheduled task, stops both programs and runs
  `Remove-NetFirewallRule -Group 'HomeSOC'`: only HomeSOC's own rules are removed, no other
  firewall or Defender setting is touched. `C:\ProgramData\HomeSOC` (alerts, settings) is kept;
  delete it by hand for a clean slate.

### Defender exclusion (test VM only)

PyInstaller executables are sometimes flagged by Windows Defender as false positives. **On the
test VM only**, you may exclude the build output folder while building and testing
(CLAUDE.md §9.4):

```powershell
# TEST VM ONLY. Never on a real PC, never for any folder but this repo's dist\.
Add-MpPreference -ExclusionPath "$PWD\dist"
# remove it when you are done:
Remove-MpPreference -ExclusionPath "$PWD\dist"
```

Never disable Defender or the firewall, and never add this exclusion on a real (non-test)
machine. Neither the installer nor HomeSOC itself ever changes Defender settings.

### Manual check on a fresh VM (demo checklist step 1)

1. Restore a fresh Windows VM snapshot with Wireshark (Npcap) installed.
2. Run `HomeSOC-Setup.exe`, accept the UAC prompt, leave "Open HomeSOC" ticked, finish.
3. Within a few seconds the tray shows the green HomeSOC shield and the window opens; the Home
   screen shows the agent connected. `Get-ScheduledTask "HomeSOC Agent"` shows it Running.
4. Uninstall (Settings > Apps): `Get-NetFirewallRule -Group 'HomeSOC'` then finds nothing and
   every other firewall rule is unchanged.

## Safety

HomeSOC never binds its API to anything but `127.0.0.1`, only creates firewall rules in the
`HomeSOC` group (all undoable), and the lab "malware" is a harmless simulator that only talks to
the lab C2 at `192.168.56.20`. See `CLAUDE.md` §9.
