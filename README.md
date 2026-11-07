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

## Safety

HomeSOC never binds its API to anything but `127.0.0.1`, only creates firewall rules in the
`HomeSOC` group (all undoable), and the lab "malware" is a harmless simulator that only talks to
the lab C2 at `192.168.56.20`. See `CLAUDE.md` §9.
