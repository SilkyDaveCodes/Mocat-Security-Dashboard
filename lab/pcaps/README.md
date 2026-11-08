# Labeled lab pcaps for the flow classifier

This directory holds the labeled packet captures that `models/train_flow.py` uses to train
the inbound-attack flow classifier (`models/flow.joblib`, CLAUDE.md §6.3 / §7). The four
labels are **benign, portscan, bruteforce, dos**.

Everything here is produced **only inside the isolated host-only lab network
`192.168.56.0/24`** (CLAUDE.md §8, §9). The generators in [`lab/traffic/`](../traffic/)
refuse to send a single packet to any address outside that range and require `HOMESOC_LAB=1`
to be set — the same safety model as `lab/fake_malware/freegamecheats.py`. Run them only on
the lab VM.

- `labels.yaml` — maps each pcap filename below to its label. This is the machine-readable
  file `models/train_flow.py` consumes; keep the filenames here and in `labels.yaml` in sync.
- The `.pcapng` files themselves are large binary captures and are **not committed** to git
  (only `.gitkeep` and this README live here). Regenerate them with the commands below.

## Prerequisites (on the lab VM)

1. The lab C2 / service host is up at `192.168.56.20:8080` (see `lab/c2_server.py`), and the
   lab DNS answers lab names (see `lab/dnsmasq.conf`).
2. `HOMESOC_LAB=1` is set in the shell that runs the generator.
3. A capture tool is available. Examples below use `dumpcap` (ships with Wireshark) on the
   capture host; `tcpdump` works equally well on the Ubuntu lab VM.
4. Find the lab interface name first:
   - Windows: `dumpcap -D`  (pick the host-only adapter, e.g. `\Device\NPF_{...}`)
   - Linux:   `ip -o link`  (e.g. `enp0s8`)

In the commands below, replace `<IFACE>` with that interface. Each capture is scoped to the
lab host with a capture filter (`host 192.168.56.20`) so only lab traffic is recorded, and
each produces the exact filename listed in `labels.yaml`.

Start the capture first, then run the generator in a second shell, then stop the capture
(Ctrl-C) once the generator prints that it has finished.

## benign  →  `benign.pcapng`

```powershell
# shell 1 (capture)
dumpcap -i <IFACE> -f "host 192.168.56.20" -w lab\pcaps\benign.pcapng
# shell 2 (generate)
set HOMESOC_LAB=1
python -m lab.traffic.benign --target 192.168.56.20 --port 8080
```

```bash
# Linux equivalent (lab Ubuntu VM)
sudo tcpdump -i <IFACE> host 192.168.56.20 -w lab/pcaps/benign.pcapng
HOMESOC_LAB=1 python3 -m lab.traffic.benign --target 192.168.56.20 --port 8080
```

## portscan  →  `portscan.pcapng`

```powershell
# shell 1 (capture)
dumpcap -i <IFACE> -f "host 192.168.56.20" -w lab\pcaps\portscan.pcapng
# shell 2 (generate)
set HOMESOC_LAB=1
python -m lab.traffic.portscan --target 192.168.56.20
```

```bash
sudo tcpdump -i <IFACE> host 192.168.56.20 -w lab/pcaps/portscan.pcapng
HOMESOC_LAB=1 python3 -m lab.traffic.portscan --target 192.168.56.20
```

## bruteforce  →  `bruteforce.pcapng`

```powershell
# shell 1 (capture)
dumpcap -i <IFACE> -f "host 192.168.56.20" -w lab\pcaps\bruteforce.pcapng
# shell 2 (generate)
set HOMESOC_LAB=1
python -m lab.traffic.bruteforce --target 192.168.56.20 --port 8080
```

```bash
sudo tcpdump -i <IFACE> host 192.168.56.20 -w lab/pcaps/bruteforce.pcapng
HOMESOC_LAB=1 python3 -m lab.traffic.bruteforce --target 192.168.56.20 --port 8080
```

## dos  →  `dos.pcapng`

```powershell
# shell 1 (capture)
dumpcap -i <IFACE> -f "host 192.168.56.20" -w lab\pcaps\dos.pcapng
# shell 2 (generate)
set HOMESOC_LAB=1
python -m lab.traffic.dos --target 192.168.56.20 --port 8080
```

```bash
sudo tcpdump -i <IFACE> host 192.168.56.20 -w lab/pcaps/dos.pcapng
HOMESOC_LAB=1 python3 -m lab.traffic.dos --target 192.168.56.20 --port 8080
```

## Windows-target captures  →  `portscan_win.pcapng`, `bruteforce_win.pcapng`

The captures above target the Ubuntu VM, which answers closed ports with a RST. Windows Firewall
drops them silently, so a scan of the Windows VM is one SYN per port with no reply, and a model
trained only on the Ubuntu captures calls it benign (found in #61). Capture the attacks again
**on the Windows VM** (admin PowerShell, repo root), with the generators run on the lab VM.
`<WIN_IP>` is the Windows VM's host-only address (`Get-NetIPAddress -AddressFamily IPv4`; it was
`192.168.56.101` in #61).

```powershell
# portscan: 20 rounds of 15 ports (~300 flows)
& "C:\Program Files\Wireshark\dumpcap.exe" -i <IFACE> -f "host 192.168.56.20" -w lab\pcaps\portscan_win.pcapng
#   lab VM:  for i in $(seq 20); do HOMESOC_LAB=1 python3 -m lab.traffic.portscan --target <WIN_IP>; done
#   then Ctrl-C the capture

# bruteforce: needs a listener on the Windows VM, or every attempt is a dropped SYN (= a scan)
.venv\Scripts\python lab\c2_server.py --host <WIN_IP> --port 8080       # normal window, keep running
netstat -ano | findstr ":8080"                                          # must show LISTENING
& "C:\Program Files\Wireshark\dumpcap.exe" -i <IFACE> -f "host 192.168.56.20" -w lab\pcaps\bruteforce_win.pcapng
#   lab VM:  for i in $(seq 5); do HOMESOC_LAB=1 python3 -m lab.traffic.bruteforce --target <WIN_IP> --port 8080; done
#   the lab VM must print "auth attempt ... sent to", not "could not connect"; then Ctrl-C the capture
```

## After capturing

All six files (`benign.pcapng`, `portscan.pcapng`, `bruteforce.pcapng`, `dos.pcapng`,
`portscan_win.pcapng`, `bruteforce_win.pcapng`) should now exist in this directory and match the
entries in `labels.yaml`. `models/train_flow.py`
reads `labels.yaml`, loads each listed pcap, extracts flow features, and trains
`models/flow.joblib` using the labels as the target. Do not commit the `.pcapng` files.

## Training

```powershell
.venv\Scripts\python models\train_flow.py                 # reads lab\pcaps\labels.yaml
.venv\Scripts\python models\train_flow.py --cap 20000 --out models\flow.joblib
```

Each pcap is read with NFStream (`statistical_analysis=True`); every flow becomes one row of
the behavioural features in `agent/detectors/flow_features.py` (no IPs or ports). Every class
is cut to `min(cap, smallest class)` rows (default cap 20,000) so the classes are balanced.
The script prints class counts, a classification report, a confusion matrix (also saved to
`models/flow_confusion.csv`) and the top features, then writes `models/flow.joblib`.
