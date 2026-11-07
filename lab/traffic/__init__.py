"""Labeled lab-traffic generators for the flow classifier (CLAUDE.md §6.3, §7, §9).

Nothing in this package is an attack tool. Each module produces a small, bounded burst
of one *labeled* traffic pattern (benign, portscan, bruteforce, dos) so that a pcap can be
captured on the isolated host-only lab network (``192.168.56.0/24``) and fed to
``models/train_flow.py``. Every generator imports :mod:`lab.traffic._guard` and refuses to
send a single packet to any target outside the lab network, exactly like the
``lab/fake_malware`` simulator. The ``192.168.56.0/24`` network is host-only (CLAUDE.md §8),
so traffic these generators make never leaves the lab.
"""
