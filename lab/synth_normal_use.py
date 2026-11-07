"""Generate the SYNTHETIC one-hour normal-use fixture for the false-positive test (ticket #49).

    .venv\\Scripts\\python -m lab.synth_normal_use      # rewrites the file below

Output: ``tests/fixtures/normal_use_synthetic.jsonl``, in exactly the format
``lab/fp_recording.py`` writes from a live capture. It is a stand-in until the real VM
recording (``tests/fixtures/normal_use_vm.jsonl``) lands; see docs/fp-test.md.

Deterministic: one seeded ``random.Random`` (:data:`SEED`), so the same code always writes the
same file (a test checks the committed file matches).

What it models (one home PC, 60 minutes):
    * chrome.exe browsing popular sites (many hosts per page, connection reuse), a YouTube video
      over one QUIC connection, and the always-on Google push (GCM) connection;
    * msedge.exe briefly (Bing/MSN/Outlook);
    * discord.exe: the gateway websocket (heartbeat every 41.25 s plus irregular events),
      API calls and CDN images;
    * spotify.exe: the access-point connection (ping every 120 s), the dealer websocket (ping
      every 30 s), per-track API calls and audio downloads;
    * svchost.exe: every DNS lookup (Windows' DNS client service), NTP, telemetry, a Windows
      Update check and download, SSDP discovery;
    * MsMpEng.exe (Defender cloud lookups), OneDrive.exe (irregular change checks, each its own
      connection; OneDrive is not on the exe allowlist);
    * a few inbound LAN broadcasts from the router (process "unknown").

Flows are cut the way NFStream cuts them (``capture.idle_timeout`` / ``active_timeout`` from
``config.yaml``): packets are simulated per connection, a gap longer than the idle timeout or a
flow older than the active timeout starts a new flow on the same 5-tuple. Only the first flow of
a TLS connection carries the SNI hostname. Every IP is private or from the RFC 5737
documentation ranges; no address comes from a threat-intel feed (CLAUDE.md §9.2).
"""

from __future__ import annotations

import ipaddress
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent import config
from lab import fp_recording

logger = logging.getLogger(__name__)

SEED = 49
DURATION_S = 3600.0
OUT_PATH = config.REPO_ROOT / "tests" / "fixtures" / "normal_use_synthetic.jsonl"

PC_IP = "192.168.1.50"
ROUTER_IP = "192.168.1.1"      # home router: DNS resolver, SSDP/NetBIOS chatter
SSDP_IP = "239.255.255.250"
BROADCAST_IP = "192.168.1.255"
TCP, UDP = 6, 17
DNS_CACHE_S = 300.0            # Windows DNS client cache: one lookup per host per ~5 min
EPHEMERAL_PORTS = (49152, 65535)
# Addresses the test intel feed (tests/fixtures/intel_feed.txt) lists; never handed out.
RESERVED_IPS = frozenset({"192.0.2.10", "198.51.100.7", "203.0.113.5", "203.0.113.99"})
REMOTE_NETS = ("198.51.100.0/24", "203.0.113.0/24")

SITES: dict[str, list[str]] = {
    "google": ["www.google.com", "www.gstatic.com", "apis.google.com", "ogs.google.com",
               "fonts.gstatic.com", "lh3.googleusercontent.com"],
    "gmail": ["mail.google.com", "accounts.google.com", "ssl.gstatic.com", "fonts.googleapis.com"],
    "wikipedia": ["en.wikipedia.org", "upload.wikimedia.org"],
    "reddit": ["www.reddit.com", "www.redditstatic.com", "styles.redditmedia.com", "i.redd.it",
               "preview.redd.it"],
    "github": ["github.com", "github.githubassets.com", "avatars.githubusercontent.com",
               "api.github.com", "collector.github.com"],
    "bbc": ["www.bbc.co.uk", "static.files.bbci.co.uk", "ichef.bbci.co.uk"],
    "nytimes": ["www.nytimes.com", "static01.nyt.com", "www.googletagmanager.com",
                "www.google-analytics.com"],
    "amazon": ["www.amazon.com", "m.media-amazon.com", "images-na.ssl-images-amazon.com",
               "fls-na.amazon.com"],
    "stackoverflow": ["stackoverflow.com", "cdn.sstatic.net", "i.sstatic.net",
                      "ajax.googleapis.com", "cdnjs.cloudflare.com"],
    "cdn-app": ["d3c1a2b9x7kq0z.cloudfront.net", "fonts.googleapis.com"],
}
EDGE_SITES: dict[str, list[str]] = {
    "bing": ["www.bing.com", "th.bing.com", "r.bing.com"],
    "msn": ["www.msn.com", "assets.msn.com", "img-s-msn-com.akamaized.net", "ntp.msn.com"],
    "outlook": ["outlook.office.com", "login.microsoftonline.com", "res.cdn.office.net"],
}
YOUTUBE_HOSTS = ["www.youtube.com", "i.ytimg.com", "yt3.ggpht.com", "jnn-pa.googleapis.com"]
YOUTUBE_VIDEO_HOST = "rr3---sn-4g5e6nsz.googlevideo.com"


@dataclass
class Conn:
    """One connection (one 5-tuple) and the exchanges simulated on it."""

    process: str
    dst_ip: str
    dst_port: int
    protocol: int
    hostname: str | None
    app_proto: str | None
    src_port: int
    src_ip: str = PC_IP
    direction: str = "outbound"
    # (time s, bytes_out, bytes_in, packets)
    exchanges: list[tuple[float, int, int, int]] = field(default_factory=list)

    def add(self, t: float, out: int, inn: int, packets: int = 2) -> None:
        self.exchanges.append((t, out, inn, packets))


class Generator:
    def __init__(self, cfg: dict[str, Any], seed: int = SEED) -> None:
        self.rng = random.Random(seed)
        self.idle_s = float(cfg["capture"]["idle_timeout"])
        self.active_s = float(cfg["capture"]["active_timeout"])
        self.conns: list[Conn] = []
        self._ips: dict[str, str] = {}
        self._pool = [str(ip) for net in REMOTE_NETS for ip in ipaddress.ip_network(net).hosts()
                      if str(ip) not in RESERVED_IPS]
        self._dns_seen: dict[str, float] = {}
        self._used_ports: set[int] = set()

    # --- helpers --------------------------------------------------------------------------

    def ip_of(self, host: str) -> str:
        if host not in self._ips:
            self._ips[host] = self._pool[len(self._ips) % len(self._pool)]
        return self._ips[host]

    def port(self) -> int:
        while True:
            p = self.rng.randint(*EPHEMERAL_PORTS)
            if p not in self._used_ports:
                self._used_ports.add(p)
                return p

    def dns(self, host: str, t: float) -> None:
        """svchost.exe (DNS client service) looks ``host`` up, unless it is cached."""
        last = self._dns_seen.get(host)
        if last is not None and t - last < DNS_CACHE_S:
            return
        self._dns_seen[host] = t
        c = Conn("svchost.exe", ROUTER_IP, 53, UDP, host, "DNS", self.port())
        c.add(max(t - 0.03, 0.0), self.rng.randint(60, 90), self.rng.randint(90, 300))
        self.conns.append(c)

    def tls(self, process: str, host: str, t: float, port: int = 443,
            app_proto: str = "TLS", protocol: int = TCP) -> Conn:
        """Open a new TLS (or QUIC) connection to ``host`` at ``t`` (after a DNS lookup)."""
        self.dns(host, t)
        c = Conn(process, self.ip_of(host), port, protocol, host, app_proto, self.port())
        self.conns.append(c)
        return c

    def burst(self, c: Conn, t: float, n: int, out_range: tuple[int, int],
              in_range: tuple[int, int], spread_s: float) -> float:
        """``n`` request/response exchanges on ``c`` within ``spread_s`` seconds of ``t``."""
        times = sorted(t + self.rng.uniform(0, spread_s) for _ in range(n))
        for x in times:
            c.add(x, self.rng.randint(*out_range), self.rng.randint(*in_range),
                  self.rng.randint(2, 12))
        return times[-1] if times else t

    def poisson(self, start: float, end: float, mean_gap_s: float) -> list[float]:
        out, t = [], start
        while True:
            t += self.rng.expovariate(1.0 / mean_gap_s)
            if t >= end:
                return out
            out.append(t)

    # --- apps -----------------------------------------------------------------------------

    def browser(self, process: str, sites: dict[str, list[str]], start: float, end: float,
                mean_gap_s: float) -> None:
        """Page visits; a host's connection is reused while it was used in the last 90 s."""
        open_conns: dict[str, tuple[Conn, float]] = {}
        names = sorted(sites)
        for t in self.poisson(start, end, mean_gap_s):
            for host in sites[self.rng.choice(names)]:
                at = t + self.rng.uniform(0.0, 1.5)
                reuse = open_conns.get(host)
                if reuse is not None and at - reuse[1] < 90.0:
                    c = reuse[0]
                else:
                    c = self.tls(process, host, at)
                last = self.burst(c, at, self.rng.randint(1, 8), (300, 4000), (2000, 250_000),
                                  self.rng.uniform(0.2, 6.0))
                open_conns[host] = (c, last)

    def youtube(self, start: float, end: float) -> None:
        for host in YOUTUBE_HOSTS:
            c = self.tls("chrome.exe", host, start + self.rng.uniform(0, 2))
            self.burst(c, start, self.rng.randint(3, 10), (500, 3000), (5000, 400_000), 5.0)
        video = self.tls("chrome.exe", YOUTUBE_VIDEO_HOST, start + 2.0, app_proto="QUIC",
                         protocol=UDP)
        t = start + 2.0
        while t < end:  # the player tops its buffer up every few seconds
            video.add(t, self.rng.randint(800, 2500), self.rng.randint(300_000, 1_200_000), 300)
            t += self.rng.uniform(2.0, 9.0)
        # occasional stats pings while the video plays
        for x in self.poisson(start, end, 40.0):
            c = self.tls("chrome.exe", "www.youtube.com", x)
            c.add(x, self.rng.randint(800, 2000), self.rng.randint(200, 900))

    def push_channel(self, process: str, host: str, port: int, keepalive_s: float,
                     event_gap_s: float | None, start: float = 1.0) -> None:
        """One long-lived connection: a keepalive every ``keepalive_s`` plus random events."""
        c = self.tls(process, host, start, port=port)
        c.add(start, 600, 4000, 8)
        t = start + keepalive_s
        while t < DURATION_S:
            c.add(t, self.rng.randint(40, 120), self.rng.randint(40, 120))
            t += keepalive_s
        if event_gap_s is not None:
            for x in self.poisson(start, DURATION_S, event_gap_s):
                c.add(x, self.rng.randint(60, 600), self.rng.randint(200, 6000),
                      self.rng.randint(2, 6))

    def discord(self) -> None:
        # Gateway websocket: heartbeat every 41.25 s, plus server events (messages, presence).
        self.push_channel("discord.exe", "gateway.discord.gg", 443, 41.25, 9.0, start=3.0)
        api = None
        for t in self.poisson(10.0, DURATION_S, 75.0):
            if api is None or self.rng.random() < 0.3:
                api = self.tls("discord.exe", "discord.com", t)
            api.add(t, self.rng.randint(400, 2000), self.rng.randint(500, 20_000), 6)
            if self.rng.random() < 0.5:
                host = self.rng.choice(["cdn.discordapp.com", "media.discordapp.net"])
                c = self.tls("discord.exe", host, t + 0.3)
                self.burst(c, t + 0.3, self.rng.randint(1, 5), (300, 900), (10_000, 400_000), 2.0)

    def spotify(self) -> None:
        self.tls("spotify.exe", "apresolve.spotify.com", 2.0).add(2.0, 500, 1500, 6)
        self.push_channel("spotify.exe", "ap-gew4.spotify.com", 4070, 120.0, None, start=2.5)
        self.push_channel("spotify.exe", "dealer.spotify.com", 443, 30.0, 400.0, start=3.0)
        t = 5.0
        while t < DURATION_S:  # one track after another
            api = self.tls("spotify.exe", "spclient.wg.spotify.com", t)
            self.burst(api, t, self.rng.randint(2, 6), (500, 3000), (1000, 40_000), 1.5)
            art = self.tls("spotify.exe", "i.scdn.co", t + 0.5)
            self.burst(art, t + 0.5, 1, (300, 600), (20_000, 120_000), 0.5)
            audio = self.tls("spotify.exe", "audio-ak-spotify-com.akamaized.net", t + 0.8)
            self.burst(audio, t + 0.8, self.rng.randint(2, 4), (500, 1500),
                       (1_000_000, 3_000_000), 4.0)
            t += self.rng.uniform(150.0, 300.0)

    def windows(self) -> None:
        self.tls("svchost.exe", "www.msftconnecttest.com", 1.0, port=80,
                 app_proto="HTTP").add(1.0, 150, 400, 6)
        # NTP: w32time polls time.windows.com from UDP 123, well over 10 minutes apart.
        t = 30.0
        while t < DURATION_S:
            self.dns("time.windows.com", t)
            c = Conn("svchost.exe", self.ip_of("time.windows.com"), 123, UDP, None, "NTP", 123)
            c.add(t, 90, 90)
            self.conns.append(c)
            t += 1024.0 + self.rng.uniform(-2.0, 2.0)
        # Telemetry and settings: irregular, each its own connection.
        for x in self.poisson(20.0, DURATION_S, 420.0):
            host = self.rng.choice(["v10.events.data.microsoft.com",
                                    "settings-win.data.microsoft.com", "arc.msn.com",
                                    "login.live.com"])
            c = self.tls("svchost.exe", host, x)
            self.burst(c, x, self.rng.randint(1, 3), (2000, 30_000), (500, 6000), 2.0)
        # A Windows Update scan, then a ~60 MB download on one connection.
        at = 900.0
        for host in ["fe3cr.delivery.mp.microsoft.com", "slscr.update.microsoft.com",
                     "displaycatalog.mp.microsoft.com", "ctldl.windowsupdate.com"]:
            c = self.tls("svchost.exe", host, at)
            self.burst(c, at, self.rng.randint(2, 5), (1000, 8000), (5000, 200_000), 3.0)
            at += self.rng.uniform(1.0, 4.0)
        dl = self.tls("svchost.exe", "7.tlu.dl.delivery.mp.microsoft.com", at + 5.0, port=80,
                      app_proto="HTTP")
        t = at + 5.0
        for _ in range(240):  # dense packets for ~4 minutes
            dl.add(t, self.rng.randint(200, 600), self.rng.randint(200_000, 300_000), 180)
            t += self.rng.uniform(0.5, 1.5)
        # SSDP discovery (multicast, fixed source port per burst) and router broadcasts.
        for x in self.poisson(0.0, DURATION_S, 300.0):
            c = Conn("svchost.exe", SSDP_IP, 1900, UDP, None, "SSDP", self.port())
            for k in range(3):
                c.add(x + k, 170, 0, 1)
            self.conns.append(c)
        for x in self.poisson(0.0, DURATION_S, 240.0):
            c = Conn("unknown", BROADCAST_IP, 137, UDP, None, "NetBIOS", 137, src_ip=ROUTER_IP,
                     direction="inbound")
            c.add(x, 92, 0, 1)
            self.conns.append(c)

    def defender_and_onedrive(self) -> None:
        for x in self.poisson(5.0, DURATION_S, 180.0):
            host = self.rng.choice(["wdcp.microsoft.com", "wdcpalt.microsoft.com"])
            c = self.tls("MsMpEng.exe", host, x)
            self.burst(c, x, 1, (1500, 6000), (800, 3000), 0.5)
        c = self.tls("MsMpEng.exe", "definitionupdates.microsoft.com", 1800.0)
        self.burst(c, 1800.0, 6, (800, 2000), (400_000, 900_000), 8.0)
        # OneDrive checks for changes now and then (driven by push notifications and local file
        # activity, so irregular), opening a new connection each time.
        for x in self.poisson(15.0, DURATION_S, 90.0):
            c = self.tls("OneDrive.exe", "skyapi.live.net", x)
            self.burst(c, x, 1, (900, 2500), (600, 4000), 0.3)
        for x in self.poisson(30.0, DURATION_S, 600.0):
            c = self.tls("OneDrive.exe", "g.live.com", x)
            self.burst(c, x, 2, (800, 2000), (2000, 15_000), 1.0)

    def build(self) -> None:
        self.windows()
        self.spotify()
        self.discord()
        self.push_channel("chrome.exe", "mtalk.google.com", 5228, 285.0, 600.0, start=4.0)
        self.browser("chrome.exe", SITES, 60.0, 1500.0, 40.0)
        self.youtube(1500.0, 2100.0)
        self.browser("chrome.exe", SITES, 2100.0, 3000.0, 45.0)
        self.browser("msedge.exe", EDGE_SITES, 3000.0, 3500.0, 30.0)
        self.defender_and_onedrive()

    # --- NFStream-style flow cutting ------------------------------------------------------

    def flows(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for c in self.conns:
            ex = sorted(e for e in c.exchanges if 0.0 <= e[0] < DURATION_S)
            if not ex:
                continue
            chunks: list[list[tuple[float, int, int, int]]] = [[ex[0]]]
            for e in ex[1:]:
                cur = chunks[-1]
                if e[0] - cur[-1][0] > self.idle_s or e[0] - cur[0][0] >= self.active_s:
                    chunks.append([e])
                else:
                    cur.append(e)
            for i, chunk in enumerate(chunks):
                start, last = chunk[0][0], chunk[-1][0] + 0.02
                active_cut = i + 1 < len(chunks) and chunks[i + 1][0][0] - start >= self.active_s \
                    and chunks[i + 1][0][0] - chunk[-1][0] <= self.idle_s
                seen = chunks[i + 1][0][0] if active_cut else last + self.idle_s
                records.append({
                    "seen_ms": round(seen * 1000),
                    "ts_ms": round(start * 1000),
                    "end_ms": round(last * 1000),
                    "process": c.process,
                    "src_ip": c.src_ip,
                    "src_port": c.src_port,
                    "dst_ip": c.dst_ip,
                    "dst_port": c.dst_port,
                    "protocol": c.protocol,
                    "hostname": c.hostname if i == 0 else None,  # SNI only in the first flow
                    "app_proto": c.app_proto,
                    "bytes_out": sum(e[1] for e in chunk),
                    "bytes_in": sum(e[2] for e in chunk),
                    "packets": sum(e[3] for e in chunk),
                    "direction": c.direction,
                })
        records.sort(key=lambda r: (r["seen_ms"], r["ts_ms"], r["process"], r["src_port"]))
        return records


def generate(cfg: dict[str, Any] | None = None, seed: int = SEED) -> list[dict[str, Any]]:
    """The synthetic hour as fixture records, in arrival order."""
    gen = Generator(cfg if cfg is not None else config.load(), seed)
    gen.build()
    return gen.flows()


def render(records: list[dict[str, Any]]) -> str:
    return "".join(fp_recording.dumps(r) + "\n" for r in records)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    records = generate()
    Path(OUT_PATH).write_text(render(records), encoding="utf-8", newline="\n")
    logger.info("Wrote %d synthetic records to %s", len(records), OUT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
