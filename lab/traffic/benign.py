"""Generate BENIGN lab traffic for the flow classifier (label ``benign``, CLAUDE.md §6.3/§7).

Ordinary, paced HTTP GET requests (plus a few DNS lookups) to the lab C2/service host, at a
modest, bounded scale suitable for capturing a short training pcap. This is the "normal"
class the inbound flow classifier learns to tell apart from portscan/bruteforce/dos.

The :mod:`lab.traffic._guard` guardrail runs before any connection: the generator refuses to
touch anything outside ``192.168.56.0/24`` and requires ``HOMESOC_LAB=1``.

Run inside the lab (see ``lab/pcaps/README.md`` for the matching capture command)::

    set HOMESOC_LAB=1
    python -m lab.traffic.benign --target 192.168.56.20
"""

from __future__ import annotations

import argparse
import http.client
import logging
import socket
import time

from lab.traffic import _guard

logger = logging.getLogger("homesoc.lab.traffic.benign")

DEFAULT_PORT = 8080
DEFAULT_REQUESTS = 30  # modest and bounded: enough flows for a training pcap, not a flood
DEFAULT_INTERVAL_S = 1.0
DEFAULT_TIMEOUT_S = 5.0
REQUEST_PATHS = ("/", "/index.html", "/status", "/favicon.ico")
LOOKUP_NAMES = ("alpha.lab", "beta.lab", "gamma.lab")


def http_get(host: str, port: int, path: str, *, timeout: float = DEFAULT_TIMEOUT_S) -> int:
    """Send one ordinary HTTP GET over a fresh connection; return the status code."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Connection": "close"})
        resp = conn.getresponse()
        resp.read()
        logger.info("GET %s -> %s via %s:%s", path, resp.status, host, port)
        return resp.status
    finally:
        conn.close()


def run(
    host: str,
    port: int = DEFAULT_PORT,
    *,
    requests: int = DEFAULT_REQUESTS,
    interval: float = DEFAULT_INTERVAL_S,
) -> int:
    """Send ``requests`` paced GETs (cycling a few paths) and a few DNS lookups.

    The guardrail is the caller's responsibility (see :func:`main`); this function assumes
    ``host`` is already validated as in-range. Returns the number of GETs sent.
    """
    for name in LOOKUP_NAMES:
        try:
            socket.getaddrinfo(name, None)
        except OSError as exc:
            logger.info("lookup of %s failed (expected outside the lab): %s", name, exc)
    sent = 0
    while sent < requests:
        http_get(host, port, REQUEST_PATHS[sent % len(REQUEST_PATHS)])
        sent += 1
        if sent < requests:
            time.sleep(interval)
    logger.info("sent %d benign GET(s) to %s:%s", sent, host, port)
    return sent


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate BENIGN lab traffic (CLAUDE.md §7)")
    parser.add_argument("--target", default=_guard.DEFAULT_LAB_TARGET, help="lab target host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="target port")
    parser.add_argument("--requests", type=int, default=DEFAULT_REQUESTS, help="GETs to send")
    parser.add_argument(
        "--interval", type=float, default=DEFAULT_INTERVAL_S, help="seconds between GETs"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse_args(argv)
    try:
        addrs = _guard.check_target(args.target)
    except _guard.LabGuardError as exc:
        logger.error("%s", exc)
        raise SystemExit(2) from exc
    logger.warning(
        "generating BENIGN lab traffic to %s:%s (host-only lab only)", addrs[0], args.port
    )
    run(addrs[0], args.port, requests=args.requests, interval=args.interval)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.info("interrupted")
        raise SystemExit(0) from None
