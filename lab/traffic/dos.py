"""Generate DOS lab traffic for the flow classifier (label ``dos``, CLAUDE.md §6.3).

A bounded burst of rapid TCP connection attempts to ONE port on one lab host, with no pause
between them. This produces the high-rate, single-destination flow pattern the inbound flow
classifier learns to recognise as a denial-of-service attempt (MITRE T1498). The burst size
is modest and bounded (a few hundred connections) — this is a labeled-sample generator for a
short pcap, deliberately NOT a stress/flood tool.

The :mod:`lab.traffic._guard` guardrail runs before any connection: the generator refuses to
touch anything outside ``192.168.56.0/24`` and requires ``HOMESOC_LAB=1``.

Run inside the lab (see ``lab/pcaps/README.md`` for the matching capture command)::

    set HOMESOC_LAB=1
    python -m lab.traffic.dos --target 192.168.56.20 --port 8080
"""

from __future__ import annotations

import argparse
import logging
import socket

from lab.traffic import _guard

logger = logging.getLogger("homesoc.lab.traffic.dos")

DEFAULT_PORT = 8080
DEFAULT_BURST = 200  # bounded: enough rapid flows for a pcap, not an unbounded flood
DEFAULT_TIMEOUT_S = 0.5
MAX_BURST = 1000  # hard cap so the "bounded" guarantee cannot be overridden into a flood


def connect_once(host: str, port: int, *, timeout: float = DEFAULT_TIMEOUT_S) -> bool:
    """Open and immediately close one TCP connection; return True if it connected.

    A refused/timed-out attempt still counts toward the burst (it is still a flow on the
    wire) and is not treated as an error.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    sock.close()
    return True


def run(host: str, port: int = DEFAULT_PORT, *, burst: int = DEFAULT_BURST) -> int:
    """Fire ``burst`` rapid back-to-back connections at ``host:port``; return attempts made.

    ``burst`` is clamped to ``MAX_BURST`` so the bounded guarantee holds. The guardrail is
    the caller's responsibility (see :func:`main`); ``host`` is assumed validated as in-range.
    """
    if burst < 0:
        raise ValueError("burst must be >= 0")
    count = min(burst, MAX_BURST)
    opened = 0
    for _ in range(count):
        if connect_once(host, port):
            opened += 1
    logger.info("dos burst of %d connection(s) to %s:%s (%d opened)", count, host, port, opened)
    return count


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate DOS lab traffic (CLAUDE.md §6.3)")
    parser.add_argument("--target", default=_guard.DEFAULT_LAB_TARGET, help="lab target host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="target port")
    parser.add_argument(
        "--burst", type=int, default=DEFAULT_BURST, help=f"connections to make (<= {MAX_BURST})"
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
        "generating DOS lab traffic to %s:%s (host-only lab only)", addrs[0], args.port
    )
    run(addrs[0], args.port, burst=args.burst)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.info("interrupted")
        raise SystemExit(0) from None
