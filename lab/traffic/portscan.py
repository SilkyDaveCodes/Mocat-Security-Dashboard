"""Generate PORTSCAN lab traffic for the flow classifier (label ``portscan``, CLAUDE.md §6.3).

A single source makes sequential TCP connect attempts across a list of ports on one lab
host. Most ports are closed, so this produces the short, fan-out, mostly-rejected flows the
inbound flow classifier learns to recognise as a port scan (MITRE T1046). The port list is
modest and bounded; this is a labeled-sample generator, not a scanning tool.

The :mod:`lab.traffic._guard` guardrail runs before any connection: the generator refuses to
touch anything outside ``192.168.56.0/24`` and requires ``HOMESOC_LAB=1``.

Run inside the lab (see ``lab/pcaps/README.md`` for the matching capture command)::

    set HOMESOC_LAB=1
    python -m lab.traffic.portscan --target 192.168.56.20
"""

from __future__ import annotations

import argparse
import logging
import socket

from lab.traffic import _guard

logger = logging.getLogger("homesoc.lab.traffic.portscan")

# A small, fixed set of common ports: enough to look like a scan, far from an exhaustive sweep.
DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080)
DEFAULT_TIMEOUT_S = 0.5


def connect_once(host: str, port: int, *, timeout: float = DEFAULT_TIMEOUT_S) -> bool:
    """Attempt one TCP connect; return True if it opened, False if refused/timed out.

    The connection is closed immediately. A refused or timed-out port is the normal,
    expected outcome of a scan and is not an error.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        logger.info("port %s closed/filtered (%s)", port, exc)
        return False
    try:
        logger.info("port %s open", port)
        return True
    finally:
        sock.close()


def run(host: str, ports: tuple[int, ...] = DEFAULT_PORTS) -> int:
    """Connect to each port in ``ports`` in sequence; return the count of open ports.

    The guardrail is the caller's responsibility (see :func:`main`); ``host`` is assumed
    already validated as in-range.
    """
    open_count = 0
    for port in ports:
        if connect_once(host, port):
            open_count += 1
    logger.info("portscan of %s finished: %d/%d open", host, open_count, len(ports))
    return open_count


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate PORTSCAN lab traffic (CLAUDE.md §6.3)")
    parser.add_argument("--target", default=_guard.DEFAULT_LAB_TARGET, help="lab target host")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse_args(argv)
    try:
        addrs = _guard.check_target(args.target)
    except _guard.LabGuardError as exc:
        logger.error("%s", exc)
        raise SystemExit(2) from exc
    logger.warning("generating PORTSCAN lab traffic to %s (host-only lab only)", addrs[0])
    run(addrs[0])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.info("interrupted")
        raise SystemExit(0) from None
