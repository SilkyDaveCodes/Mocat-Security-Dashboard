"""Generate BRUTEFORCE lab traffic for the flow classifier (label ``bruteforce``, §6.3).

Repeated authentication attempts against ONE service port on one lab host: many short
connections in a row, each sending a throwaway fake ``user:password`` line and reading the
rejection. This produces the repetitive, single-port, many-short-flows pattern the inbound
flow classifier learns to recognise as a brute-force (MITRE T1110). The attempt count is
modest and bounded; the credentials are meaningless constants (no real account is targeted).

The :mod:`lab.traffic._guard` guardrail runs before any connection: the generator refuses to
touch anything outside ``192.168.56.0/24`` and requires ``HOMESOC_LAB=1``.

Run inside the lab (see ``lab/pcaps/README.md`` for the matching capture command)::

    set HOMESOC_LAB=1
    python -m lab.traffic.bruteforce --target 192.168.56.20 --port 8080
"""

from __future__ import annotations

import argparse
import logging
import socket

from lab.traffic import _guard

logger = logging.getLogger("homesoc.lab.traffic.bruteforce")

DEFAULT_PORT = 8080
DEFAULT_ATTEMPTS = 40  # modest and bounded: a credible burst, not an endless hammer
DEFAULT_TIMEOUT_S = 1.0
# Meaningless placeholder credentials; this never targets a real account or service.
FAKE_USERNAME = "labuser"
FAKE_PASSWORDS = ("password", "123456", "admin", "letmein", "qwerty")


def attempt_login(
    host: str, port: int, password: str, *, timeout: float = DEFAULT_TIMEOUT_S
) -> bool:
    """Open one short connection and send a fake login line; return True if it connected.

    The server is expected to reject; the point is the flow shape, not a successful login.
    A refused/timed-out connection is logged and counts as a (failed) attempt.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        logger.info("auth attempt could not connect to %s:%s (%s)", host, port, exc)
        return False
    try:
        payload = f"LOGIN {FAKE_USERNAME}:{password}\r\n".encode()
        sock.sendall(payload)
        try:
            sock.recv(256)  # drain any rejection banner; ignore contents
        except OSError:
            pass
        logger.info("auth attempt (user=%s) sent to %s:%s", FAKE_USERNAME, host, port)
        return True
    finally:
        sock.close()


def run(host: str, port: int = DEFAULT_PORT, *, attempts: int = DEFAULT_ATTEMPTS) -> int:
    """Make ``attempts`` sequential login attempts against ``host:port``; return the count.

    The guardrail is the caller's responsibility (see :func:`main`); ``host`` is assumed
    already validated as in-range.
    """
    for i in range(attempts):
        password = FAKE_PASSWORDS[i % len(FAKE_PASSWORDS)]
        attempt_login(host, port, password)
    logger.info("bruteforce of %s:%s finished after %d attempt(s)", host, port, attempts)
    return attempts


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate BRUTEFORCE lab traffic (CLAUDE.md §6.3)")
    parser.add_argument("--target", default=_guard.DEFAULT_LAB_TARGET, help="lab target host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="service port to hammer")
    parser.add_argument(
        "--attempts", type=int, default=DEFAULT_ATTEMPTS, help="number of login attempts"
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
        "generating BRUTEFORCE lab traffic to %s:%s (host-only lab only)", addrs[0], args.port
    )
    run(addrs[0], args.port, attempts=args.attempts)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.info("interrupted")
        raise SystemExit(0) from None
