"""Passive logging HTTP endpoint for the host-only lab network (CLAUDE.md §8, §9).

This is a DEMO-ONLY receiving endpoint. It stands in for a malware command-and-control
server so the harmless ``lab/fake_malware`` simulator has something to check in with, and
so the demo can show those check-ins stopping once HomeSOC quarantines the app.

Safety (CLAUDE.md §9): this server is a *passive access log* only. It does exactly two
things and nothing else:

* answers an inbound HTTP GET by logging the time and the client IP, then returns a tiny
  ``200 OK`` body;
* answers an inbound HTTP POST by reading the ``Content-Length`` body, **discarding** it
  (never written to disk), logging only the received byte count, then returns ``200 OK``.

It sends no commands back, delivers no payloads, keeps no uploaded bytes, and has no
persistence or remote-control capability. It is meant to run on the lab Ubuntu VM, but it
is plain stdlib so the unit tests start it on 127.0.0.1 on any OS.

Run on the lab VM::

    python3 lab/c2_server.py --host 192.168.56.20 --port 8080
"""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal

logger = logging.getLogger("homesoc.lab.c2")

# Documented lab default (host-only network, CLAUDE.md §8). Never a public/wildcard address.
DEFAULT_HOST = "192.168.56.20"
DEFAULT_PORT = 8080

# Cap the number of bytes we are willing to read from a single upload so a client cannot
# make the server allocate without bound. The simulator POSTs ~20 MB once (CLAUDE.md §9.1).
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
READ_CHUNK = 1 << 20  # 1 MiB; read-and-discard in chunks, never buffering the whole body.


@dataclass(frozen=True)
class LogEntry:
    """One recorded request. Kept in memory only, for the demo view and for tests."""

    kind: Literal["GET", "POST"]
    client_ip: str
    ts: float  # seconds since the epoch (time.time())
    byte_count: int = 0  # received upload size for POST; 0 for GET


class LoggingC2Server(ThreadingHTTPServer):
    """A threading HTTP server that keeps an in-memory list of what it has logged.

    The ``log`` list lets the demo UI (and the tests) inspect check-ins and uploads
    without any file being written.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler_class: type) -> None:
        super().__init__(server_address, handler_class)
        self.log: list[LogEntry] = []

    def record(self, entry: LogEntry) -> None:
        self.log.append(entry)


class C2RequestHandler(BaseHTTPRequestHandler):
    """Logs GET check-ins and POST uploads; never serves a payload or stores a body."""

    server_version = "HomeSOCLabC2/1.0"

    # Route BaseHTTPRequestHandler's own logging through our logger instead of stderr.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (stdlib name)
        logger.debug("%s - %s", self.address_string(), format % args)

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _reply(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib handler name)
        import time

        entry = LogEntry(kind="GET", client_ip=self._client_ip(), ts=time.time())
        self.server.record(entry)  # type: ignore[attr-defined]
        logger.info("check-in (GET %s) from %s", self.path, entry.client_ip)
        self._reply(b"ok\n")

    def do_POST(self) -> None:  # noqa: N802 (stdlib handler name)
        import time

        received = self._drain_body()
        entry = LogEntry(
            kind="POST", client_ip=self._client_ip(), ts=time.time(), byte_count=received
        )
        self.server.record(entry)  # type: ignore[attr-defined]
        logger.info("upload (POST %s) of %d bytes from %s", self.path, received, entry.client_ip)
        self._reply(b"ok\n")

    def _drain_body(self) -> int:
        """Read the request body in chunks and discard it; return the byte count received.

        Nothing is kept: each chunk is counted and dropped. If ``Content-Length`` is
        missing or malformed we treat it as a zero-length body rather than guessing.
        """
        try:
            declared = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            declared = 0
        if declared < 0:
            declared = 0
        remaining = min(declared, MAX_UPLOAD_BYTES)

        received = 0
        while remaining > 0:
            chunk = self.rfile.read(min(READ_CHUNK, remaining))
            if not chunk:
                break
            received += len(chunk)
            remaining -= len(chunk)
            del chunk  # read-and-discard: the body is never retained or written to disk
        return received


def make_server(host: str, port: int) -> LoggingC2Server:
    """Create (but do not start) the lab C2 server bound to ``host:port``.

    The bind address is whatever the caller passes; there is no hardcoded public default
    here. Tests pass ``127.0.0.1`` and port ``0`` to get an ephemeral local port.
    """
    return LoggingC2Server((host, port), C2RequestHandler)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HomeSOC lab C2 passive logging server")
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"address to bind (default: {DEFAULT_HOST}, the host-only lab C2 address)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"port to bind (default: {DEFAULT_PORT})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = _parse_args(argv)
    server = make_server(args.host, args.port)
    host, port = server.server_address[:2]
    logger.info("lab C2 listening on %s:%s (passive logging only)", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
