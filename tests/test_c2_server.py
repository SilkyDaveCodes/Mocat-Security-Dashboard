"""Tests for lab.c2_server and lab/dnsmasq.conf (the lab demo endpoint, CLAUDE.md §8/§9).

Every test starts the server on 127.0.0.1 on an ephemeral port in a background thread and
makes real localhost HTTP requests with stdlib http.client. No test touches the network
beyond loopback, and no test needs the lab VM. The server is a passive access log only, so
the tests assert that uploads are counted but never written to disk.
"""

from __future__ import annotations

import http.client
import re
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from lab import c2_server
from lab.c2_server import LoggingC2Server, make_server

REPO_ROOT = Path(__file__).resolve().parent.parent
DNSMASQ_CONF = REPO_ROOT / "lab" / "dnsmasq.conf"
C2_SERVER_SRC = REPO_ROOT / "lab" / "c2_server.py"
LAB_C2 = "192.168.56.20"


@pytest.fixture
def server() -> Iterator[LoggingC2Server]:
    """A running server on 127.0.0.1:<ephemeral>, torn down after the test."""
    srv = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _conn(server: LoggingC2Server) -> http.client.HTTPConnection:
    host, port = server.server_address[:2]
    return http.client.HTTPConnection(host, port, timeout=5)


# --- AC1: a GET check-in is logged with time and client IP -----------------------------------


def test_get_checkin_is_logged_with_time_and_client_ip(server: LoggingC2Server) -> None:
    conn = _conn(server)
    conn.request("GET", "/checkin")
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    assert resp.status == 200
    assert body == b"ok\n"
    assert len(server.log) == 1
    entry = server.log[0]
    assert entry.kind == "GET"
    assert entry.client_ip == "127.0.0.1"
    assert entry.byte_count == 0
    assert entry.ts > 0  # a real timestamp was recorded


def test_multiple_checkins_are_each_logged(server: LoggingC2Server) -> None:
    for _ in range(3):
        conn = _conn(server)
        conn.request("GET", "/checkin")
        conn.getresponse().read()
        conn.close()
    assert [e.kind for e in server.log] == ["GET", "GET", "GET"]


# --- AC2: a POST upload is logged with its byte count, and no file is stored -----------------


def test_post_upload_logs_byte_count(server: LoggingC2Server) -> None:
    payload = b"x" * 1234
    conn = _conn(server)
    conn.request("POST", "/upload", body=payload, headers={"Content-Length": str(len(payload))})
    resp = conn.getresponse()
    assert resp.status == 200
    resp.read()
    conn.close()

    assert len(server.log) == 1
    entry = server.log[0]
    assert entry.kind == "POST"
    assert entry.byte_count == 1234
    assert entry.client_ip == "127.0.0.1"


def test_post_upload_writes_no_files(server: LoggingC2Server, tmp_path: Path) -> None:
    """The server stores nothing: the cwd (here tmp_path) gains no files from an upload."""
    import os

    before = set(os.listdir(tmp_path))
    payload = b"\x00\x01\x02" * 500  # 1500 bytes of binary junk
    conn = _conn(server)
    conn.request("POST", "/upload", body=payload, headers={"Content-Length": str(len(payload))})
    conn.getresponse().read()
    conn.close()

    assert server.log[0].byte_count == len(payload)
    # No persistence: nothing landed in the working directory.
    assert set(os.listdir(tmp_path)) == before


def test_source_never_opens_a_file_for_writing() -> None:
    """Static guard: the module performs no file-write/open-for-write of any kind."""
    src = C2_SERVER_SRC.read_text(encoding="utf-8")
    assert "open(" not in src
    assert "write_text" not in src
    assert "write_bytes" not in src
    # The only wfile.write calls are the tiny HTTP responses, not body persistence.


# --- AC3: the bind address comes from the CLI arg, never a hardcoded public address ----------


def test_cli_host_is_used_as_bind_address() -> None:
    args = c2_server._parse_args(["--host", "127.0.0.1", "--port", "0"])
    assert args.host == "127.0.0.1"
    assert args.port == 0


def test_default_host_is_the_lab_address_not_public() -> None:
    args = c2_server._parse_args([])
    assert args.host == LAB_C2
    assert c2_server.DEFAULT_HOST == LAB_C2


def test_make_server_binds_exactly_the_passed_host() -> None:
    srv = make_server("127.0.0.1", 0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()


def test_module_has_no_hardcoded_public_bind() -> None:
    src = C2_SERVER_SRC.read_text(encoding="utf-8")
    assert "0.0.0.0" not in src
    # make_server must bind whatever it is given, not a literal address.
    assert "return LoggingC2Server((host, port)" in src


# --- AC4: dnsmasq.conf resolves all names to the lab C2 address ------------------------------


def test_dnsmasq_conf_wildcards_all_names_to_lab_c2() -> None:
    lines = [
        line.strip()
        for line in DNSMASQ_CONF.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert f"address=/#/{LAB_C2}" in lines


def test_dnsmasq_conf_does_not_forward_upstream() -> None:
    """A sealed lab must not leak lookups: no-resolv keeps dnsmasq from forwarding."""
    text = DNSMASQ_CONF.read_text(encoding="utf-8")
    assert re.search(r"^\s*no-resolv\s*$", text, flags=re.MULTILINE)
