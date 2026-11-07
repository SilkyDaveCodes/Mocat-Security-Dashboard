"""Tests for lab.fake_malware.freegamecheats, the HARMLESS lab simulator (CLAUDE.md §9.1).

These tests assert REAL behaviour, never just that a mock was called:

* The two §9.1 guardrails are enforced *before* any network activity: with sockets and the
  HTTP client patched to record (and refuse) any use, a misconfigured run makes zero network
  calls and exits with an error.
* Check-ins and the upload are exercised against a real stdlib ThreadingHTTPServer on
  127.0.0.1:0 that counts accepted TCP connections and captures POST bodies, so "a new
  connection each check-in" and "exactly one ~20 MB POST" are observed, not mocked.
* Domain generation is pure and deterministic, checked without any network.

The guard rejects 127.0.0.1 (it is not in 192.168.56.0/24), so the transport tests call the
lower-level check_in/run_check_ins/upload functions directly against the local server, and the
guard is tested separately via validate_lab_target and main.
"""

from __future__ import annotations

import math
import socket
import struct
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from lab.fake_malware import freegamecheats as fgc
from lab.fake_malware.freegamecheats import LabGuardError

LAB_C2 = "192.168.56.20"


# --- a real local server that counts TCP connections and captures POST bodies ----------------


class _CountingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler: type) -> None:
        super().__init__(server_address, handler)
        self.connections = 0
        self.requests: list[tuple[str, int]] = []  # (method, body length)
        self._lock = threading.Lock()

    def get_request(self):  # one call per accepted TCP connection
        sock, addr = super().get_request()
        with self._lock:
            self.connections += 1
        return sock, addr

    def record(self, method: str, body_len: int) -> None:
        with self._lock:
            self.requests.append((method, body_len))


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence stderr
        pass

    def _ok(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_GET(self) -> None:  # noqa: N802
        self.server.record("GET", 0)  # type: ignore[attr-defined]
        self._ok()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        self.server.record("POST", len(data))  # type: ignore[attr-defined]
        self._ok()


@pytest.fixture
def server() -> Iterator[_CountingServer]:
    srv = _CountingServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _host_port(srv: _CountingServer) -> tuple[str, int]:
    host, port = srv.server_address[:2]
    return host, port


class _NetworkTripwire:
    """Stands in for socket/HTTP constructors; records and refuses any attempt to use them."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: object, **kwargs: object):
        self.calls += 1
        raise AssertionError("network activity attempted before/despite guardrail")


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> _NetworkTripwire:
    """Patch every network entrypoint the module uses so any call is recorded and fails."""
    tripwire = _NetworkTripwire()
    monkeypatch.setattr(fgc.http.client, "HTTPConnection", tripwire)
    monkeypatch.setattr(fgc.socket, "getaddrinfo", tripwire)
    monkeypatch.setattr(fgc.socket, "socket", tripwire)
    return tripwire


# --- AC1: HOMESOC_LAB unset -> error, zero network calls -------------------------------------


def test_main_without_homesoc_lab_exits_and_makes_no_network_calls(
    monkeypatch: pytest.MonkeyPatch, no_network: _NetworkTripwire
) -> None:
    monkeypatch.delenv(fgc.ENV_HOMESOC_LAB, raising=False)
    monkeypatch.setenv(fgc.ENV_LAB_C2, LAB_C2)  # in-range: only the missing flag should fail

    with pytest.raises(SystemExit) as excinfo:
        fgc.main([])

    assert excinfo.value.code == 2
    assert no_network.calls == 0  # the guard ran before any DNS/socket/HTTP


def test_validate_rejects_disabled_lab() -> None:
    with pytest.raises(LabGuardError, match="HOMESOC_LAB"):
        fgc.validate_lab_target(LAB_C2, lab_enabled=False)


def test_is_lab_enabled_requires_exactly_one() -> None:
    assert fgc._is_lab_enabled({"HOMESOC_LAB": "1"}) is True
    assert fgc._is_lab_enabled({"HOMESOC_LAB": "0"}) is False
    assert fgc._is_lab_enabled({"HOMESOC_LAB": "true"}) is False
    assert fgc._is_lab_enabled({}) is False


# --- AC2: LAB_C2 outside 192.168.56.0/24 -> error --------------------------------------------


def test_main_with_out_of_range_c2_exits_and_makes_no_network_calls(
    monkeypatch: pytest.MonkeyPatch, no_network: _NetworkTripwire
) -> None:
    monkeypatch.setenv(fgc.ENV_HOMESOC_LAB, "1")
    monkeypatch.setenv(fgc.ENV_LAB_C2, "8.8.8.8")

    with pytest.raises(SystemExit) as excinfo:
        fgc.main([])

    assert excinfo.value.code == 2
    assert no_network.calls == 0


def test_validate_rejects_out_of_range_target() -> None:
    with pytest.raises(LabGuardError, match="192.168.56.0/24"):
        fgc.validate_lab_target("8.8.8.8", lab_enabled=True)


@pytest.mark.parametrize(
    "host,inside",
    [
        ("192.168.56.20", True),
        ("192.168.56.1", True),
        ("192.168.56.255", True),
        ("192.168.57.20", False),  # adjacent subnet
        ("8.8.8.8", False),
        ("127.0.0.1", False),  # loopback is NOT the lab network
        ("not-an-ip", False),
        ("192.168.56.20 ", False),  # stray whitespace is not a valid address
    ],
)
def test_is_in_lab_network(host: str, inside: bool) -> None:
    assert fgc._is_in_lab_network(host) is inside


def test_validate_accepts_in_range_target_with_flag() -> None:
    # Valid configuration: returns None, raises nothing, does no I/O.
    assert fgc.validate_lab_target(LAB_C2, lab_enabled=True) is None


# --- AC3: each check-in opens a new connection (N check-ins -> N connections) -----------------


def test_each_checkin_opens_a_new_connection(server: _CountingServer) -> None:
    host, port = _host_port(server)
    n = 4

    sent = fgc.run_check_ins(host, port, count=n, interval=0)

    assert sent == n
    # N check-ins -> exactly N accepted TCP connections and N GET requests: no keep-alive reuse.
    assert server.connections == n
    assert server.requests == [("GET", 0)] * n


def test_single_checkin_is_one_connection(server: _CountingServer) -> None:
    host, port = _host_port(server)
    assert fgc.check_in(host, port) == 200
    assert server.connections == 1
    assert server.requests == [("GET", 0)]
    # A second call opens a second, independent connection.
    fgc.check_in(host, port)
    assert server.connections == 2


def test_checkin_interval_default_is_five_seconds() -> None:
    assert fgc.CHECKIN_INTERVAL_S == 5.0


# --- AC4: the upload sends ~20 MB exactly once ------------------------------------------------


def test_upload_posts_once_with_the_configured_size(server: _CountingServer) -> None:
    host, port = _host_port(server)
    size = 2048  # small, for a fast test

    status = fgc.upload(host, port, size=size)

    assert status == 200
    assert server.connections == 1
    assert server.requests == [("POST", size)]  # exactly one POST, body length == size


def test_default_upload_size_is_about_twenty_megabytes() -> None:
    twenty_mb = 20 * 1024 * 1024
    assert fgc.UPLOAD_SIZE_BYTES == twenty_mb
    # Sanity band: comfortably "about 20 MB" (18-22 MB).
    assert 18 * 1024 * 1024 <= fgc.UPLOAD_SIZE_BYTES <= 22 * 1024 * 1024


# --- AC5: generated domains are deterministic per seed and look random ------------------------


def test_same_seed_gives_same_domains() -> None:
    assert fgc.generate_domains(42, 10) == fgc.generate_domains(42, 10)


def test_different_seeds_give_different_domains() -> None:
    assert fgc.generate_domains(1, 10) != fgc.generate_domains(2, 10)


def test_generation_does_not_disturb_global_rng() -> None:
    import random

    random.seed(99)
    expected = [random.random() for _ in range(3)]
    random.seed(99)
    fgc.generate_domains(12345, 20)  # must not consume the global RNG stream
    assert [random.random() for _ in range(3)] == expected


def test_domains_look_random() -> None:
    domains = fgc.generate_domains(2024, 25)
    assert len(domains) == 25
    for domain in domains:
        label, _, tld = domain.rpartition(".")
        assert tld in fgc.DOMAIN_TLDS
        assert fgc.DOMAIN_LABEL_MIN_LEN <= len(label) <= fgc.DOMAIN_LABEL_MAX_LEN
        assert set(label) <= set(fgc.DOMAIN_ALPHABET)  # lowercase letters only
        # Random-looking, not a dictionary word: several distinct letters and real entropy.
        assert len(set(label)) >= 5
        counts = {c: label.count(c) for c in set(label)}
        entropy = -sum(
            (k / len(label)) * math.log2(k / len(label)) for k in counts.values()
        )
        assert entropy >= 2.5  # a true word of this length sits well below this


def test_generate_domains_count_zero_and_negative() -> None:
    assert fgc.generate_domains(1, 0) == []
    with pytest.raises(ValueError):
        fgc.generate_domains(1, -1)


# --- DNS goes straight to the lab DNS, one fresh socket per lookup (found in #58) -----------
# Through the Windows resolver the lookups were sent by svchost.exe (allowlisted), and Windows'
# own DNS had to point at the wildcard lab DNS, which sent every app's traffic to the C2.


def _parse_dns_query(packet: bytes) -> tuple[int, int, int, str, int, int]:
    """(id, flags, qdcount, qname, qtype, qclass) of a one-question DNS query."""
    query_id, flags, qdcount = struct.unpack(">HHH", packet[:6])
    labels, i = [], 12
    while packet[i]:
        labels.append(packet[i + 1 : i + 1 + packet[i]].decode("ascii"))
        i += 1 + packet[i]
    qtype, qclass = struct.unpack(">HH", packet[i + 1 : i + 5])
    return query_id, flags, qdcount, ".".join(labels), qtype, qclass


class _UdpDnsServer:
    """A real UDP socket on 127.0.0.1 that records each query and its source port."""

    def __init__(self, answer: bool = True) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.answer = answer
        self.queries: list[tuple[int, bytes]] = []  # (client source port, packet)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            self.queries.append((addr[1], data))
            if self.answer:
                self.sock.sendto(data[:2] + b"\x81\x80" + data[4:], addr)  # echo as a reply

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self.sock.close()


@pytest.fixture
def dns_server() -> Iterator[_UdpDnsServer]:
    srv = _UdpDnsServer()
    try:
        yield srv
    finally:
        srv.close()


def test_build_dns_query_is_one_a_question_for_the_domain() -> None:
    packet = fgc.build_dns_query("qwhzkxlmpv.xyz", 0x1234)
    assert _parse_dns_query(packet) == (0x1234, 0x0100, 1, "qwhzkxlmpv.xyz", 1, 1)


def test_each_lookup_goes_to_the_given_dns_server_from_a_fresh_socket(
    dns_server: _UdpDnsServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fgc.socket, "getaddrinfo", _NetworkTripwire())  # never the OS resolver
    domains = fgc.generate_domains(7, 5)

    sent = fgc.resolve_domains(domains, "127.0.0.1", port=dns_server.port, timeout=1.0)

    assert sent == 5
    assert [_parse_dns_query(p)[3] for _, p in dns_server.queries] == domains
    # One socket per lookup -> a distinct source port each time -> one flow per lookup.
    assert len({src_port for src_port, _ in dns_server.queries}) == 5


def test_unanswered_lookup_times_out_and_the_rest_still_go_out() -> None:
    srv = _UdpDnsServer(answer=False)
    try:
        sent = fgc.resolve_domains(["aaaaaaaaaa.com", "bbbbbbbbbb.net"], "127.0.0.1",
                                   port=srv.port, timeout=0.2)
        assert sent == 2
        deadline = time.monotonic() + 5.0  # wait for the server thread; no fixed sleep
        while len(srv.queries) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(srv.queries) == 2
    finally:
        srv.close()


def _closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now: connects are refused
    return port


def test_failed_check_ins_are_logged_and_the_loop_keeps_going() -> None:
    # After HomeSOC quarantines the app every check-in fails; the sim must keep trying so
    # check-ins resume after Undo (#58 step 8) instead of crashing on the first refusal.
    assert fgc.run_check_ins("127.0.0.1", _closed_port(), count=3, interval=0) == 3


def test_main_carries_on_to_check_ins_when_the_upload_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(fgc.ENV_HOMESOC_LAB, "1")
    monkeypatch.setenv(fgc.ENV_LAB_C2, LAB_C2)
    lookups: list[tuple[list[str], str]] = []
    check_ins: list[str] = []

    def refused_upload(*args: object, **kwargs: object) -> int:
        raise ConnectionRefusedError("C2 down")

    monkeypatch.setattr(fgc, "resolve_domains", lambda d, server: lookups.append((d, server)))
    monkeypatch.setattr(fgc, "upload", refused_upload)
    monkeypatch.setattr(fgc, "run_check_ins",
                        lambda host, port, **kw: check_ins.append(host) or 1)

    assert fgc.main(["--checkins", "1"]) == 0
    assert lookups[0][1] == LAB_C2  # lookups are sent to the lab DNS on the C2 address
    assert check_ins == [LAB_C2]
