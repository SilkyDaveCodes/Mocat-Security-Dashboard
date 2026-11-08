"""#68: short flows keep their process (DNS lookups and beacon check-ins of the fake malware).

Found in the #62 live run: the fake malware's DGA lookups and about half of its check-ins were
``unknown pid=-1``, so the DGA alert could never quarantine it and the beacon detector (keyed
per process) never reached 6 starts. These tests replay that run on any OS: a synthetic socket
timeline stands in for ``psutil.net_connections`` (what the kernel lists at each instant), the
real :class:`PortHistory` polls it on a 50 ms schedule, NFStream-style flows are reported
``idle_timeout`` (10 s) after their socket closed, and the real resolver + BeaconDetector run.
"""

from __future__ import annotations

import logging
import socket
import sys
import types
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import ip_address
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent import capture, config
from agent.capture import LocalAddresses, PortHistory, PortPidResolver, SocketSighting
from agent.config import Allowlist
from agent.detectors.beacon import BeaconDetector
from agent.events import FlowEvent
from lab.fake_malware import freegamecheats as fgc

PC_IP = "192.168.56.10"
LAB_C2 = "192.168.56.20"
PC_IPS = frozenset({ip_address(PC_IP)})
MALWARE_PID = 4100
MALWARE = "python.exe"
EPOCH_MS = 1_700_000_000_000
POLL_S = 0.05            # config.yaml capture.port_poll_interval_s
POLL_PHASE_S = 0.013     # the poller's first poll; any phase works
IDLE_TIMEOUT_S = 10.0    # config.yaml capture.idle_timeout: a flow is reported this long after
KEEP_S = 60.0            # config.yaml capture.port_history_s
TCP, UDP = socket.SOCK_STREAM, socket.SOCK_DGRAM


@dataclass(frozen=True)
class Sock:
    """One socket on the PC: who owns which local port, from ``opened`` to ``closed`` (s)."""

    sock_type: int
    port: int
    pid: int
    remote: tuple[str, int] | None   # what psutil reports as raddr (None: UDP on Windows)
    opened: float
    closed: float
    dst: tuple[str, int]             # where the flow's packets went

    def sighting(self) -> SocketSighting:
        remote = (self.sock_type, *self.remote) if self.remote else None
        return SocketSighting(self.sock_type, self.port, self.pid, remote)  # type: ignore[arg-type]

    def flow(self) -> SimpleNamespace:
        """The NFStream flow for this socket, with no process name (helper off, #68)."""
        return SimpleNamespace(
            bidirectional_first_seen_ms=EPOCH_MS + int(self.opened * 1000),
            bidirectional_last_seen_ms=EPOCH_MS + int(self.closed * 1000),
            system_process_name="", system_process_pid=0,
            src_ip=PC_IP, src_port=self.port, dst_ip=self.dst[0], dst_port=self.dst[1],
            protocol=6 if self.sock_type == TCP else 17,
            src2dst_bytes=100, dst2src_bytes=200, bidirectional_packets=4,
        )


class Timeline:
    """What ``psutil.net_connections`` would list at the current (fake) time."""

    def __init__(self, socks: list[Sock]) -> None:
        self.socks = socks
        self.now = 0.0
        self.polls = 0

    def table(self) -> list[SocketSighting]:
        self.polls += 1
        return [s.sighting() for s in self.socks if s.opened <= self.now < s.closed]


def _fixed() -> LocalAddresses:
    return LocalAddresses(refresh_s=60, source=lambda: PC_IPS)


@pytest.fixture
def names(monkeypatch: pytest.MonkeyPatch) -> dict[int, str]:
    """PID -> process name (psutil.Process(pid).name()); a missing PID has exited."""
    table: dict[int, str] = {MALWARE_PID: MALWARE, 5200: "chrome.exe", 5300: "spotify.exe"}

    def name_of(pid: int) -> str | None:
        return table.get(pid)

    monkeypatch.setattr(capture, "_process_name", name_of)
    return table


def replay(socks: list[Sock], monkeypatch: pytest.MonkeyPatch, *,
           endpoint_fallback: bool = True) -> tuple[list[FlowEvent], set[int]]:
    """Run the poller and the resolver over the timeline.

    Returns every flow's FlowEvent (in report order) and the local ports the poller saw.
    """
    timeline = Timeline(socks)
    monkeypatch.setattr(capture, "_socket_table", timeline.table)   # history + live snapshot
    history = PortHistory(POLL_S, KEEP_S, clock=lambda: timeline.now)
    resolver = PortPidResolver(2.0, _fixed(), clock=lambda: timeline.now, history=history,
                               endpoint_fallback=endpoint_fallback)
    seen_ports: set[int] = set()

    end = max(s.closed for s in socks) + IDLE_TIMEOUT_S + 1
    steps: list[tuple[float, int, Any]] = []
    t = POLL_PHASE_S
    while t < end:
        steps.append((t, 0, None))
        t += POLL_S
    steps += [(s.closed + IDLE_TIMEOUT_S, 1, s) for s in socks]
    events: list[FlowEvent] = []
    for when, kind, sock in sorted(steps, key=lambda step: (step[0], step[1])):
        timeline.now = when
        if kind == 0:
            seen_ports.update(s.port for s in timeline.table())
            history.poll_once()
        else:
            events.append(capture.to_flow_event(sock.flow(), PC_IPS, resolver))
    return events, seen_ports


UPLOAD_START_S = 4.0
UPLOAD_END_S = 4.4
INTERVAL_S = fgc.CHECKIN_INTERVAL_S


def fake_malware_run(dns_lifetime_s: float, n_checkins: int = 6, *,
                     on_schedule: bool = True) -> list[Sock]:
    """The #62 run: 8 DGA lookups, one 20 MB upload, then a check-in every 5 s.

    Check-ins live 20 ms each (connect, GET, response, close on the lab network) and start at
    a phase that puts every other one between two polls, like the live run. ``on_schedule``:
    the first check-in starts one interval after the upload started (the fixed simulator);
    else right after the upload ended (the #62 simulator).
    """
    socks: list[Sock] = []
    t = 1.02
    for i in range(8):        # resolve_domains: one fresh UDP socket per lookup, sendto only
        socks.append(Sock(UDP, 61000 + i, MALWARE_PID, None, t, t + dns_lifetime_s,
                          (LAB_C2, 53)))
        t += dns_lifetime_s + 0.001
    socks.append(Sock(TCP, 50100, MALWARE_PID, (LAB_C2, 8080), UPLOAD_START_S, UPLOAD_END_S,
                      (LAB_C2, 8080)))
    first = UPLOAD_START_S + INTERVAL_S if on_schedule else UPLOAD_END_S + 0.01
    for k in range(n_checkins):
        start = first + INTERVAL_S * k + 0.03 * (k % 2)  # odd ones fall between polls
        socks.append(Sock(TCP, 50101 + k, MALWARE_PID, (LAB_C2, 8080), start, start + 0.02,
                          (LAB_C2, 8080)))
    return socks


def _attributed(events: list[FlowEvent], dst_port: int) -> tuple[int, int]:
    hits = [e for e in events if e.dst_port == dst_port]
    return sum(1 for e in hits if (e.process, e.pid) == (MALWARE, MALWARE_PID)), len(hits)


# --- the #62 run, replayed ----------------------------------------------------------------------


def test_the_62_bug_reproduces_with_1ms_dns_sockets_and_no_endpoint_fallback(
    names: dict[int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The old behaviour: what the VM log showed (DNS all unknown, check-ins split).
    events, _ = replay(fake_malware_run(dns_lifetime_s=0.001), monkeypatch,
                       endpoint_fallback=False)
    assert _attributed(events, 53) == (0, 8)
    good, total = _attributed(events, 8080)
    assert 0 < good < total


def test_dns_lookups_held_open_by_the_simulator_are_all_attributed(
    names: dict[int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows lists UDP sockets without a remote address, and the flow arrives 10 s after the
    # socket closed: only a poll that ran while it was open can name it.
    events, _ = replay(fake_malware_run(fgc.DNS_SOCKET_MIN_LIFETIME_S), monkeypatch)
    good, total = _attributed(events, 53)
    assert total == 8
    assert good / total >= 0.9
    assert good == total


def test_check_ins_missed_by_the_poller_get_the_app_seen_on_the_same_endpoint(
    names: dict[int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    socks = fake_malware_run(fgc.DNS_SOCKET_MIN_LIFETIME_S)
    events, seen = replay(socks, monkeypatch)
    checkin_ports = {s.port for s in socks if s.dst == (LAB_C2, 8080) and s.port != 50100}
    assert checkin_ports - seen, "the scenario must include check-ins no poll ever saw"
    good, total = _attributed(events, 8080)
    assert total == 7                       # the upload and the 6 check-ins
    assert good == total                    # >= 90% required; all of them here


def test_six_check_ins_all_attributed_make_the_real_beacon_detector_fire(
    names: dict[int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    events, _ = replay(fake_malware_run(fgc.DNS_SOCKET_MIN_LIFETIME_S, n_checkins=6),
                       monkeypatch)
    signals = _beacon_signals(events)
    assert signals, "the beacon detector must fire on the check-ins"
    assert {(s.detector, s.process, s.pid, s.target) for s in signals} == {
        ("beacon", MALWARE, MALWARE_PID, LAB_C2)
    }


def _beacon_signals(events: list[FlowEvent]) -> list[Any]:
    beacon = BeaconDetector(config.load(), allowlist=Allowlist(frozenset()))
    return [s for e in sorted(events, key=lambda e: e.ts_ms) for s in beacon.process(e)]


def test_without_the_fix_the_beacon_detector_stays_silent(
    names: dict[int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The #62 run: check-ins split between python.exe and unknown, upload off the beat.
    events, _ = replay(fake_malware_run(0.001, n_checkins=6, on_schedule=False), monkeypatch,
                       endpoint_fallback=False)
    assert _beacon_signals(events) == []


def test_an_upload_off_the_beat_hides_the_beacon_even_when_attribution_is_right(
    names: dict[int, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Second cause found while replaying #62: the upload goes to the same C2 port, so it is one
    # more start for (python.exe, C2, 8080); a ~1 s gap before 5 s gaps -> CV too high.
    events, _ = replay(fake_malware_run(fgc.DNS_SOCKET_MIN_LIFETIME_S, n_checkins=6,
                                        on_schedule=False), monkeypatch)
    assert _attributed(events, 8080) == (7, 7)
    assert _beacon_signals(events) == []


# --- endpoint fallback rules --------------------------------------------------------------------


def _history_with(sightings: list[SocketSighting], now: list[float]) -> PortHistory:
    history = PortHistory(POLL_S, KEEP_S, clock=lambda: now[0], read=lambda: sightings)
    history.poll_once()
    return history


def _flow(**overrides: Any) -> SimpleNamespace:
    attrs: dict[str, Any] = dict(system_process_name="", system_process_pid=0, src_ip=PC_IP,
                                 src_port=50999, dst_ip=LAB_C2, dst_port=8080, protocol=6)
    attrs.update(overrides)
    return SimpleNamespace(**attrs)


@pytest.fixture
def empty_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live psutil snapshot lists nothing (every short socket already closed)."""
    monkeypatch.setattr(capture, "_socket_table", lambda: [])


def _seen_on_c2(pid: int, port: int = 50100) -> SocketSighting:
    return SocketSighting(TCP, port, pid, (TCP, LAB_C2, 8080))


def test_two_apps_on_the_same_endpoint_is_ambiguous_and_stays_unknown(
    names: dict[int, str], empty_snapshot: None
) -> None:
    now = [0.0]
    history = _history_with([_seen_on_c2(MALWARE_PID), _seen_on_c2(5200, 50200)], now)
    resolver = PortPidResolver(2.0, _fixed(), clock=lambda: now[0], history=history)
    event = capture.to_flow_event(_flow(), PC_IPS, resolver)
    assert (event.process, event.pid) == ("unknown", -1)


def test_endpoint_fallback_is_never_used_for_inbound_flows(
    names: dict[int, str], empty_snapshot: None
) -> None:
    now = [0.0]
    # Seen: python.exe talking to the attacker's port 40000. An inbound flow from that same
    # attacker IP:port to a closed port on this PC must not be pinned on python.exe.
    history = _history_with([SocketSighting(TCP, 50100, MALWARE_PID, (TCP, LAB_C2, 40000))],
                            now)
    resolver = PortPidResolver(2.0, _fixed(), clock=lambda: now[0], history=history)
    inbound = _flow(src_ip=LAB_C2, src_port=40000, dst_ip=PC_IP, dst_port=445)
    event = capture.to_flow_event(inbound, PC_IPS, resolver)
    assert event.direction == "inbound"
    assert (event.process, event.pid) == ("unknown", -1)


def test_endpoint_fallback_can_be_switched_off(
    names: dict[int, str], empty_snapshot: None
) -> None:
    now = [0.0]
    history = _history_with([_seen_on_c2(MALWARE_PID)], now)
    on = PortPidResolver(2.0, _fixed(), clock=lambda: now[0], history=history)
    off = PortPidResolver(2.0, _fixed(), clock=lambda: now[0], history=history,
                          endpoint_fallback=False)
    assert capture.to_flow_event(_flow(), PC_IPS, on).process == MALWARE
    assert capture.to_flow_event(_flow(), PC_IPS, off).process == "unknown"


def test_endpoint_sightings_expire_after_keep_s(names: dict[int, str]) -> None:
    now = [0.0]
    sightings = [_seen_on_c2(MALWARE_PID)]
    history = PortHistory(POLL_S, KEEP_S, clock=lambda: now[0], read=lambda: sightings)
    history.poll_once()
    sightings.clear()
    now[0] = KEEP_S - 1
    history.poll_once()
    assert history.lookup_endpoint((TCP, LAB_C2, 8080)) == (MALWARE, MALWARE_PID)
    now[0] = KEEP_S + 1
    assert history.lookup_endpoint((TCP, LAB_C2, 8080)) is None
    history.poll_once()
    assert history._endpoints == {}


def test_an_old_owner_of_the_endpoint_ages_out_and_the_new_one_is_used(
    names: dict[int, str]
) -> None:
    now = [0.0]
    sightings = [_seen_on_c2(5200)]
    history = PortHistory(POLL_S, KEEP_S, clock=lambda: now[0], read=lambda: sightings)
    history.poll_once()
    now[0] = 30.0
    sightings[:] = [_seen_on_c2(MALWARE_PID, 50300)]
    history.poll_once()
    assert history.lookup_endpoint((TCP, LAB_C2, 8080)) is None     # both seen in the window
    now[0] = KEEP_S + 1
    assert history.lookup_endpoint((TCP, LAB_C2, 8080)) == (MALWARE, MALWARE_PID)


def test_endpoint_match_needs_the_same_socket_type(
    names: dict[int, str], empty_snapshot: None
) -> None:
    now = [0.0]
    history = _history_with([_seen_on_c2(MALWARE_PID)], now)
    resolver = PortPidResolver(2.0, _fixed(), clock=lambda: now[0], history=history)
    udp = _flow(protocol=17)
    assert capture.to_flow_event(udp, PC_IPS, resolver).process == "unknown"


# --- psutil table: remote addresses -------------------------------------------------------------


def test_socket_table_keeps_tcp_remotes_and_has_none_for_windows_udp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psutil

    def conn(sock_type: int, port: int, pid: int | None, raddr: Any) -> SimpleNamespace:
        return SimpleNamespace(type=sock_type, laddr=SimpleNamespace(ip=PC_IP, port=port),
                               raddr=raddr, pid=pid)

    conns = [
        conn(TCP, 50100, MALWARE_PID, SimpleNamespace(ip="::ffff:192.168.56.20", port=8080)),
        conn(UDP, 61000, MALWARE_PID, ()),                         # Windows: never a raddr
        conn(TCP, 3389, 888, SimpleNamespace(ip="0.0.0.0", port=0)),   # listening
        conn(TCP, 50101, 0, SimpleNamespace(ip=LAB_C2, port=8080)),    # TIME_WAIT: PID 0
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
    assert capture._socket_table() == [
        SocketSighting(TCP, 50100, MALWARE_PID, (TCP, LAB_C2, 8080)),
        SocketSighting(UDP, 61000, MALWARE_PID, None),
        SocketSighting(TCP, 3389, 888, None),
    ]
    assert capture._socket_owners() == {(TCP, 50100): MALWARE_PID, (UDP, 61000): MALWARE_PID,
                                        (TCP, 3389): 888}


# --- NFStream's process helper (WinError 6) -----------------------------------------------------


@pytest.fixture
def fake_nfstream(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    module = types.ModuleType("nfstream")
    streamer_cls = MagicMock(name="NFStreamer")
    module.NFStreamer = streamer_cls  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "nfstream", module)
    return streamer_cls


def test_nfstream_helper_is_not_started_by_default(
    fake_nfstream: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = config.load()
    assert cfg["capture"]["nfstream_process_visibility"] is False
    with caplog.at_level(logging.INFO, logger="agent.capture"):
        capture.make_streamer(cfg)
    # system_visibility_mode=0: NFStream never spawns system_socket_worflow, so it can't crash.
    assert fake_nfstream.call_args.kwargs["system_visibility_mode"] == 0
    assert caplog.text.count("process visibility is off") == 1


def test_nfstream_helper_can_be_switched_back_on_with_one_warning(
    fake_nfstream: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = {"capture": {"interface": "Ethernet", "idle_timeout": 10, "active_timeout": 30,
                       "nfstream_process_visibility": True}}
    with caplog.at_level(logging.WARNING, logger="agent.capture"):
        capture.make_streamer(cfg)
    assert fake_nfstream.call_args.kwargs["system_visibility_mode"] == 1
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "#68" in warnings[0].getMessage()


def test_nfstream_time_wait_name_is_replaced_by_the_real_owner() -> None:
    # NFStream's helper names a TIME_WAIT socket "System Idle Process" with PID 0.
    flow = _flow(system_process_name="System Idle Process", system_process_pid=0)
    event = capture.to_flow_event(flow, PC_IPS, lambda f: (MALWARE, MALWARE_PID))
    assert (event.process, event.pid) == (MALWARE, MALWARE_PID)
    # No owner found: NFStream's name is kept, without a PID (as before).
    kept = capture.to_flow_event(flow, PC_IPS, lambda f: None)
    assert (kept.process, kept.pid) == ("System Idle Process", -1)


def test_named_flow_with_a_real_pid_never_asks_the_fallback() -> None:
    def boom(flow: Any) -> tuple[str, int]:
        raise AssertionError("fallback must not run")

    event = capture.to_flow_event(_flow(system_process_name="chrome.exe",
                                        system_process_pid=5200), PC_IPS, boom)
    assert (event.process, event.pid) == ("chrome.exe", 5200)


def test_run_reads_endpoint_fallback_from_config(
    monkeypatch: pytest.MonkeyPatch, names: dict[int, str]
) -> None:
    monkeypatch.setattr(capture, "_socket_table", lambda: [])
    built: list[bool] = []
    real_init = PortPidResolver.__init__

    def spy(self: Any, *args: Any, **kwargs: Any) -> None:
        built.append(kwargs["endpoint_fallback"])
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(PortPidResolver, "__init__", spy)

    class Bus:
        def publish_threadsafe(self, event: Any) -> None:
            pass

    for value in (False, True):
        capture.run(Bus(), {"capture": {"endpoint_fallback": value}},  # type: ignore[arg-type]
                    streamer_factory=lambda c: [], local_addresses=_fixed())
    capture.run(Bus(), {}, streamer_factory=lambda c: [],  # type: ignore[arg-type]
                local_addresses=_fixed())
    assert built == [False, True, True]
    assert config.load()["capture"]["endpoint_fallback"] is True


# --- the simulator keeps each DNS socket open long enough to be polled (lab, #68) --------------


class _FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


class _FakeUdp:
    """Records when each socket is opened and closed (fake clock); answers instantly."""

    log: list[tuple[float, float]] = []
    clock: _FakeClock
    answer = True

    def __init__(self, *args: Any) -> None:
        self.opened = self.clock.t

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        assert addr == (LAB_C2, fgc.LAB_DNS_PORT)

    def recvfrom(self, n: int) -> tuple[bytes, Any]:
        self.clock.t += 0.001
        if not self.answer:
            self.clock.t += self.timeout
            raise TimeoutError("timed out")
        return b"answer", (LAB_C2, fgc.LAB_DNS_PORT)

    def close(self) -> None:
        self.log.append((self.opened, self.clock.t))


@pytest.fixture
def fake_udp(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_FakeUdp]]:
    clock = _FakeClock()
    sock_cls = type("Udp", (_FakeUdp,), {"log": [], "clock": clock, "answer": True})
    monkeypatch.setattr(fgc.socket, "socket", sock_cls)
    monkeypatch.setattr(fgc.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(fgc.time, "sleep", clock.sleep)
    yield sock_cls


def test_simulator_holds_each_dns_socket_for_several_port_polls(
    fake_udp: type[_FakeUdp],
) -> None:
    sent = fgc.resolve_domains(fgc.generate_domains(1, 8), LAB_C2)
    assert sent == 8
    assert len(fake_udp.log) == 8
    poll_s = config.load()["capture"]["port_poll_interval_s"]
    for opened, closed in fake_udp.log:
        assert closed - opened >= fgc.DNS_SOCKET_MIN_LIFETIME_S
    assert fgc.DNS_SOCKET_MIN_LIFETIME_S >= 3 * poll_s   # several polls fit in its lifetime


def test_simulator_starts_the_first_check_in_one_interval_after_the_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    clock.t = 100.0
    starts: list[tuple[str, float]] = []
    monkeypatch.setenv(fgc.ENV_HOMESOC_LAB, "1")
    monkeypatch.setenv(fgc.ENV_LAB_C2, LAB_C2)
    monkeypatch.setattr(fgc.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(fgc.time, "sleep", clock.sleep)
    monkeypatch.setattr(fgc, "resolve_domains", lambda d, server: len(d))

    def upload(*args: Any, **kwargs: Any) -> int:
        starts.append(("upload", clock.t))
        clock.t += 0.7                       # 20 MB over the lab network
        return 200

    def run_check_ins(host: str, port: int, **kwargs: Any) -> int:
        starts.append(("checkin", clock.t))
        return 1

    monkeypatch.setattr(fgc, "upload", upload)
    monkeypatch.setattr(fgc, "run_check_ins", run_check_ins)
    assert fgc.main(["--checkins", "6"]) == 0
    (_, up), (_, first) = starts
    assert first - up == pytest.approx(fgc.CHECKIN_INTERVAL_S)


@pytest.mark.parametrize(("elapsed", "waited"), [(0.7, 4.3), (5.0, 0.0), (6.0, 4.0), (0.0, 5.0)])
def test_wait_on_schedule_sleeps_to_the_next_beat(
    monkeypatch: pytest.MonkeyPatch, elapsed: float, waited: float
) -> None:
    clock = _FakeClock()
    monkeypatch.setattr(fgc.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(fgc.time, "sleep", clock.sleep)
    clock.t = elapsed
    fgc.wait_on_schedule(0.0, 5.0)
    assert clock.t - elapsed == pytest.approx(waited)


def test_simulator_does_not_wait_extra_after_a_timed_out_lookup(
    fake_udp: type[_FakeUdp],
) -> None:
    fake_udp.answer = False
    fgc.resolve_domains(["aaaaaaaaaa.com"], LAB_C2, timeout=1.0)
    ((opened, closed),) = fake_udp.log
    assert closed - opened == pytest.approx(1.001)   # the timeout already kept it open
