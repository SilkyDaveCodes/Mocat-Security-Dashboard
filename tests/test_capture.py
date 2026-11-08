"""Tests for agent.capture: NFlow -> FlowEvent mapping, direction, streamer kwargs, run loop.

NFStream is not installed here; fake flows are SimpleNamespace objects and the streamer is a
patched module / factory.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import subprocess
import sys
import threading
import time
import types
from ipaddress import ip_address
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent import capture, config
from agent.bus import Bus
from agent.capture import (
    FEATURE_FIELDS,
    CaptureError,
    LocalAddresses,
    direction_of,
    is_local_address,
    to_flow_event,
)
from agent.config import REPO_ROOT
from agent.events import FlowEvent

TIMEOUT_S = 2.0

# This PC's own addresses in the tests. The lab PC is 192.168.56.10; the lab attacker/C2 is
# 192.168.56.20 (CLAUDE.md §8), another private address on the same network.
PC_IPS = frozenset({ip_address("192.168.56.10"), ip_address("fe80::1")})
LAB_ATTACKER = "192.168.56.20"


def _fixed() -> LocalAddresses:
    return LocalAddresses(refresh_s=60, source=lambda: PC_IPS)


def _flow(**overrides: Any) -> SimpleNamespace:
    """A fake NFStream 6.x NFlow with every mapped attribute and a few statistics."""
    attrs: dict[str, Any] = dict(
        bidirectional_first_seen_ms=1_700_000_000_000,
        bidirectional_last_seen_ms=1_700_000_005_000,
        system_process_name="chrome.exe",
        system_process_pid=4242,
        src_ip="192.168.56.10",
        src_port=51515,
        dst_ip="142.250.80.4",
        dst_port=443,
        protocol=6,
        requested_server_name="www.google.com",
        application_name="TLS.Google",
        src2dst_bytes=1234,
        dst2src_bytes=56789,
        bidirectional_packets=42,
        # statistics (subset of FEATURE_FIELDS)
        bidirectional_duration_ms=5000,
        bidirectional_bytes=58023,
        src2dst_packets=20,
        dst2src_packets=22,
        bidirectional_mean_ps=1381.5,
        bidirectional_stddev_piat_ms=12.25,
        src2dst_syn_packets=1,
        dst2src_rst_packets=0,
        # identifiers that must never be features
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
    )
    attrs.update(overrides)
    return SimpleNamespace(**attrs)


# --- to_flow_event: field mapping -------------------------------------------------------------


def test_to_flow_event_maps_every_field() -> None:
    event = to_flow_event(_flow(), PC_IPS)
    assert event == FlowEvent(
        ts_ms=1_700_000_000_000,
        end_ms=1_700_000_005_000,
        process="chrome.exe",
        pid=4242,
        exe_path=None,
        src_ip="192.168.56.10",
        src_port=51515,
        dst_ip="142.250.80.4",
        dst_port=443,
        protocol=6,
        hostname="www.google.com",
        app_proto="TLS.Google",
        bytes_out=1234,
        bytes_in=56789,
        packets=42,
        direction="outbound",
        features={
            "bidirectional_duration_ms": 5000,
            "bidirectional_packets": 42,
            "bidirectional_bytes": 58023,
            "src2dst_packets": 20,
            "src2dst_bytes": 1234,
            "dst2src_packets": 22,
            "dst2src_bytes": 56789,
            "bidirectional_mean_ps": 1381.5,
            "bidirectional_stddev_piat_ms": 12.25,
            "src2dst_syn_packets": 1,
            "dst2src_rst_packets": 0,
        },
    )
    assert event.type == "flow"


def test_bytes_out_is_src2dst_and_bytes_in_is_dst2src() -> None:
    event = to_flow_event(_flow(src2dst_bytes=7, dst2src_bytes=900), PC_IPS)
    assert (event.bytes_out, event.bytes_in) == (7, 900)


@pytest.mark.parametrize("field", ["requested_server_name", "application_name"])
@pytest.mark.parametrize("empty", ["", "   ", None])
def test_empty_hostname_and_app_proto_map_to_none(field: str, empty: Any) -> None:
    event = to_flow_event(_flow(**{field: empty}), PC_IPS)
    assert getattr(event, "hostname" if field == "requested_server_name" else "app_proto") is None


def test_missing_hostname_and_app_proto_attributes_map_to_none() -> None:
    flow = _flow()
    del flow.requested_server_name
    del flow.application_name
    event = to_flow_event(flow, PC_IPS)
    assert event.hostname is None
    assert event.app_proto is None


@pytest.mark.parametrize("pid", [0, -1, None])
def test_nfstream_unknown_pid_normalizes_to_minus_one(pid: Any) -> None:
    event = to_flow_event(_flow(system_process_pid=pid), PC_IPS)
    assert event.process == "chrome.exe"
    assert event.pid == -1


@pytest.mark.parametrize("name", ["", None])
def test_empty_process_name_maps_to_unknown_and_minus_one(name: Any) -> None:
    event = to_flow_event(_flow(system_process_name=name, system_process_pid=4242), PC_IPS)
    assert (event.process, event.pid) == ("unknown", -1)


def test_missing_process_attributes_map_to_defaults() -> None:
    flow = _flow()
    del flow.system_process_name
    del flow.system_process_pid
    event = to_flow_event(flow, PC_IPS)
    assert (event.process, event.pid) == ("unknown", -1)


def test_process_fallback_hook_is_used_only_for_empty_names() -> None:
    calls: list[Any] = []

    def fallback(flow: Any) -> tuple[str, int]:
        calls.append(flow)
        return ("svchost.exe", 900)

    empty = _flow(system_process_name="")
    mapped = to_flow_event(empty, PC_IPS, fallback)
    assert (mapped.process, mapped.pid) == ("svchost.exe", 900)
    to_flow_event(empty, PC_IPS, fallback)  # second call: the hook runs again for empty names
    named = to_flow_event(_flow(), PC_IPS, fallback)
    assert named.process == "chrome.exe"
    assert calls == [empty, empty]


# --- features ---------------------------------------------------------------------------------


def test_feature_fields_never_include_ips_ports_or_macs() -> None:
    banned = ("ip", "port", "mac")
    for name in FEATURE_FIELDS:
        parts = name.split("_")
        assert not any(b in parts for b in banned), name
    assert len(FEATURE_FIELDS) == len(set(FEATURE_FIELDS))


def test_feature_fields_cover_the_documented_statistics() -> None:
    for expected in (
        "bidirectional_duration_ms", "src2dst_bytes", "dst2src_packets",
        "bidirectional_min_ps", "src2dst_max_ps", "dst2src_stddev_ps",
        "bidirectional_mean_piat_ms", "dst2src_max_piat_ms",
        "bidirectional_syn_packets", "src2dst_rst_packets", "dst2src_fin_packets",
    ):
        assert expected in FEATURE_FIELDS


def test_features_skip_missing_attributes_and_exclude_identifiers() -> None:
    event = to_flow_event(SimpleNamespace(src_ip="10.0.0.5", src2dst_bytes=10, src_mac="x"), PC_IPS)
    assert event.features == {"src2dst_bytes": 10}
    assert not {"src_ip", "dst_ip", "src_port", "dst_port", "src_mac"} & event.features.keys()


def test_bare_object_maps_to_defaults_without_crashing() -> None:
    event = to_flow_event(SimpleNamespace(), PC_IPS)
    assert event.process == "unknown"
    assert event.pid == -1
    assert event.hostname is None
    assert event.features == {}
    assert event.direction == "inbound"  # empty src_ip is not a local address


# --- direction --------------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["192.168.56.10", "fe80::1", "127.0.0.1", "127.5.5.5", "::1"])
def test_flow_started_by_this_pc_is_outbound(ip: str) -> None:
    assert is_local_address(ip, PC_IPS) is True
    assert direction_of(ip, PC_IPS) == "outbound"
    assert to_flow_event(_flow(src_ip=ip), PC_IPS).direction == "outbound"


def test_flow_started_by_the_lab_attacker_is_inbound() -> None:
    # A portscan/brute force from another machine on the same private network must reach the
    # inbound flow_model (#48), so a private source that isn't this PC is inbound.
    event = to_flow_event(_flow(src_ip=LAB_ATTACKER, dst_ip="192.168.56.10", dst_port=22), PC_IPS)
    assert event.direction == "inbound"


@pytest.mark.parametrize(
    "ip",
    ["192.168.56.20", "192.168.1.50", "10.1.2.3", "172.16.0.9", "169.254.10.20", "fe80::2",
     "fd00::1234", "8.8.8.8", "142.250.80.4", "2001:4860::8888"],
)
def test_flow_started_by_any_other_machine_is_inbound(ip: str) -> None:
    assert is_local_address(ip, PC_IPS) is False
    assert direction_of(ip, PC_IPS) == "inbound"
    assert to_flow_event(_flow(src_ip=ip), PC_IPS).direction == "inbound"


@pytest.mark.parametrize("ip", ["", "not-an-ip", "999.1.1.1"])
def test_unparseable_source_is_not_local(ip: str) -> None:
    assert is_local_address(ip, PC_IPS) is False
    assert to_flow_event(_flow(src_ip=ip), PC_IPS).direction == "inbound"


def test_ipv6_zone_and_ipv4_mapped_addresses_are_normalized() -> None:
    assert direction_of("fe80::1%eth0", PC_IPS) == "outbound"       # zone id dropped
    assert direction_of("::ffff:192.168.56.10", PC_IPS) == "outbound"  # IPv4-mapped unwrapped
    assert direction_of("::ffff:192.168.56.20", PC_IPS) == "inbound"


def test_with_no_known_addresses_only_loopback_is_outbound() -> None:
    assert direction_of("127.0.0.1", frozenset()) == "outbound"
    assert direction_of("192.168.56.10", frozenset()) == "inbound"


def test_host_addresses_reads_every_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    import psutil

    nic = SimpleNamespace
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {
        "Ethernet": [nic(family=socket.AF_INET, address="192.168.56.10"),
                     nic(family=socket.AF_INET6, address="fe80::abcd%12"),
                     nic(family=psutil.AF_LINK, address="aa-bb-cc-dd-ee-ff")],
        "Wi-Fi": [nic(family=socket.AF_INET, address="10.0.0.7")],
    })
    assert capture.host_addresses() == frozenset(
        {ip_address("192.168.56.10"), ip_address("fe80::abcd"), ip_address("10.0.0.7")}
    )


def test_local_addresses_refresh_on_interval_and_survive_errors() -> None:
    now = [0.0]
    reads: list[frozenset] = [frozenset({ip_address("10.0.0.1")}),
                              frozenset({ip_address("10.0.0.2")})]
    calls = {"n": 0}

    def source() -> frozenset:
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("adapter gone")
        return reads[calls["n"] - 1]

    local = LocalAddresses(refresh_s=60, source=source, clock=lambda: now[0])
    assert local.get() == reads[0]
    now[0] = 59
    assert local.get() == reads[0] and calls["n"] == 1        # cached within the interval
    now[0] = 60
    assert local.get() == reads[1] and calls["n"] == 2        # re-read after the interval (DHCP)
    now[0] = 120
    assert local.get() == reads[1] and calls["n"] == 3        # error: keep the last known set


def test_run_reads_refresh_interval_from_config() -> None:
    cfg = config.load()
    assert cfg["capture"]["local_ips_refresh_s"] == 60


def test_run_defaults_to_this_pcs_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    # No local_addresses passed: run() must read this PC's own IPs (host_addresses) itself.
    monkeypatch.setattr(capture, "host_addresses", lambda: PC_IPS)
    flows = [_flow(src_ip="192.168.56.10"), _flow(src_ip=LAB_ATTACKER)]
    bus = RecordingBus()
    cfg = {"capture": {"local_ips_refresh_s": 60}}
    capture.run(bus, cfg, streamer_factory=lambda c: flows)  # type: ignore[arg-type]
    assert [e.direction for e in bus.events] == ["outbound", "inbound"]


# --- make_streamer ----------------------------------------------------------------------------


@pytest.fixture
def fake_nfstream(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    module = types.ModuleType("nfstream")
    streamer_cls = MagicMock(name="NFStreamer")
    module.NFStreamer = streamer_cls  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "nfstream", module)
    return streamer_cls


def test_make_streamer_uses_exactly_the_spec_settings(fake_nfstream: MagicMock) -> None:
    cfg = config.load()
    streamer = capture.make_streamer(cfg)
    assert streamer is fake_nfstream.return_value
    fake_nfstream.assert_called_once_with(
        source="Ethernet",
        statistical_analysis=True,
        system_visibility_mode=0,  # NFStream's process helper is off by default (#68)
        idle_timeout=10,
        active_timeout=30,
    )
    _, kwargs = fake_nfstream.call_args
    assert "n_dissections" not in kwargs


def test_make_streamer_reads_interface_and_timeouts_from_config(
    fake_nfstream: MagicMock,
) -> None:
    cfg = {"capture": {"interface": "Wi-Fi", "idle_timeout": 3, "active_timeout": 7}}
    capture.make_streamer(cfg)
    _, kwargs = fake_nfstream.call_args
    assert kwargs == {
        "source": "Wi-Fi",
        "statistical_analysis": True,
        "system_visibility_mode": 0,  # key missing -> off (#68)
        "idle_timeout": 3,
        "active_timeout": 7,
    }


def test_make_streamer_without_nfstream_raises_clear_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "nfstream", None)  # makes `import nfstream` fail
    with pytest.raises(CaptureError, match="NFStream is not installed"):
        capture.make_streamer(config.load())


def test_import_does_not_need_nfstream() -> None:
    code = (
        "import sys; sys.modules['nfstream'] = None\n"  # any `import nfstream` now fails
        "import agent.capture as c\n"
        "print(c.to_flow_event(type('F', (), {'system_process_name': 'a.exe'})(), ()).process)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "a.exe"


# --- run loop ---------------------------------------------------------------------------------


class RecordingBus:
    def __init__(self) -> None:
        self.events: list[FlowEvent] = []

    def publish_threadsafe(self, event: FlowEvent) -> None:
        self.events.append(event)

    def publish(self, event: FlowEvent) -> None:  # pragma: no cover - must not be used
        raise AssertionError("capture must use publish_threadsafe")


def test_run_publishes_each_mapped_flow_with_publish_threadsafe() -> None:
    flows = [_flow(bidirectional_first_seen_ms=i, dst_port=1000 + i) for i in range(5)]
    bus = RecordingBus()
    seen_cfg: list[dict[str, Any]] = []

    def factory(cfg: dict[str, Any]) -> list[SimpleNamespace]:
        seen_cfg.append(cfg)
        return flows

    cfg = {"capture": {"interface": "x"}}
    count = capture.run(bus, cfg, streamer_factory=factory, local_addresses=_fixed())  # type: ignore[arg-type]
    assert count == 5
    assert seen_cfg == [cfg]
    assert bus.events == [to_flow_event(f, PC_IPS) for f in flows]


def test_run_skips_a_flow_that_fails_to_map(caplog: pytest.LogCaptureFixture) -> None:
    class Exploding:
        @property
        def src_ip(self) -> str:
            raise RuntimeError("boom")

    flows = [_flow(dst_port=1), Exploding(), _flow(dst_port=3)]
    bus = RecordingBus()
    with caplog.at_level(logging.ERROR, logger="agent.capture"):
        count = capture.run(bus, {}, streamer_factory=lambda cfg: flows, local_addresses=_fixed())  # type: ignore[arg-type]
    assert count == 2
    assert [e.dst_port for e in bus.events] == [1, 3]
    assert "skipping" in caplog.text


def test_run_stops_when_stop_event_is_set() -> None:
    stop = threading.Event()
    bus = RecordingBus()

    def streamer(cfg: dict[str, Any]):
        for i in range(100):
            if i == 3:
                stop.set()
            yield _flow(dst_port=i)

    count = capture.run(bus, {}, streamer_factory=streamer, stop_event=stop,
                        local_addresses=_fixed())  # type: ignore[arg-type]
    assert count == 3
    assert [e.dst_port for e in bus.events] == [0, 1, 2]


def test_run_passes_process_fallback_to_mapping() -> None:
    bus = RecordingBus()
    capture.run(
        bus,  # type: ignore[arg-type]
        {},
        streamer_factory=lambda cfg: [_flow(system_process_name="")],
        process_fallback=lambda flow: ("svchost.exe", 900),
        local_addresses=_fixed(),
    )
    assert (bus.events[0].process, bus.events[0].pid) == ("svchost.exe", 900)


def test_run_in_a_thread_delivers_events_in_order_to_real_bus_subscribers() -> None:
    flows = [_flow(bidirectional_first_seen_ms=i) for i in range(200)]
    expected = [to_flow_event(f, PC_IPS) for f in flows]

    async def main() -> None:
        bus = Bus(queue_size=1000, drop_log_every=1)
        subs = [bus.subscribe(f"s{i}") for i in range(2)]  # attaches the running loop
        thread = threading.Thread(
            target=capture.run,
            args=(bus, {}),
            kwargs={"streamer_factory": lambda cfg: flows, "local_addresses": _fixed()},
        )
        thread.start()

        async def consume(sub: Any) -> list:
            return [await sub.get() for _ in range(len(flows))]

        results = await asyncio.wait_for(asyncio.gather(*(consume(s) for s in subs)), TIMEOUT_S)
        await asyncio.to_thread(thread.join, TIMEOUT_S)
        assert not thread.is_alive()
        for got in results:
            assert got == expected

    asyncio.run(main())


# --- psutil port -> PID fallback (#5) ---------------------------------------------------------


def _conn(port: int, pid: int | None, sock_type: int = 1, ip: str = "192.168.56.10") -> Any:
    """A fake psutil ``sconn`` (only the fields the resolver reads)."""
    laddr = SimpleNamespace(ip=ip, port=port) if port else ()
    return SimpleNamespace(type=sock_type, laddr=laddr, raddr=(), pid=pid)


class FakeProcess:
    names: dict[int, str] = {}

    def __init__(self, pid: int) -> None:
        self.pid = pid

    def name(self) -> str:
        import psutil

        if self.pid not in self.names:
            raise psutil.NoSuchProcess(self.pid)
        return self.names[self.pid]


@pytest.fixture
def fake_psutil(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch psutil.net_connections / psutil.Process; returns knobs and a call counter."""
    import socket

    import psutil

    state: dict[str, Any] = {
        "conns": [
            _conn(51515, 777, socket.SOCK_STREAM),          # TCP client port of updater.exe
            _conn(3389, 888, socket.SOCK_STREAM),           # TCP server port of rdpsvc.exe
            _conn(5353, 999, socket.SOCK_DGRAM),            # UDP port of mdns.exe
        ],
        "names": {777: "updater.exe", 888: "rdpsvc.exe", 999: "mdns.exe"},
        "calls": 0,
        "error": None,
    }

    def net_connections(kind: str = "inet") -> list[Any]:
        assert kind == "inet"
        state["calls"] += 1
        if state["error"] is not None:
            raise state["error"]
        return list(state["conns"])

    class Proc(FakeProcess):
        names = state["names"]

    monkeypatch.setattr(psutil, "net_connections", net_connections)
    monkeypatch.setattr(psutil, "Process", Proc)
    return state


def _resolver(now: list[float] | None = None, ttl_s: float = 2.0) -> capture.PortPidResolver:
    clock = (lambda: now[0]) if now is not None else (lambda: 0.0)
    return capture.PortPidResolver(ttl_s, _fixed(), clock=clock)


def test_fallback_gives_outbound_flow_the_owner_of_its_src_port(fake_psutil: dict) -> None:
    flow = _flow(system_process_name="", system_process_pid=0, src_port=51515, protocol=6)
    event = to_flow_event(flow, PC_IPS, _resolver())
    assert (event.process, event.pid) == ("updater.exe", 777)


def test_fallback_gives_inbound_flow_the_owner_of_its_dst_port(fake_psutil: dict) -> None:
    flow = _flow(system_process_name="", src_ip=LAB_ATTACKER, src_port=40000,
                 dst_ip="192.168.56.10", dst_port=3389, protocol=6)
    event = to_flow_event(flow, PC_IPS, _resolver())
    assert event.direction == "inbound"
    assert (event.process, event.pid) == ("rdpsvc.exe", 888)


def test_fallback_matches_udp_flows_only_to_udp_sockets(fake_psutil: dict) -> None:
    udp = _flow(system_process_name="", src_port=5353, protocol=17)
    assert to_flow_event(udp, PC_IPS, _resolver()).process == "mdns.exe"
    # Same port number over TCP: no TCP socket owns it.
    tcp = _flow(system_process_name="", src_port=5353, protocol=6)
    assert to_flow_event(tcp, PC_IPS, _resolver()).process == "unknown"


@pytest.mark.parametrize(
    "overrides",
    [
        {"src_port": 60000, "protocol": 6},     # no connection owns the port
        {"src_port": 51515, "protocol": 17},    # port owned only over TCP
        {"src_port": 0, "protocol": 6},         # no port
        {"src_port": 51515, "protocol": 1},     # ICMP: no ports at all
    ],
)
def test_fallback_without_a_matching_connection_keeps_defaults(
    fake_psutil: dict, overrides: dict[str, Any]
) -> None:
    flow = _flow(system_process_name="", system_process_pid=0, **overrides)
    event = to_flow_event(flow, PC_IPS, _resolver())
    assert (event.process, event.pid) == ("unknown", -1)


def test_fallback_skips_connections_without_pid_or_local_address(fake_psutil: dict) -> None:
    fake_psutil["conns"] = [_conn(51515, None), _conn(0, 777), _conn(51515, 0)]
    event = to_flow_event(_flow(system_process_name="", src_port=51515), PC_IPS, _resolver())
    assert (event.process, event.pid) == ("unknown", -1)


def test_fallback_keeps_pid_when_process_name_cannot_be_read(fake_psutil: dict) -> None:
    fake_psutil["conns"] = [_conn(51515, 4321)]  # PID with no readable name (process gone)
    event = to_flow_event(_flow(system_process_name="", src_port=51515), PC_IPS, _resolver())
    assert (event.process, event.pid) == ("unknown", 4321)


def test_fallback_caches_snapshot_within_ttl_and_refreshes_after(fake_psutil: dict) -> None:
    now = [100.0]
    resolver = _resolver(now, ttl_s=2.0)
    flow = _flow(system_process_name="", src_port=51515)
    for _ in range(50):  # a burst of flows
        assert to_flow_event(flow, PC_IPS, resolver).pid == 777
    assert fake_psutil["calls"] == 1

    # The port changes owner; within the TTL the cached snapshot is still used.
    fake_psutil["conns"] = [_conn(51515, 999)]
    now[0] = 101.9
    assert to_flow_event(flow, PC_IPS, resolver).pid == 777
    assert fake_psutil["calls"] == 1

    now[0] = 102.0  # TTL elapsed: refresh
    event = to_flow_event(flow, PC_IPS, resolver)
    assert (event.process, event.pid) == ("mdns.exe", 999)
    assert fake_psutil["calls"] == 2


def test_fallback_logs_access_denied_and_capture_continues(
    fake_psutil: dict, caplog: pytest.LogCaptureFixture
) -> None:
    import psutil

    now = [0.0]
    fake_psutil["error"] = psutil.AccessDenied()
    resolver = _resolver(now)
    flows = [_flow(system_process_name="", src_port=51515, dst_port=i) for i in range(3)]
    bus = RecordingBus()
    with caplog.at_level(logging.WARNING, logger="agent.capture"):
        count = capture.run(
            bus, {}, streamer_factory=lambda cfg: flows,  # type: ignore[arg-type]
            process_fallback=resolver, local_addresses=_fixed(),
        )
    assert count == 3
    assert [(e.process, e.pid, e.dst_port) for e in bus.events] == [
        ("unknown", -1, 0), ("unknown", -1, 1), ("unknown", -1, 2)
    ]
    assert "net_connections failed" in caplog.text
    assert fake_psutil["calls"] == 1  # the failure is cached too: no psutil call per flow

    # psutil recovers: after the TTL the resolver works again.
    fake_psutil["error"] = None
    now[0] = 5.0
    assert to_flow_event(flows[0], PC_IPS, resolver).pid == 777


def test_fallback_survives_process_name_access_denied(
    fake_psutil: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psutil

    class DeniedProcess:
        def __init__(self, pid: int) -> None:
            raise psutil.AccessDenied(pid)

    monkeypatch.setattr(psutil, "Process", DeniedProcess)
    event = to_flow_event(_flow(system_process_name="", src_port=51515), PC_IPS, _resolver())
    assert (event.process, event.pid) == ("unknown", 777)


def test_run_uses_psutil_fallback_by_default_with_ttl_from_config(
    fake_psutil: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[float] = []
    real_init = capture.PortPidResolver.__init__

    def spy_init(self: Any, ttl_s: float, *args: Any, **kwargs: Any) -> None:
        built.append(ttl_s)
        real_init(self, ttl_s, *args, **kwargs)

    monkeypatch.setattr(capture.PortPidResolver, "__init__", spy_init)
    bus = RecordingBus()
    cfg = {"capture": {"local_ips_refresh_s": 60, "port_pid_cache_ttl_s": 7}}
    capture.run(bus, cfg, streamer_factory=lambda c: [_flow(system_process_name="")],  # type: ignore[arg-type]
                local_addresses=_fixed())
    assert (bus.events[0].process, bus.events[0].pid) == ("updater.exe", 777)
    assert built == [7]

    capture.run(RecordingBus(), {}, streamer_factory=lambda c: [],  # type: ignore[arg-type]
                local_addresses=_fixed())
    assert built == [7, capture.DEFAULT_PORT_PID_CACHE_TTL_S]


def test_config_sets_port_pid_cache_ttl() -> None:
    assert config.load()["capture"]["port_pid_cache_ttl_s"] == 2


# --- PortHistory: short connections keep their process (#58) ------------------------------------
# NFStream reports a check-in only after it closed; by then psutil no longer lists its port.


def _history(now: list[float], keep_s: float = 60.0) -> capture.PortHistory:
    return capture.PortHistory(0.05, keep_s, clock=lambda: now[0])


def test_closed_connection_keeps_its_process_through_the_history(fake_psutil: dict) -> None:
    now = [100.0]
    history = _history(now)
    fake_psutil["conns"] = [_conn(51515, 777)]       # check-in open while the history polls
    history.poll_once()
    fake_psutil["conns"] = []                        # closed before NFStream reports the flow
    fake_psutil["names"].clear()                     # and updater.exe has even exited

    flow = _flow(system_process_name="", system_process_pid=0, src_port=51515, protocol=6)
    without = to_flow_event(flow, PC_IPS, capture.PortPidResolver(2.0, _fixed()))
    with_history = to_flow_event(flow, PC_IPS,
                                 capture.PortPidResolver(2.0, _fixed(), history=history))

    assert (without.process, without.pid) == ("unknown", -1)          # the #58 bug
    assert (with_history.process, with_history.pid) == ("updater.exe", 777)


def test_live_snapshot_wins_over_the_history(fake_psutil: dict) -> None:
    now = [0.0]
    history = _history(now)
    fake_psutil["conns"] = [_conn(51515, 999, socket.SOCK_STREAM)]
    history.poll_once()                               # remembered: mdns.exe
    fake_psutil["conns"] = [_conn(51515, 777, socket.SOCK_STREAM)]  # owned now by updater.exe
    resolver = capture.PortPidResolver(2.0, _fixed(), history=history)
    event = to_flow_event(_flow(system_process_name="", src_port=51515), PC_IPS, resolver)
    assert (event.process, event.pid) == ("updater.exe", 777)


def test_history_keeps_the_latest_owner_and_matches_the_socket_type(fake_psutil: dict) -> None:
    now = [0.0]
    history = _history(now)
    fake_psutil["conns"] = [_conn(51515, 777, socket.SOCK_STREAM)]
    history.poll_once()
    now[0] = 1.0
    fake_psutil["conns"] = [_conn(51515, 888, socket.SOCK_STREAM),
                            _conn(5353, 999, socket.SOCK_DGRAM)]
    history.poll_once()
    assert history.lookup((socket.SOCK_STREAM, 51515)) == ("rdpsvc.exe", 888)
    assert history.lookup((socket.SOCK_DGRAM, 5353)) == ("mdns.exe", 999)
    assert history.lookup((socket.SOCK_DGRAM, 51515)) is None  # TCP sighting, UDP flow


def test_history_forgets_sightings_older_than_keep_s(fake_psutil: dict) -> None:
    now = [0.0]
    history = _history(now, keep_s=60.0)
    fake_psutil["conns"] = [_conn(51515, 777)]
    history.poll_once()
    fake_psutil["conns"] = []
    now[0] = 59.0
    history.poll_once()
    assert history.lookup((socket.SOCK_STREAM, 51515)) == ("updater.exe", 777)
    now[0] = 60.5
    assert history.lookup((socket.SOCK_STREAM, 51515)) is None   # expired on read
    history.poll_once()
    assert history._seen == {}                                   # and pruned on the next poll


def test_history_poll_error_is_logged_once_and_never_raises(
    fake_psutil: dict, caplog: pytest.LogCaptureFixture
) -> None:
    import psutil

    history = _history([0.0])
    fake_psutil["error"] = psutil.AccessDenied()
    with caplog.at_level(logging.WARNING, logger="agent.capture"):
        history.poll_once()
        history.poll_once()
    assert caplog.text.count("net_connections failed") == 1
    fake_psutil["error"] = None
    history.poll_once()
    assert history.lookup((socket.SOCK_STREAM, 51515)) == ("updater.exe", 777)


def test_history_rejects_non_positive_times() -> None:
    with pytest.raises(ValueError):
        capture.PortHistory(0, 60)
    with pytest.raises(ValueError):
        capture.PortHistory(0.05, 0)


def test_history_thread_polls_until_stopped(fake_psutil: dict) -> None:
    history = capture.PortHistory(0.01, 60)
    history.start()
    try:
        deadline = time.monotonic() + 5.0
        while fake_psutil["calls"] < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert fake_psutil["calls"] >= 3
    finally:
        history.stop()
    calls = fake_psutil["calls"]
    time.sleep(0.05)
    assert fake_psutil["calls"] == calls          # stopped: no more polling
    assert history.lookup((socket.SOCK_STREAM, 51515)) == ("updater.exe", 777)


def test_run_starts_the_history_with_config_times_and_stops_it(
    fake_psutil: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[capture.PortHistory] = []
    real_init = capture.PortHistory.__init__

    def spy_init(self: Any, poll_s: float, keep_s: float, *args: Any, **kwargs: Any) -> None:
        real_init(self, poll_s, keep_s, *args, **kwargs)
        built.append(self)

    monkeypatch.setattr(capture.PortHistory, "__init__", spy_init)
    cfg = {"capture": {"local_ips_refresh_s": 60, "port_poll_interval_s": 0.02,
                       "port_history_s": 30}}
    capture.run(RecordingBus(), cfg, streamer_factory=lambda c: [],  # type: ignore[arg-type]
                local_addresses=_fixed())
    (history,) = built
    assert (history._poll_s, history._keep_s) == (0.02, 30)
    assert history._thread is None                 # stopped when capture ended

    # An injected fallback (tests, the pipeline's own) starts no history thread.
    capture.run(RecordingBus(), cfg, streamer_factory=lambda c: [],  # type: ignore[arg-type]
                process_fallback=lambda f: None, local_addresses=_fixed())
    assert len(built) == 1


def test_config_sets_port_history_times() -> None:
    capture_cfg = config.load()["capture"]
    assert capture_cfg["port_poll_interval_s"] == 0.05
    assert capture_cfg["port_history_s"] == 60
