"""Tests for the normal-use recorder (lab/fp_recording.py), the privacy of every normal-use
fixture, and the synthetic stand-in fixture (lab/synth_normal_use.py). Ticket #49."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent import capture, config
from agent.events import FlowEvent
from lab import fp_recording, synth_normal_use

FIXTURE_DIR = Path(__file__).parent / "fixtures"
NORMAL_USE_FIXTURES = sorted(FIXTURE_DIR.glob("normal_use_*.jsonl"))
SYNTHETIC_FIXTURE = FIXTURE_DIR / "normal_use_synthetic.jsonl"
PC_IP = "192.168.1.50"
T0_MS = 1_762_500_000_000  # "wall clock" when the fake recording starts

# The allowed-key set, spelled out here on purpose: widening fp_recording.ALLOWED_KEYS must be a
# deliberate change to this test too.
EXPECTED_ALLOWED_KEYS = {
    "seen_ms", "ts_ms", "end_ms", "process", "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "hostname", "app_proto", "bytes_out", "bytes_in", "packets", "direction",
}
USER_PATH = re.compile(r"\\users\\|/users/|\\appdata\\|^[a-z]:\\", re.IGNORECASE)


def fixture_id(path: Path) -> str:
    return path.stem


# --- acceptance: fixtures hold no personal data beyond process names, IPs and hostnames -------


def test_allowed_key_set_is_the_documented_one() -> None:
    assert set(fp_recording.ALLOWED_KEYS) == EXPECTED_ALLOWED_KEYS
    assert not {"pid", "exe_path", "features", "type"} & set(fp_recording.ALLOWED_KEYS)


@pytest.mark.parametrize("fixture", NORMAL_USE_FIXTURES, ids=fixture_id)
def test_fixture_records_have_only_allowed_keys_and_no_user_paths(fixture: Path) -> None:
    records = fp_recording.load_records(fixture)
    assert records
    for number, rec in enumerate(records, start=1):
        extra = sorted(set(rec) - EXPECTED_ALLOWED_KEYS)
        assert not extra, f"line {number}: keys not allowed {extra}"
        for key, value in rec.items():
            if isinstance(value, str):
                assert not USER_PATH.search(value), f"line {number}: {key}={value!r}"
        assert fp_recording.personal_data_problems(rec) == [], f"line {number}"
        assert "\\" not in rec["process"] and "/" not in rec["process"]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"pid": 4242}, "keys not allowed"),
        ({"exe_path": r"C:\Users\jake\Downloads\a.exe"}, "keys not allowed"),
        ({"features": {"bidirectional_bytes": 10}}, "keys not allowed"),
        ({"hostname": r"C:\Users\jake\file.txt"}, "Windows/user path"),
        ({"process": r"C:\Users\jake\AppData\Local\app.exe"}, "Windows/user path"),
        ({"app_proto": "/Users/jake/x"}, "Windows/user path"),
        ({"bytes_out": "12"}, "must be an int"),
        ({"direction": "sideways"}, "direction must be"),
    ],
)
def test_privacy_check_rejects_extra_keys_and_user_paths(change: dict[str, Any],
                                                         expected: str) -> None:
    rec = fp_recording.load_records(SYNTHETIC_FIXTURE)[0] | change
    problems = fp_recording.personal_data_problems(rec)
    assert any(expected in p for p in problems), problems


def test_privacy_check_flags_a_missing_key() -> None:
    rec = dict(fp_recording.load_records(SYNTHETIC_FIXTURE)[0])
    del rec["seen_ms"]
    assert any("keys missing" in p for p in fp_recording.personal_data_problems(rec))


# --- to_record / from_record ------------------------------------------------------------------


def make_event(**overrides: Any) -> FlowEvent:
    base: dict[str, Any] = dict(
        ts_ms=T0_MS + 1_500, end_ms=T0_MS + 2_000, process="chrome.exe", pid=7312,
        exe_path=r"C:\Users\jake\AppData\Local\Google\Chrome\Application\chrome.exe",
        src_ip=PC_IP, src_port=51515, dst_ip="198.51.100.20", dst_port=443, protocol=6,
        hostname="www.google.com", app_proto="TLS.Google", bytes_out=1234, bytes_in=56789,
        packets=42, direction="outbound", features={"bidirectional_bytes": 58023},
    )
    return FlowEvent(**(base | overrides))


def test_to_record_drops_pid_exe_path_features_and_rebases_times() -> None:
    rec = fp_recording.to_record(make_event(), t0_ms=T0_MS, seen_ms=T0_MS + 12_000)

    assert list(rec) == list(fp_recording.ALLOWED_KEYS)
    assert "pid" not in rec and "exe_path" not in rec and "features" not in rec
    assert (rec["ts_ms"], rec["end_ms"], rec["seen_ms"]) == (1_500, 2_000, 12_000)
    assert rec["process"] == "chrome.exe"
    assert rec["hostname"] == "www.google.com"
    assert (rec["src_ip"], rec["dst_ip"], rec["dst_port"]) == (PC_IP, "198.51.100.20", 443)
    assert "jake" not in json.dumps(rec)
    assert fp_recording.personal_data_problems(rec) == []


def test_to_record_strips_a_path_from_the_process_name_and_blanks_local_hostnames() -> None:
    event = make_event(process=r"C:\Users\jake\Downloads\tool.exe", hostname="Jakes-iPhone.local",
                       app_proto=None)
    rec = fp_recording.to_record(event, t0_ms=T0_MS, seen_ms=T0_MS)
    assert rec["process"] == "tool.exe"
    assert rec["hostname"] is None
    assert rec["app_proto"] is None
    assert fp_recording.to_record(make_event(process=""), T0_MS, T0_MS)["process"] == "unknown"


def test_from_record_round_trips_every_allowed_field() -> None:
    event = make_event()
    rec = fp_recording.to_record(event, t0_ms=0, seen_ms=event.end_ms)
    back = fp_recording.from_record(rec, pid=1000)
    assert back.pid == 1000 and back.exe_path is None and back.features == {}
    for key in fp_recording.ALLOWED_KEYS:
        if key != "seen_ms":
            assert getattr(back, key) == getattr(event, key), key


def test_replay_events_sorts_by_arrival_and_gives_stable_fake_pids() -> None:
    def rec(seen: int, process: str) -> dict[str, Any]:
        r = fp_recording.to_record(make_event(process=process), 0, seen)
        return r

    pairs = list(fp_recording.replay_events(
        [rec(30, "b.exe"), rec(10, "a.exe"), rec(20, "unknown"), rec(40, "a.exe")]
    ))
    assert [seen for seen, _ in pairs] == [10, 20, 30, 40]
    pids = [(ev.process, ev.pid) for _, ev in pairs]
    assert pids == [("a.exe", 1000), ("unknown", -1), ("b.exe", 1001), ("a.exe", 1000)]


# --- the live recorder (capture.run with a fake NFStreamer) -----------------------------------


def nflow(i: int, **overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = dict(
        bidirectional_first_seen_ms=T0_MS + i * 1000,
        bidirectional_last_seen_ms=T0_MS + i * 1000 + 80,
        system_process_name="spotify.exe", system_process_pid=9000 + i, src_ip=PC_IP,
        src_port=50000 + i, dst_ip="203.0.113.40", dst_port=443, protocol=6,
        requested_server_name="spclient.wg.spotify.com", application_name="TLS",
        src2dst_bytes=900, dst2src_bytes=4000, bidirectional_packets=12,
        bidirectional_bytes=4900, bidirectional_duration_ms=80,
    )
    return SimpleNamespace(**(base | overrides))


class FakeClock:
    """Wall-clock ms: starts at T0_MS, each call moves ``step_ms`` on."""

    def __init__(self, step_ms: int) -> None:
        self.now = T0_MS - step_ms
        self.step_ms = step_ms

    def __call__(self) -> int:
        self.now += self.step_ms
        return self.now


def record_fake(tmp_path: Path, flows: list[Any], duration_s: float = 3600,
                step_ms: int = 1000, **kw: Any) -> tuple[int, Path]:
    out = tmp_path / "normal_use_vm.jsonl"
    written = fp_recording.record(
        config.load(), out, duration_s, clock=FakeClock(step_ms),
        streamer_factory=lambda cfg: iter(flows),
        local_addresses=capture.LocalAddresses(
            60, source=lambda: frozenset({ipaddress.ip_address(PC_IP)})),
        process_fallback=lambda flow: None, **kw,
    )
    return written, out


def test_recorder_writes_only_allowed_keys_with_rebased_times(tmp_path: Path) -> None:
    flows = [nflow(0), nflow(1, system_process_name="", system_process_pid=0,
                             src_ip="192.168.1.1", dst_ip=PC_IP, requested_server_name="")]
    written, out = record_fake(tmp_path, flows)

    assert written == 2
    records = fp_recording.load_records(out)
    assert all(list(r) == list(fp_recording.ALLOWED_KEYS) for r in records)
    first, second = records
    assert (first["ts_ms"], first["end_ms"], first["seen_ms"]) == (0, 80, 1000)
    assert first["process"] == "spotify.exe" and first["hostname"] == "spclient.wg.spotify.com"
    assert first["direction"] == "outbound"
    assert second["process"] == "unknown" and second["direction"] == "inbound"
    assert second["hostname"] is None
    text = out.read_text(encoding="utf-8")
    assert "9000" not in text and "bidirectional_bytes" not in text and "pid" not in text
    assert str(T0_MS)[:6] not in text  # no absolute timestamps


def test_recorder_stops_after_the_duration(tmp_path: Path) -> None:
    flows = [nflow(i) for i in range(10)]
    written, out = record_fake(tmp_path, flows, duration_s=3.5, step_ms=1000)
    # Flows arrive at t = 1, 2, 3 s; the one at 4 s is past 3.5 s and stops the capture.
    assert written == 3
    assert [r["seen_ms"] for r in fp_recording.load_records(out)] == [1000, 2000, 3000]


def test_recorder_keeps_what_it_wrote_on_ctrl_c(tmp_path: Path) -> None:
    def flows() -> Any:
        yield nflow(0)
        yield nflow(1)
        raise KeyboardInterrupt

    out = tmp_path / "rec.jsonl"
    written = fp_recording.record(
        config.load(), out, 3600, clock=FakeClock(1000), streamer_factory=lambda cfg: flows(),
        local_addresses=capture.LocalAddresses(
            60, source=lambda: frozenset({ipaddress.ip_address(PC_IP)})),
        process_fallback=lambda flow: None,
    )
    assert written == 2 and len(fp_recording.load_records(out)) == 2


def test_recorder_refuses_to_overwrite_unless_forced(tmp_path: Path) -> None:
    out = tmp_path / "normal_use_vm.jsonl"
    out.write_text("keep me\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        record_fake(tmp_path, [nflow(0)])
    assert out.read_text(encoding="utf-8") == "keep me\n"
    assert fp_recording.main(["--out", str(out), "--minutes", "1"]) == 1  # CLI: error, no capture
    written, _ = record_fake(tmp_path, [nflow(0)], overwrite=True)
    assert written == 1


def test_recorder_skips_a_record_that_fails_the_privacy_check(tmp_path: Path) -> None:
    flows = [nflow(0, requested_server_name=r"\\fileserver\Users\jake"), nflow(1)]
    written, out = record_fake(tmp_path, flows)
    assert written == 1
    assert "jake" not in out.read_text(encoding="utf-8")


# --- the synthetic stand-in fixture -----------------------------------------------------------


@pytest.fixture(scope="module")
def synthetic() -> list[dict[str, Any]]:
    return fp_recording.load_records(SYNTHETIC_FIXTURE)


def test_synthetic_fixture_is_reproducible_from_the_generator(
    synthetic: list[dict[str, Any]],
) -> None:
    assert synth_normal_use.generate() == synthetic
    assert synth_normal_use.render(synthetic) == SYNTHETIC_FIXTURE.read_text(encoding="utf-8")


def test_synthetic_fixture_is_small_and_covers_normal_apps(
    synthetic: list[dict[str, Any]],
) -> None:
    assert 500 <= len(synthetic) <= 3000
    processes = {r["process"] for r in synthetic}
    assert {"chrome.exe", "msedge.exe", "discord.exe", "spotify.exe", "svchost.exe"} <= processes
    span_s = (synthetic[-1]["seen_ms"] - synthetic[0]["seen_ms"]) / 1000
    assert span_s >= 3500  # about an hour
    dns = [r for r in synthetic if r["dst_port"] == 53]
    assert len({r["hostname"] for r in dns}) >= 50  # many real-looking popular domains
    assert any(r["dst_port"] == 123 for r in synthetic)  # NTP
    # long-lived connections: many flows on one 5-tuple (keepalives / active-timeout chunks)
    per_conn: dict[tuple[str, int, str, int], int] = {}
    for r in synthetic:
        key = (r["process"], r["src_port"], r["dst_ip"], r["dst_port"])
        per_conn[key] = per_conn.get(key, 0) + 1
    assert max(per_conn.values()) >= 20


def test_synthetic_fixture_uses_only_private_or_documentation_ips(
    synthetic: list[dict[str, Any]],
) -> None:
    lab_and_test_intel = set()
    for path in (config.REPO_ROOT / "data" / "test_intel.txt", FIXTURE_DIR / "intel_feed.txt"):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lab_and_test_intel.add(line)
    for r in synthetic:
        for key in ("src_ip", "dst_ip"):
            ip = ipaddress.ip_address(r[key])
            assert ip.is_private or ip.is_multicast, f"{key}={ip}"
            assert r[key] not in lab_and_test_intel
