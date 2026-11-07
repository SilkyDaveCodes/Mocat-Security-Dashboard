"""Tests for agent.detectors.intel: the known-bad IP detector (CLAUDE.md §6.3).

No test touches the network: an autouse fixture replaces both ``intel.download_feed`` and
``urllib.request.urlopen`` with recorders, and fails the test if either is reached unexpectedly.
Only lab (192.168.56.x) and documentation (192.0.2.x, 198.51.100.x, 203.0.113.x) IPs are used.
"""

from __future__ import annotations

import copy
import io
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent import config
from agent.detectors import intel
from agent.detectors.intel import IntelDetector
from agent.events import FlowEvent, Signal

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_TEST_INTEL = REPO_ROOT / "data" / "test_intel.txt"
FEED_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "intel_feed.txt"
FEED_FIXTURE_IPS = frozenset({"192.0.2.10", "198.51.100.7", "203.0.113.5"})

LAB_C2 = "192.168.56.20"  # the only entry in data/test_intel.txt
LAB_PC = "192.168.56.10"
FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
REFRESH_S = 3600.0
_REAL_DOWNLOAD_FEED = intel.download_feed  # captured before any monkeypatching


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeDownload:
    """Stands in for intel.download_feed: records calls, returns text or raises."""

    def __init__(self, result: str | BaseException) -> None:
        self.result = result
        self.calls: list[tuple[str, float]] = []

    def __call__(self, url: str, timeout_s: float) -> str:
        self.calls.append((url, timeout_s))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def run_now(task: Callable[[], None]) -> None:
    """Synchronous spawner so refreshes finish before the test continues."""
    task()


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch):
    """Guard: any unpatched download or urlopen is recorded and fails the test at teardown."""
    reached: list[str] = []

    def guard_download(url: str, timeout_s: float) -> str:
        reached.append(f"download_feed({url})")
        raise OSError("network disabled in tests")

    def guard_urlopen(*args: Any, **kwargs: Any) -> Any:
        reached.append("urlopen")
        raise OSError("network disabled in tests")

    monkeypatch.setattr(intel, "download_feed", guard_download)
    monkeypatch.setattr(urllib.request, "urlopen", guard_urlopen)
    yield
    assert reached == [], f"test reached the network guard: {reached}"


@pytest.fixture
def cfg() -> dict[str, Any]:
    data = copy.deepcopy(config.load())
    data["detectors"]["intel"]["refresh_interval_s"] = REFRESH_S
    return data


def make_detector(
    cfg: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    download: FakeDownload,
    *,
    clock: FakeClock | None = None,
    test_intel_path: Path = REAL_TEST_INTEL,
) -> IntelDetector:
    monkeypatch.setattr(intel, "download_feed", download)
    return IntelDetector(
        cfg,
        cache_dir=tmp_path / "cache",
        test_intel_path=test_intel_path,
        clock=clock or FakeClock(),
        spawn=run_now,
    )


def outbound_flow(dst_ip: str, src_ip: str = LAB_PC) -> FlowEvent:
    return FlowEvent(
        ts_ms=1_700_000_000_000,
        process="freegamecheats.exe",
        pid=4242,
        src_ip=src_ip,
        src_port=50123,
        dst_ip=dst_ip,
        dst_port=8080,
        protocol=6,
        direction="outbound",
    )


def inbound_flow(src_ip: str, dst_ip: str = LAB_PC) -> FlowEvent:
    return FlowEvent(
        ts_ms=1_700_000_123_000,
        process="svchost.exe",
        pid=900,
        src_ip=src_ip,
        src_port=40000,
        dst_ip=dst_ip,
        dst_port=3389,
        protocol=6,
        direction="inbound",
    )


# --- config --------------------------------------------------------------------------------


def test_real_config_has_intel_feed_settings() -> None:
    intel_cfg = config.load()["detectors"]["intel"]
    assert intel_cfg["feed_url"] == FEED_URL
    assert intel_cfg["download_timeout_s"] > 0
    assert intel_cfg["refresh_interval_s"] == 3600
    assert intel_cfg["score"] == 1.0


def test_non_https_feed_url_is_rejected(cfg: dict, tmp_path: Path) -> None:
    cfg["detectors"]["intel"]["feed_url"] = "file:///etc/passwd"
    with pytest.raises(ValueError, match="https"):
        IntelDetector(cfg, cache_dir=tmp_path, test_intel_path=REAL_TEST_INTEL, spawn=run_now)


# --- AC1: outbound flow to a test_intel.txt IP -> one intel Signal, score 1.0, T1071 ---------


def test_outbound_flow_to_test_intel_ip_produces_one_signal(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")))
    assert LAB_C2 in detector.ips

    signals = detector.process(outbound_flow(LAB_C2))

    assert signals == [
        Signal(
            detector="intel",
            process="freegamecheats.exe",
            pid=4242,
            target=LAB_C2,
            score=1.0,
            reasons=[f"talks to {LAB_C2}, which is on a known-bad IP list"],
            mitre="T1071",
            ts_ms=1_700_000_000_000,
        )
    ]


def test_score_comes_from_config(cfg: dict, tmp_path: Path, monkeypatch) -> None:
    cfg["detectors"]["intel"]["score"] = 0.75
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")))
    [signal] = detector.process(outbound_flow(LAB_C2))
    assert signal.score == 0.75


def test_unlisted_flow_produces_no_signal(cfg: dict, tmp_path: Path, monkeypatch) -> None:
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")))
    assert detector.process(outbound_flow("192.168.56.30")) == []
    assert detector.process(inbound_flow("198.51.100.200")) == []
    assert detector.process(FlowEvent()) == []  # empty IPs must not crash or match


def test_module_level_process_uses_default_detector(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")))
    monkeypatch.setattr(intel, "_default_detector", detector)
    [signal] = intel.process(outbound_flow(LAB_C2))
    assert (signal.detector, signal.target, signal.mitre) == ("intel", LAB_C2, "T1071")


# --- AC2: inbound flow from a listed src_ip -> Signal ----------------------------------------


def test_inbound_flow_from_listed_src_ip_produces_signal(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")))

    signals = detector.process(inbound_flow(LAB_C2))

    assert signals == [
        Signal(
            detector="intel",
            process="svchost.exe",
            pid=900,
            target=LAB_C2,
            score=1.0,
            reasons=[f"receives a connection from {LAB_C2}, which is on a known-bad IP list"],
            mitre="T1071",
            ts_ms=1_700_000_123_000,
        )
    ]


def test_mislabelled_direction_still_gives_exactly_one_signal(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")))
    # Marked outbound, but the listed IP is the source (capture guessed direction wrong).
    flow = outbound_flow(dst_ip=LAB_PC, src_ip=LAB_C2)
    signals = detector.process(flow)
    assert [s.target for s in signals] == [LAB_C2]


def test_both_ips_listed_gives_one_signal_for_the_remote_ip(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test_list = tmp_path / "test_intel.txt"
    test_list.write_text(f"{LAB_C2}\n192.168.56.21\n", encoding="utf-8")
    detector = make_detector(
        cfg, tmp_path, monkeypatch, FakeDownload(OSError("offline")), test_intel_path=test_list
    )
    out = detector.process(outbound_flow(dst_ip=LAB_C2, src_ip="192.168.56.21"))
    inn = detector.process(inbound_flow(src_ip=LAB_C2, dst_ip="192.168.56.21"))
    assert [s.target for s in out] == [LAB_C2]
    assert [s.target for s in inn] == [LAB_C2]


# --- AC3: comment and blank lines in the feed are ignored -----------------------------------


def test_parse_feed_ignores_comments_and_blank_lines() -> None:
    text = FEED_FIXTURE.read_text(encoding="utf-8")
    assert intel.parse_feed(text) == FEED_FIXTURE_IPS
    # The commented-out IP in the fixture must not be loaded.
    assert "203.0.113.99" not in intel.parse_feed(text)


def test_parse_feed_skips_lines_that_are_not_ips() -> None:
    assert intel.parse_feed("192.0.2.1\nnot-an-ip\n<html>\n192.0.2.1\n") == {"192.0.2.1"}


def test_downloaded_feed_with_comments_loads_only_the_ips(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feed_text = FEED_FIXTURE.read_text(encoding="utf-8")
    download = FakeDownload(feed_text)
    detector = make_detector(cfg, tmp_path, monkeypatch, download)

    assert download.calls == [(FEED_URL, cfg["detectors"]["intel"]["download_timeout_s"])]
    assert detector.feed_ips == FEED_FIXTURE_IPS
    assert detector.ips == FEED_FIXTURE_IPS | {LAB_C2}
    [signal] = detector.process(outbound_flow("198.51.100.7"))
    assert signal.target == "198.51.100.7"
    # The successful download is written to the cache verbatim.
    assert (tmp_path / "cache" / intel.CACHE_FILE_NAME).read_text(encoding="utf-8") == feed_text


# --- AC4: download fails -> cached list used, no exception escapes ---------------------------


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("no route to host"),
        urllib.error.HTTPError(FEED_URL, 503, "Service Unavailable", {}, io.BytesIO()),  # type: ignore[arg-type]
        TimeoutError("timed out"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ],
    ids=["URLError", "HTTPError", "timeout", "bad-encoding"],
)
def test_download_failure_uses_cached_list(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / intel.CACHE_FILE_NAME
    cached_text = FEED_FIXTURE.read_text(encoding="utf-8")
    cache_file.write_text(cached_text, encoding="utf-8")
    download = FakeDownload(error)

    detector = make_detector(cfg, tmp_path, monkeypatch, download)  # must not raise
    signals = detector.process(outbound_flow("203.0.113.5"))  # must not raise

    assert len(download.calls) == 1
    assert detector.feed_ips == FEED_FIXTURE_IPS
    assert [s.target for s in signals] == ["203.0.113.5"]
    assert cache_file.read_text(encoding="utf-8") == cached_text  # cache left untouched


def test_download_failure_without_cache_falls_back_to_test_list(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    download = FakeDownload(urllib.error.URLError("offline"))
    detector = make_detector(cfg, tmp_path, monkeypatch, download)

    assert len(download.calls) == 1
    assert detector.feed_ips == frozenset()
    assert detector.ips == {LAB_C2}
    assert [s.target for s in detector.process(outbound_flow(LAB_C2))] == [LAB_C2]
    assert not (tmp_path / "cache" / intel.CACHE_FILE_NAME).exists()


def test_download_with_no_ips_keeps_cache(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / intel.CACHE_FILE_NAME
    cache_file.write_text("192.0.2.10\n", encoding="utf-8")

    detector = make_detector(
        cfg, tmp_path, monkeypatch, FakeDownload("<html>maintenance</html>\n# nothing\n")
    )

    assert detector.feed_ips == {"192.0.2.10"}
    assert cache_file.read_text(encoding="utf-8") == "192.0.2.10\n"


def test_unexpected_refresh_error_does_not_escape(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    detector = make_detector(cfg, tmp_path, monkeypatch, FakeDownload(RuntimeError("boom")))
    assert [s.target for s in detector.process(outbound_flow(LAB_C2))] == [LAB_C2]


def test_download_feed_uses_url_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real HTTP function, with urlopen patched: right URL, a timeout, decoded body."""
    seen: dict[str, Any] = {}

    class FakeResponse(io.BytesIO):
        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *exc: object) -> None:
            self.close()

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return FakeResponse(b"# header\n192.0.2.10\n")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    # The autouse guard replaced intel.download_feed; call the real one captured at import.
    result = _REAL_DOWNLOAD_FEED(FEED_URL, 7.5)

    assert result == "# header\n192.0.2.10\n"
    assert seen == {"url": FEED_URL, "timeout": 7.5}


def test_download_feed_propagates_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_urlopen(request: urllib.request.Request, timeout: float) -> Any:
        raise urllib.error.HTTPError(FEED_URL, 404, "Not Found", {}, io.BytesIO())  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", failing_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        _REAL_DOWNLOAD_FEED(FEED_URL, 1.0)


# --- AC5: no re-download within the refresh interval (fake clock) ----------------------------


def test_not_downloaded_again_within_refresh_interval(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    download = FakeDownload("192.0.2.10\n")
    detector = make_detector(cfg, tmp_path, monkeypatch, download, clock=clock)
    assert len(download.calls) == 1  # initial refresh on construction

    for step in (1, 60, 1800, REFRESH_S - 1 - 60 - 1800 - 1):
        clock.advance(step)
        detector.process(outbound_flow("192.168.56.30"))
    assert clock.now - 1_000_000.0 == REFRESH_S - 1
    assert len(download.calls) == 1

    download.result = "192.0.2.10\n203.0.113.5\n"
    clock.advance(1)  # exactly one interval after the first download
    detector.process(outbound_flow("192.168.56.30"))
    assert len(download.calls) == 2
    assert detector.feed_ips == {"192.0.2.10", "203.0.113.5"}
    cache_file = tmp_path / "cache" / intel.CACHE_FILE_NAME
    assert cache_file.read_text(encoding="utf-8") == "192.0.2.10\n203.0.113.5\n"

    clock.advance(REFRESH_S / 2)
    detector.process(outbound_flow("192.168.56.30"))
    assert len(download.calls) == 2


def test_failed_download_is_not_retried_on_every_flow(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    download = FakeDownload(urllib.error.URLError("offline"))
    detector = make_detector(cfg, tmp_path, monkeypatch, download, clock=clock)

    for _ in range(50):
        clock.advance(1)
        detector.process(outbound_flow(LAB_C2))
    assert len(download.calls) == 1

    clock.advance(REFRESH_S)
    detector.process(outbound_flow(LAB_C2))
    assert len(download.calls) == 2


def test_default_refresh_runs_off_the_calling_thread(
    cfg: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the default spawner, construction returns without waiting for the download."""
    release = threading.Event()
    finished = threading.Event()
    threads: list[threading.Thread] = []

    def slow_download(url: str, timeout_s: float) -> str:
        threads.append(threading.current_thread())
        release.wait(timeout=5)
        finished.set()
        return "192.0.2.10\n"

    monkeypatch.setattr(intel, "download_feed", slow_download)
    detector = IntelDetector(
        cfg, cache_dir=tmp_path / "cache", test_intel_path=REAL_TEST_INTEL, clock=FakeClock()
    )
    # The download is still blocked, yet detection already works from the test list.
    assert [s.target for s in detector.process(outbound_flow(LAB_C2))] == [LAB_C2]
    assert not finished.is_set()

    release.set()
    assert finished.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
    assert len(threads) == 1 and threads[0] is not threading.main_thread()
    assert detector.feed_ips == {"192.0.2.10"}
