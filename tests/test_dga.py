"""Tests for agent.detectors.dga: the live DGA lookup detector (CLAUDE.md §6.3).

The model is a stub at the ``predict_proba`` boundary that records every feature vector it gets,
so tests can check both the Signal and whether the model was called at all. No test needs the
real ``models/dga.joblib`` or the network; Tranco and allowlist files are written to ``tmp_path``.
"""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

import pytest

from agent import config
from agent.detectors import dga
from agent.detectors.dga import DgaDetector
from agent.detectors.dga_features import FEATURE_NAMES, features
from agent.events import FlowEvent

REPO_ROOT = Path(__file__).resolve().parent.parent
DGA_HOST = "xkqzjvwpthrb.com"
T0_MS = 1_700_000_000_000


class StubModel:
    """Stands in for the sklearn classifier: fixed P(dga), records every vector it scores."""

    def __init__(self, p_dga: float) -> None:
        self.p_dga = p_dga
        self.calls: list[list[float]] = []

    def predict_proba(self, rows: list[list[float]]) -> list[list[float]]:
        self.calls.extend(rows)
        return [[1.0 - self.p_dga, self.p_dga] for _ in rows]


def bundle(model: StubModel) -> dict[str, Any]:
    """Same shape as train_dga.make_bundle."""
    return {
        "format_version": 1,
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "classes": ["benign", "dga"],
        "dga_class_index": 1,
    }


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def tranco_file(tmp_path: Path) -> Path:
    path = tmp_path / "tranco.csv"
    path.write_text("1,google.com\n2,bbc.co.uk\n3,microsoft.com\n", encoding="utf-8")
    return path


@pytest.fixture
def allowlist_file(tmp_path: Path) -> Path:
    path = tmp_path / "domain_allowlist.txt"
    path.write_text("# comment\nqwrtzxpl.net\n", encoding="utf-8")
    return path


def make(
    cfg: dict[str, Any], stub: StubModel, tranco: Path, allow: Path, **kw: Any
) -> DgaDetector:
    return DgaDetector(
        cfg, model=bundle(stub), tranco_path=tranco, domain_allowlist_path=allow, **kw
    )


def dns_flow(
    hostname: str,
    ts_ms: int = T0_MS,
    process: str = "freegamecheats.exe",
    dst_port: int = 53,
    app_proto: str | None = "DNS",
) -> FlowEvent:
    return FlowEvent(
        ts_ms=ts_ms,
        end_ms=ts_ms + 20,
        process=process,
        pid=4242,
        src_ip="192.168.56.10",
        src_port=50000,
        dst_ip="192.168.56.20",
        dst_port=dst_port,
        protocol=17,
        hostname=hostname,
        app_proto=app_proto,
        direction="outbound",
    )


# --- criterion 1: random-looking DNS lookup -> Signal ------------------------------------------


def test_random_dns_lookup_gives_dga_signal(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.93)
    det = make(cfg, stub, tranco_file, allowlist_file)

    signals = det.process(dns_flow(DGA_HOST))

    assert len(signals) == 1
    sig = signals[0]
    assert sig.detector == "dga"
    assert sig.mitre == "T1568.002"
    assert sig.score >= 0.8
    assert sig.score == pytest.approx(0.93)
    assert sig.target == DGA_HOST
    assert sig.process == "freegamecheats.exe"
    assert sig.pid == 4242
    assert sig.ts_ms == T0_MS
    assert any(DGA_HOST in r for r in sig.reasons)
    # The model saw exactly the training features, in the bundle's column order.
    expected = [features(DGA_HOST)[name] for name in FEATURE_NAMES]
    assert stub.calls == [expected]


def test_dns_detected_by_app_proto_on_other_port(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.9)
    det = make(cfg, stub, tranco_file, allowlist_file)
    # DNS-over-something on port 5353 but NFStream says DNS
    assert len(det.process(dns_flow(DGA_HOST, dst_port=5353, app_proto="DNS.Unknown"))) == 1
    # port 53 alone is enough, even without app_proto
    assert len(det.process(dns_flow(DGA_HOST, app_proto=None))) == 1


def test_low_probability_gives_no_signal(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.3)
    det = make(cfg, stub, tranco_file, allowlist_file)
    assert det.process(dns_flow(DGA_HOST)) == []
    assert len(stub.calls) == 1


# --- criterion 2: non-DNS flow -> nothing ------------------------------------------------------


def test_non_dns_flow_gives_no_signal(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.99)
    det = make(cfg, stub, tranco_file, allowlist_file)

    signals = det.process(dns_flow(DGA_HOST, dst_port=443, app_proto="TLS"))

    assert signals == []
    assert stub.calls == []


# --- criterion 3: skipped domains never reach the model ----------------------------------------


@pytest.mark.parametrize(
    "hostname",
    [
        "printer.local",
        "1.168.192.in-addr.arpa",
        "google.com",  # Tranco
        "www.google.com",  # subdomain of a Tranco registered domain
        "news.bbc.co.uk",  # Tranco, multi-part suffix
        "MICROSOFT.COM.",  # Tranco, case and trailing dot normalized
        "qwrtzxpl.net",  # allowlisted
        "a1.qwrtzxpl.net",  # subdomain of an allowlisted domain
        "192.168.56.20",  # IP literal
        "",
    ],
)
def test_skipped_hostnames_do_not_call_model(cfg, tranco_file, allowlist_file, hostname):
    stub = StubModel(0.99)
    det = make(cfg, stub, tranco_file, allowlist_file)

    assert det.process(dns_flow(hostname)) == []
    assert stub.calls == []


def test_parent_of_registered_domain_does_not_skip(cfg, tmp_path, allowlist_file):
    # A Tranco entry "co.uk" must not whitelist every *.co.uk domain.
    tranco = tmp_path / "t.csv"
    tranco.write_text("1,co.uk\n", encoding="utf-8")
    stub = StubModel(0.99)
    det = make(cfg, stub, tranco, allowlist_file)
    assert len(det.process(dns_flow("xkqzjvwpthrb.co.uk"))) == 1


def test_tranco_top_n_limits_entries(cfg, tranco_file, allowlist_file):
    cfg["detectors"]["dga"]["tranco_top_n"] = 1  # only google.com
    stub = StubModel(0.99)
    det = make(cfg, stub, tranco_file, allowlist_file)
    assert det.process(dns_flow("google.com")) == []
    assert len(det.process(dns_flow("microsoft.com"))) == 1


def test_tranco_cache_directory_uses_csv_inside(cfg, tmp_path, allowlist_file):
    cache_dir = tmp_path / "tranco"
    cache_dir.mkdir()
    (cache_dir / "ABC12.csv").write_text("1,google.com\n", encoding="utf-8")
    stub = StubModel(0.99)
    det = make(cfg, stub, cache_dir, allowlist_file)
    assert det.process(dns_flow("google.com")) == []
    assert stub.calls == []


def test_missing_tranco_and_allowlist_are_tolerated(cfg, tmp_path, caplog):
    stub = StubModel(0.99)
    with caplog.at_level(logging.WARNING, logger="agent.detectors.dga"):
        det = make(cfg, stub, tmp_path / "nope.csv", tmp_path / "nope.txt")
    assert "Tranco" in caplog.text
    assert len(det.process(dns_flow(DGA_HOST))) == 1


def test_missing_model_logs_and_returns_nothing(cfg, tmp_path, tranco_file, allowlist_file, caplog):
    with caplog.at_level(logging.WARNING, logger="agent.detectors.dga"):
        det = DgaDetector(
            cfg,
            model_path=tmp_path / "missing.joblib",
            tranco_path=tranco_file,
            domain_allowlist_path=allowlist_file,
        )
    assert "DGA model not found" in caplog.text
    assert det.process(dns_flow(DGA_HOST)) == []


def test_bare_model_without_bundle_is_accepted(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.9)
    det = DgaDetector(
        cfg, model=stub, tranco_path=tranco_file, domain_allowlist_path=allowlist_file
    )
    assert det.process(dns_flow(DGA_HOST))[0].score == pytest.approx(0.9)


# --- criterion 4: burst boost ------------------------------------------------------------------


def _hosts(n: int) -> list[str]:
    return [f"xkqzjv{chr(ord('a') + i)}pthrb.com" for i in range(n)]


def test_fifth_lookup_within_window_scores_higher(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.85)
    det = make(cfg, stub, tranco_file, allowlist_file)

    scores = [
        det.process(dns_flow(h, ts_ms=T0_MS + i * 10_000))[0].score
        for i, h in enumerate(_hosts(5))
    ]

    assert scores[:4] == [pytest.approx(0.85)] * 4
    assert scores[4] > scores[0]
    assert scores[4] == pytest.approx(0.95)


def test_lookups_spread_over_more_than_window_are_not_boosted(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.85)
    det = make(cfg, stub, tranco_file, allowlist_file)

    # 5 lookups 20 s apart span 80 s: never 5 inside one 60 s window.
    scores = [
        det.process(dns_flow(h, ts_ms=T0_MS + i * 20_000))[0].score
        for i, h in enumerate(_hosts(5))
    ]

    assert scores == [pytest.approx(0.85)] * 5


def test_burst_is_per_process(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.85)
    det = make(cfg, stub, tranco_file, allowlist_file)
    for i, h in enumerate(_hosts(4)):
        det.process(dns_flow(h, ts_ms=T0_MS + i * 1000, process="a.exe"))
    sig = det.process(dns_flow(DGA_HOST, ts_ms=T0_MS + 5000, process="b.exe"))[0]
    assert sig.score == pytest.approx(0.85)


def test_burst_boost_is_capped_at_one(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.97)
    det = make(cfg, stub, tranco_file, allowlist_file)
    scores = [
        det.process(dns_flow(h, ts_ms=T0_MS + i * 1000))[0].score for i, h in enumerate(_hosts(6))
    ]
    assert scores[4] == 1.0
    assert scores[5] == 1.0
    assert all(s <= 1.0 for s in scores)


def test_below_threshold_lookups_do_not_count_toward_burst(cfg, tranco_file, allowlist_file):
    stub = StubModel(0.5)
    det = make(cfg, stub, tranco_file, allowlist_file)
    for i, h in enumerate(_hosts(4)):
        assert det.process(dns_flow(h, ts_ms=T0_MS + i * 1000)) == []
    stub.p_dga = 0.85
    assert det.process(dns_flow(DGA_HOST, ts_ms=T0_MS + 5000))[0].score == pytest.approx(0.85)


# --- criterion 5: threshold comes from config.yaml ---------------------------------------------


def _config_with_threshold(tmp_path: Path, threshold: float) -> dict[str, Any]:
    text = (REPO_ROOT / "config.yaml").read_text(encoding="utf-8")
    old = "probability_threshold: 0.8 "
    assert old in text
    path = tmp_path / f"config_{threshold}.yaml"
    path.write_text(text.replace(old, f"probability_threshold: {threshold} "), encoding="utf-8")
    return config.load(path)


def test_threshold_is_read_from_config_file(tmp_path, tranco_file, allowlist_file):
    stub = StubModel(0.85)

    strict = make(_config_with_threshold(tmp_path, 0.9), stub, tranco_file, allowlist_file)
    assert strict.process(dns_flow(DGA_HOST)) == []

    loose = make(_config_with_threshold(tmp_path, 0.8), stub, tranco_file, allowlist_file)
    assert len(loose.process(dns_flow(DGA_HOST))) == 1

    lower = make(_config_with_threshold(tmp_path, 0.5), StubModel(0.6), tranco_file, allowlist_file)
    assert lower.process(dns_flow(DGA_HOST))[0].score == pytest.approx(0.6)


# --- helpers -----------------------------------------------------------------------------------


def test_candidate_domains_stop_at_registered_domain():
    expected = ["a.b.google.com", "b.google.com", "google.com"]
    assert dga.candidate_domains("a.b.google.com") == expected
    assert dga.candidate_domains("news.bbc.co.uk") == ["news.bbc.co.uk", "bbc.co.uk"]
    assert dga.candidate_domains("google.com") == ["google.com"]
