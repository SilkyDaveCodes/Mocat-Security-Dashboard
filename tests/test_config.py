"""Tests for agent.config: config.yaml loading/validation and the allowlist helper."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent import config
from agent.config import ConfigError

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def real_config() -> dict:
    return config.load()


def _write_config(tmp_path: Path, **overrides: object) -> Path:
    """Copy the real config.yaml into tmp_path with some top-level keys replaced."""
    data = yaml.safe_load((REPO_ROOT / "config.yaml").read_text(encoding="utf-8"))
    data.update(overrides)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# --- config.yaml ---------------------------------------------------------------------------


def test_load_defaults_to_repo_root_config(real_config: dict) -> None:
    explicit = config.load(REPO_ROOT / "config.yaml")
    assert real_config == explicit


def test_config_has_mode_interface_and_capture_timeouts(real_config: dict) -> None:
    assert real_config["mode"] in ("off", "notify", "auto")
    capture = real_config["capture"]
    assert isinstance(capture["interface"], str) and capture["interface"]
    assert capture["idle_timeout"] == 10
    assert capture["active_timeout"] == 30
    assert real_config["calibration"]["minutes"] == 10


def test_config_has_detector_thresholds(real_config: dict) -> None:
    det = real_config["detectors"]
    assert det["intel"]["refresh_interval_s"] > 0

    assert det["dga"]["probability_threshold"] == 0.8
    assert det["dga"]["burst_count"] == 5
    assert det["dga"]["burst_window_s"] == 60

    beacon = det["beacon"]
    assert beacon["history"] == 20
    assert beacon["min_starts"] == 6
    assert beacon["mean_interval_min_s"] == 2
    assert beacon["mean_interval_max_s"] == 600
    assert beacon["cv_max"] == 0.1
    assert beacon["score"] == 0.9
    assert beacon["high_score"] == 0.95
    assert beacon["high_score_min_starts"] == 12

    anomaly = det["anomaly"]
    assert anomaly["min_windows"] == 30
    assert anomaly["window_s"] == 60
    assert anomaly["bytes_out_threshold"] == 10_000_000
    assert anomaly["score_min"] == 0.6
    assert anomaly["score_max"] == 0.9

    assert det["flow_model"]["probability_threshold"] == 0.85


def test_config_has_scoring_thresholds(real_config: dict) -> None:
    scoring = real_config["scoring"]
    assert scoring["window_s"] == 60
    assert scoring["context_boost"] == 1.2
    assert scoring["alert_threshold"] == 0.5
    assert scoring["severity"] == {"medium": 0.5, "high": 0.75, "critical": 0.9}
    assert scoring["auto_quarantine"] == {"risk": 0.85, "min_detectors": 2}


def test_config_api_binds_loopback_only(real_config: dict) -> None:
    api = real_config["api"]
    assert api["host"] == "127.0.0.1"
    assert api["port"] == 8765
    assert api["ws_flow_rate_limit_per_s"] == 5


@pytest.mark.parametrize("mode", ["off", "notify", "auto"])
def test_each_valid_mode_loads(tmp_path: Path, mode: str) -> None:
    assert config.load(_write_config(tmp_path, mode=mode))["mode"] == mode


@pytest.mark.parametrize("mode", ["off", "notify", "auto"])
def test_each_mode_loads_when_hand_written_unquoted(tmp_path: Path, mode: str) -> None:
    # Edit the real file's text the way a person would, so YAML sees a bare `mode: off`.
    text = (REPO_ROOT / "config.yaml").read_text(encoding="utf-8")
    assert "\nmode: notify\n" in text
    path = tmp_path / "config.yaml"
    path.write_text(text.replace("\nmode: notify\n", f"\nmode: {mode}\n"), encoding="utf-8")
    assert config.load(path)["mode"] == mode


@pytest.mark.parametrize("bad", ["true", "yes", "on"])
def test_yaml_true_mode_is_rejected(tmp_path: Path, bad: str) -> None:
    text = (REPO_ROOT / "config.yaml").read_text(encoding="utf-8")
    path = tmp_path / "config.yaml"
    path.write_text(text.replace("\nmode: notify\n", f"\nmode: {bad}\n"), encoding="utf-8")
    with pytest.raises(ConfigError, match="allowed modes are"):
        config.load(path)


def test_invalid_mode_raises_clear_error(tmp_path: Path) -> None:
    path = _write_config(tmp_path, mode="panic")
    with pytest.raises(ConfigError) as excinfo:
        config.load(path)
    message = str(excinfo.value)
    assert "'panic'" in message
    for allowed in ("off", "notify", "auto"):
        assert allowed in message


def test_config_error_is_a_value_error() -> None:
    assert issubclass(ConfigError, ValueError)


def test_non_loopback_api_host_is_rejected(tmp_path: Path) -> None:
    path = _write_config(tmp_path, api={"host": "0.0.0.0", "port": 8765})
    with pytest.raises(ConfigError, match="0.0.0.0"):
        config.load(path)


def test_missing_section_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("mode: notify\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="capture"):
        config.load(path)


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        config.load(tmp_path / "nope.yaml")


# --- data/allowlist.txt --------------------------------------------------------------------

SECTION_6_4_APPS = [
    # browsers
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    # Windows Update
    "svchost.exe", "wuauclt.exe", "usoclient.exe", "MoUsoCoreWorker.exe",
    # Steam, Discord, Spotify
    "steam.exe", "steamwebhelper.exe", "discord.exe", "spotify.exe",
    # Defender
    "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe",
]  # fmt: skip


@pytest.mark.parametrize("exe", SECTION_6_4_APPS)
def test_real_allowlist_contains_section_6_4_apps(exe: str) -> None:
    assert exe in config.load_allowlist()


def test_real_allowlist_has_exactly_the_listed_apps() -> None:
    allowlist = config.load_allowlist()
    assert allowlist.names == frozenset(e.casefold() for e in SECTION_6_4_APPS)
    assert "freegamecheats.exe" not in allowlist


def test_allowlist_ignores_comments_and_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.txt"
    path.write_text("# header comment\n\n   \nfoo.exe\n  # indented comment\nbar.exe  \n", "utf-8")
    allowlist = config.load_allowlist(path)
    assert allowlist.names == frozenset({"foo.exe", "bar.exe"})
    assert len(allowlist) == 2
    assert "# header comment" not in allowlist
    assert "" not in allowlist


def test_allowlist_matching_is_case_insensitive(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.txt"
    path.write_text("MsMpEng.exe\nchrome.exe\n", encoding="utf-8")
    allowlist = config.load_allowlist(path)
    assert "msmpeng.exe" in allowlist
    assert "MSMPENG.EXE" in allowlist
    assert "Chrome.EXE" in allowlist
    assert "evil.exe" not in allowlist


def test_test_intel_holds_only_the_lab_c2() -> None:
    lines = (REPO_ROOT / "data" / "test_intel.txt").read_text(encoding="utf-8").splitlines()
    entries = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    assert entries == ["192.168.56.20"]
