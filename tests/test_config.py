"""Tests for agent.config: config.yaml loading/validation and the allowlist helper."""

from __future__ import annotations

import os
import subprocess
import sys
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


# --- installed (frozen) layout: bundle root vs data root (ticket #50) ----------------------


def test_running_from_source_both_roots_are_the_repo() -> None:
    assert config.FROZEN is False
    assert config.REPO_ROOT == REPO_ROOT
    assert config.BUNDLE_ROOT == REPO_ROOT
    assert config.DEFAULT_CONFIG_PATH == REPO_ROOT / "config.yaml"
    assert config.default_config_path() == REPO_ROOT / "config.yaml"
    assert config.seed_data_root() == []  # same root: nothing copied


def test_frozen_roots_are_meipass_and_programdata(tmp_path: Path) -> None:
    assert config.bundle_root_for(True, str(tmp_path)) == tmp_path
    assert config.bundle_root_for(False, str(tmp_path)) == REPO_ROOT
    env = {"PROGRAMDATA": str(tmp_path / "PD")}
    assert config.data_root_for(True, env) == tmp_path / "PD" / "HomeSOC"
    assert config.data_root_for(True, {"ALLUSERSPROFILE": "X"}) == Path("X") / "HomeSOC"
    assert config.data_root_for(False, env) == REPO_ROOT


def test_frozen_import_resolves_every_relative_path_under_programdata(tmp_path: Path) -> None:
    # A real import of agent.config with sys.frozen / sys._MEIPASS set, as PyInstaller does.
    code = (
        "import sys; sys.frozen = True; sys._MEIPASS = sys.argv[1]\n"
        "from agent import config\n"
        "print(config.FROZEN, config.BUNDLE_ROOT, config.REPO_ROOT, config.DEFAULT_STORE_PATH,"
        " config.store_path({'store': {'path': 'data/homesoc.db'}}), sep='|')\n"
    )
    env = dict(os.environ, PROGRAMDATA=str(tmp_path / "PD"))
    out = subprocess.run([sys.executable, "-c", code, str(tmp_path / "bundle")], cwd=REPO_ROOT,
                         env=env, capture_output=True, text=True, check=True).stdout.strip()
    frozen, bundle, data, default_store, store = out.split("|")
    data_root = tmp_path / "PD" / "HomeSOC"
    assert frozen == "True"
    assert Path(bundle) == tmp_path / "bundle"
    assert Path(data) == data_root
    assert Path(default_store) == Path(store) == data_root / "data" / "homesoc.db"


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    for rel in config.SEED_IF_MISSING + config.SEED_REFRESH:
        (bundle / rel).parent.mkdir(parents=True, exist_ok=True)
        (bundle / rel).write_bytes(f"bundled {rel}".encode())
    return bundle


def test_seed_copies_every_bundled_file_into_an_empty_data_root(tmp_path: Path) -> None:
    bundle, data = _bundle(tmp_path), tmp_path / "data_root"
    written = config.seed_data_root(bundle, data)
    rels = config.SEED_IF_MISSING + config.SEED_REFRESH
    assert sorted(written) == sorted(data / rel for rel in rels)
    for rel in rels:
        assert (data / rel).read_bytes() == f"bundled {rel}".encode()
    assert (data / "data" / "cache").is_dir()
    assert config.seed_data_root(bundle, data) == []  # second start: nothing to do


def test_seed_keeps_user_edits_but_refreshes_changed_models(tmp_path: Path) -> None:
    bundle, data = _bundle(tmp_path), tmp_path / "data_root"
    config.seed_data_root(bundle, data)
    (data / "config.yaml").write_text("edited by the user", encoding="utf-8")
    (bundle / "config.yaml").write_text("new bundled config", encoding="utf-8")
    (bundle / "models" / "dga.joblib").write_bytes(b"retrained model")
    written = config.seed_data_root(bundle, data)
    assert written == [data / "models" / "dga.joblib"]
    assert (data / "config.yaml").read_text(encoding="utf-8") == "edited by the user"
    assert (data / "models" / "dga.joblib").read_bytes() == b"retrained model"


def test_seed_skips_a_file_missing_from_the_bundle(tmp_path: Path) -> None:
    bundle, data = _bundle(tmp_path), tmp_path / "data_root"
    (bundle / "models" / "flow.joblib").unlink()
    written = config.seed_data_root(bundle, data)
    assert data / "models" / "flow.joblib" not in written
    assert not (data / "models" / "flow.joblib").exists()
    assert (data / "models" / "dga.joblib").is_file()


def test_default_config_falls_back_to_the_bundle_until_seeded(tmp_path: Path) -> None:
    bundle, data = _bundle(tmp_path), tmp_path / "data_root"
    assert config.default_config_path(data, bundle) == bundle / "config.yaml"
    config.seed_data_root(bundle, data)
    assert config.default_config_path(data, bundle) == data / "config.yaml"
