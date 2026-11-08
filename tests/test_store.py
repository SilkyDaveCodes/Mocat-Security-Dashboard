"""Tests for agent.store: SQLite persistence of alerts, actions and baselines (ticket #8)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from agent import config
from agent.events import Action, Alert, Signal
from agent.store import Store


def _alert(alert_id: str = "a1", ts_ms: int = 1_000, **overrides: object) -> Alert:
    base = Alert(
        id=alert_id,
        ts_ms=ts_ms,
        severity="high",
        process="freegamecheats.exe",
        exe_path=r"C:\Users\demo\Downloads\FreeGameCheats.exe",
        risk=0.93,
        title="FreeGameCheats.exe is talking to a command server",
        what_happened="It checks in every 5 s.",
        what_we_did="We quarantined it.",
        what_you_should_do="Delete it.",
        signals=[
            Signal(
                detector="beacon",
                process="freegamecheats.exe",
                pid=4242,
                target="192.168.56.20",
                score=0.9,
                reasons=["checks in with 192.168.56.20 every 5.0 s (±0.2 s)"],
                mitre="T1071.001",
                ts_ms=900,
            ),
            Signal(
                detector="dga",
                process="freegamecheats.exe",
                pid=4242,
                target="xkqzvbnrtp.com",
                score=0.88,
                reasons=["random-looking domain"],
                mitre=None,
                ts_ms=950,
            ),
        ],
        action_ids=["act-1", "act-2"],
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _action(action_id: str = "act-1", ts_ms: int = 2_000, **overrides: object) -> Action:
    base = Action(
        id=action_id,
        ts_ms=ts_ms,
        kind="quarantine_app",
        target=r"C:\Users\demo\Downloads\FreeGameCheats.exe",
        rule_names=[
            "HomeSOC quarantine FreeGameCheats.exe out #deadbeef",
            "HomeSOC quarantine FreeGameCheats.exe in #deadbeef",
        ],
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "sub" / "homesoc.db"


# --- alerts ---------------------------------------------------------------------------------


def test_saved_alert_with_signals_reads_back_equal(db_path: Path) -> None:
    original = _alert()
    with Store(db_path) as store:
        store.save_alert(original)
        loaded = store.get_alert("a1")
    assert loaded == original
    assert all(isinstance(s, Signal) for s in loaded.signals)
    assert loaded is not original


def test_saved_alert_reads_back_equal_after_reopen(db_path: Path) -> None:
    original = _alert()
    with Store(db_path) as store:
        store.save_alert(original)
    with Store(db_path) as store:
        assert store.get_alert("a1") == original
        assert store.list_alerts() == [original]


def test_alert_with_no_signals_round_trips(db_path: Path) -> None:
    original = Alert(id="bare", ts_ms=5)
    with Store(db_path) as store:
        store.save_alert(original)
        assert store.get_alert("bare") == original


def test_get_unknown_alert_returns_none(db_path: Path) -> None:
    with Store(db_path) as store:
        assert store.get_alert("nope") is None


def test_save_alert_upserts(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_alert(_alert(action_ids=[]))
        store.save_alert(_alert(action_ids=["act-9"], what_we_did="Blocked."))
        alerts = store.list_alerts()
    assert len(alerts) == 1
    assert alerts[0].action_ids == ["act-9"]
    assert alerts[0].what_we_did == "Blocked."


def test_list_alerts_newest_first(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_alert(_alert("old", ts_ms=100))
        store.save_alert(_alert("newest", ts_ms=300))
        store.save_alert(_alert("middle", ts_ms=200))
        assert [a.id for a in store.list_alerts()] == ["newest", "middle", "old"]
        assert [a.id for a in store.list_alerts(limit=2)] == ["newest", "middle"]


def test_list_alerts_equal_ts_latest_inserted_first_and_stable_on_resave(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_alert(_alert("first", ts_ms=100))
        store.save_alert(_alert("second", ts_ms=100))
        assert [a.id for a in store.list_alerts()] == ["second", "first"]
        # Re-saving (e.g. after finalize_alert) does not move it.
        store.save_alert(_alert("first", ts_ms=100, action_ids=["x"]))
        assert [a.id for a in store.list_alerts()] == ["second", "first"]


def test_save_alert_with_empty_id_raises(db_path: Path) -> None:
    with Store(db_path) as store, pytest.raises(ValueError):
        store.save_alert(Alert(id=""))


# --- actions --------------------------------------------------------------------------------


def test_saved_action_survives_reopen_with_rule_names(db_path: Path) -> None:
    original = _action()
    store = Store(db_path)
    store.save_action(original)
    store.close()

    reopened = Store(db_path)
    try:
        loaded = reopened.get_action("act-1")
        assert loaded == original
        assert loaded.rule_names == [
            "HomeSOC quarantine FreeGameCheats.exe out #deadbeef",
            "HomeSOC quarantine FreeGameCheats.exe in #deadbeef",
        ]
        assert loaded.undone is False
        assert reopened.list_actions() == [original]
    finally:
        reopened.close()


def test_action_rule_names_with_awkward_characters_round_trip(db_path: Path) -> None:
    names = ["HomeSOC quarantine it's [1]*.exe out #00000001", 'HomeSOC "x"; $y` in #00000001']
    with Store(db_path) as store:
        store.save_action(_action("weird", rule_names=names))
    with Store(db_path) as store:
        assert store.get_action("weird").rule_names == names


def test_get_unknown_action_returns_none(db_path: Path) -> None:
    with Store(db_path) as store:
        assert store.get_action("missing") is None


def test_list_actions_newest_first_and_undone_filter(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_action(_action("a", ts_ms=1))
        store.save_action(_action("c", ts_ms=3, undone=True))
        store.save_action(_action("b", ts_ms=2))
        assert [a.id for a in store.list_actions()] == ["c", "b", "a"]
        assert [a.id for a in store.list_actions(undone=False)] == ["b", "a"]
        assert [a.id for a in store.list_actions(undone=True)] == ["c"]
        assert [a.id for a in store.list_actions(limit=1)] == ["c"]


def test_mark_undone_sets_flag_and_persists(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_action(_action())
        assert store.mark_undone("act-1") is True
        assert store.get_action("act-1").undone is True
    with Store(db_path) as store:
        loaded = store.get_action("act-1")
        assert loaded.undone is True
        assert loaded.rule_names == _action().rule_names


def test_mark_undone_unknown_id_returns_false(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_action(_action())
        assert store.mark_undone("does-not-exist") is False
        assert store.get_action("act-1").undone is False
        assert store.get_action("does-not-exist") is None


def test_mark_all_undone(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_action(_action("a"))
        store.save_action(_action("b"))
        store.save_action(_action("c", undone=True))
        assert store.mark_all_undone() == 2
    with Store(db_path) as store:
        assert all(a.undone for a in store.list_actions())


def test_save_action_upserts(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_action(_action())
        store.save_action(_action(undone=True))
        assert len(store.list_actions()) == 1
        assert store.get_action("act-1").undone is True


def test_save_action_with_empty_id_raises(db_path: Path) -> None:
    with Store(db_path) as store, pytest.raises(ValueError):
        store.save_action(Action(id=""))


# --- baselines ------------------------------------------------------------------------------


def test_baselines_saved_and_loaded_per_process(db_path: Path) -> None:
    chrome = {"windows": [[1000, 5, 3], [2000, 7, 4]], "calibrated_at_ms": 123}
    spotify = {"windows": [[50, 1, 1]], "calibrated_at_ms": 456}
    with Store(db_path) as store:
        store.save_baseline("chrome.exe", chrome)
        store.save_baseline("spotify.exe", spotify)
    with Store(db_path) as store:
        assert store.load_baseline("chrome.exe") == chrome
        assert store.load_baseline("spotify.exe") == spotify
        assert store.load_baseline("unknown.exe") is None
        assert store.load_baselines() == {"chrome.exe": chrome, "spotify.exe": spotify}


def test_save_baseline_replaces_previous(db_path: Path) -> None:
    with Store(db_path) as store:
        store.save_baseline("chrome.exe", {"v": 1})
        store.save_baseline("chrome.exe", {"v": 2})
        assert store.load_baseline("chrome.exe") == {"v": 2}
        assert store.load_baselines() == {"chrome.exe": {"v": 2}}


def test_save_baseline_rejects_non_dict_and_non_json(db_path: Path) -> None:
    with Store(db_path) as store:
        with pytest.raises(TypeError):
            store.save_baseline("x.exe", [1, 2, 3])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            store.save_baseline("x.exe", {"bad": object()})
        assert store.load_baseline("x.exe") is None


# --- plumbing -------------------------------------------------------------------------------


def test_store_creates_parent_dir(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "homesoc.db"
    with Store(path) as store:
        assert store.path == path
    assert path.is_file()


def test_store_path_comes_from_config(tmp_path: Path) -> None:
    cfg = config.load()
    assert cfg["store"]["path"] == "data/homesoc.db"
    assert config.store_path(cfg) == config.REPO_ROOT / "data" / "homesoc.db"
    assert config.store_path({}) == config.DEFAULT_STORE_PATH

    absolute = tmp_path / "cfg.db"
    with Store.from_config({"store": {"path": str(absolute)}}) as store:
        assert store.path == absolute
    assert absolute.is_file()


def test_store_is_usable_from_several_threads(db_path: Path) -> None:
    with Store(db_path) as store:
        errors: list[BaseException] = []

        def worker(n: int) -> None:
            try:
                for i in range(20):
                    store.save_action(_action(f"t{n}-{i}", ts_ms=n * 100 + i))
            except BaseException as exc:  # pragma: no cover - only on failure
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(store.list_actions()) == 80
