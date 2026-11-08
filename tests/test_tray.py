"""Tests for the tray shield (app/tray.py, CLAUDE.md §6.7, ticket #42; MoCat logo icon: #63).

* :func:`app.tray.tray_state` colours: green / yellow / red, and "active" = not every action of
  the alert undone.
* Undoing the last high alert's action through the real API (``create_app`` + a real store, a
  fake firewall) turns the tray from red back to yellow / green.
* The Mode menu items send ``POST /mode`` and Undo all sends ``POST /undo-all`` to
  ``http://127.0.0.1:8765`` (recorded by a fake HTTP client, and against the real API).
* The pystray icon is built from the same menu with a fake ``pystray`` module (no display).
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent.api import FlowTracker, create_app
from agent.config import Allowlist
from agent.events import Action, Alert, to_json
from agent.scoring import Scorer
from agent.store import Store
from app import main as app_main
from app import tray as tray_mod
from app.tray import AgentApi, Tray, build_icon, is_active, poll, tray_settings, tray_state
from tests.api_helpers import CLIENT_HEADERS

BASE = "http://127.0.0.1:8765"
EXE = r"C:\Users\demo\Downloads\FreeGameCheats.exe"


def alert(alert_id: str, severity: str, action_ids: list[str] | None = None,
          ts_ms: int = 10) -> dict[str, Any]:
    return to_json(Alert(id=alert_id, ts_ms=ts_ms, severity=severity,  # type: ignore[arg-type]
                         process="FreeGameCheats.exe", exe_path=EXE, risk=0.9, title="t",
                         action_ids=action_ids or []))


def action(action_id: str, undone: bool = False, kind: str = "quarantine_app") -> dict[str, Any]:
    return to_json(Action(id=action_id, ts_ms=5, kind=kind,  # type: ignore[arg-type]
                          target=EXE, rule_names=[f"HomeSOC quarantine x out #{action_id}"],
                          undone=undone))


# --- tray_state: pure colour logic -------------------------------------------------------------


def test_no_alerts_is_green() -> None:
    assert tray_state([]) == "green"
    assert tray_state([], [action("a1")]) == "green"


@pytest.mark.parametrize("severities", [["low"], ["medium"], ["low", "medium", "low"]])
def test_only_low_or_medium_alerts_is_yellow(severities: list[str]) -> None:
    alerts = [alert(f"al{i}", s) for i, s in enumerate(severities)]
    assert tray_state(alerts) == "yellow"


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_any_active_high_or_critical_is_red(severity: str) -> None:
    alerts = [alert("al1", "low"), alert("al2", severity), alert("al3", "medium")]
    assert tray_state(alerts) == "red"


def test_high_alert_whose_actions_are_all_undone_is_not_active() -> None:
    high = alert("al1", "high", ["a1", "a2"])
    assert not is_active(high, {"a1": action("a1", True), "a2": action("a2", True)})
    assert tray_state([high], [action("a1", True), action("a2", True)]) == "green"
    assert tray_state([high, alert("al2", "medium")],
                      [action("a1", True), action("a2", True)]) == "yellow"


def test_high_alert_with_one_action_still_in_force_stays_red() -> None:
    high = alert("al1", "high", ["a1", "a2"])
    assert tray_state([high], [action("a1", True), action("a2", False)]) == "red"


def test_alert_without_actions_or_with_unknown_action_stays_active() -> None:
    assert tray_state([alert("al1", "critical")], [action("x", True)]) == "red"
    # The action id is not in GET /actions (e.g. not loaded): in doubt, keep warning.
    assert tray_state([alert("al1", "high", ["missing"])], []) == "red"


# --- HTTP calls (fake client) ------------------------------------------------------------------


class FakeResponse:
    def __init__(self, data: Any, status: int = 200) -> None:
        self._data = data
        self.status_code = status

    def json(self) -> Any:
        return self._data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttp:
    """Records every call; answers like the agent API."""

    def __init__(self, alerts: list[dict[str, Any]] | None = None,
                 actions: list[dict[str, Any]] | None = None, mode: str = "notify") -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.post_headers: list[dict[str, str] | None] = []  # headers= of each POST, in order
        self.alerts = alerts or []
        self.actions = actions or []
        self.mode = mode
        self.down = False

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("GET", url, None))
        if self.down:
            raise ConnectionError("agent offline")
        path = url.removeprefix(BASE).split("?")[0]
        data = {"/alerts": {"alerts": self.alerts}, "/actions": {"actions": self.actions},
                "/status": {"status": "running", "mode": self.mode}}[path]
        return FakeResponse(data)

    def post(self, url: str, json: Any = None, **kwargs: Any) -> FakeResponse:
        self.calls.append(("POST", url, json))
        self.post_headers.append(kwargs.get("headers"))
        if url == f"{BASE}/mode":
            self.mode = json["mode"]
            return FakeResponse({"mode": self.mode})
        if url == f"{BASE}/undo-all":
            for a in self.actions:
                a["undone"] = True
            return FakeResponse({"undone": len(self.actions), "undo": {}})
        return FakeResponse({"detail": "not found"}, 404)

    def posts(self) -> list[tuple[str, str, Any]]:
        return [c for c in self.calls if c[0] == "POST"]


def entry(menu: list[tray_mod.MenuEntry], label: str) -> tray_mod.MenuEntry:
    return next(e for e in menu if e.label == label)


def test_menu_has_open_mode_undo_all_quit() -> None:
    menu = Tray(AgentApi(FakeHttp())).menu()
    assert [e.label for e in menu] == ["Open", "Mode", "Undo all", "Quit"]
    assert [e.label for e in entry(menu, "Mode").children] == ["off", "notify", "auto"]


@pytest.mark.parametrize("mode", ["off", "notify", "auto"])
def test_mode_menu_item_posts_mode(mode: str) -> None:
    http = FakeHttp(mode="notify" if mode != "notify" else "off")
    tray = Tray(AgentApi(http))
    item = entry(entry(tray.menu(), "Mode").children, mode)
    assert item.action is not None and item.checked is not None
    item.action()
    assert http.posts() == [("POST", f"{BASE}/mode", {"mode": mode})]
    assert tray.mode == mode
    assert item.checked() is True
    others = [e for e in entry(tray.menu(), "Mode").children if e.label != mode]
    assert all(e.checked is not None and e.checked() is False for e in others)


def test_undo_all_menu_item_posts_undo_all_and_refreshes_colour() -> None:
    http = FakeHttp(alerts=[alert("al1", "high", ["a1"])], actions=[action("a1")])
    tray = Tray(AgentApi(http))
    assert tray.refresh() == "red"
    action_fn = entry(tray.menu(), "Undo all").action
    assert action_fn is not None
    action_fn()
    assert http.posts() == [("POST", f"{BASE}/undo-all", None)]
    assert tray.colour == "green"


def test_every_request_goes_to_the_local_agent_only() -> None:
    http = FakeHttp()
    tray = Tray(AgentApi(http))
    tray.refresh()
    tray.set_mode("auto")
    tray.undo_all()
    assert http.calls
    assert all(url.startswith(BASE + "/") for _, url, _ in http.calls)
    with pytest.raises(ValueError):
        AgentApi(http, base_url="http://10.0.0.5:8765")


def test_every_tray_post_sends_the_client_header() -> None:
    """#71: the agent answers 403 to a POST without X-MoCat: 1."""
    http = FakeHttp()
    tray = Tray(AgentApi(http))
    tray.set_mode("auto")
    tray.undo_all()
    assert len(http.posts()) == 2
    assert http.post_headers == [{"X-MoCat": "1"}, {"X-MoCat": "1"}]
    assert (app_main.API_CLIENT_HEADER, app_main.API_CLIENT_HEADER_VALUE) == ("X-MoCat", "1")


def test_tray_post_without_header_would_be_refused_by_the_real_api(
    api_client: TestClient, scorer: Scorer
) -> None:
    """Guards the test above: the real API does refuse a header-less POST from this client."""
    assert api_client.post(f"{BASE}/mode", json={"mode": "auto"}).status_code == 403
    assert scorer.mode == "notify"
    assert AgentApi(api_client).set_mode("auto") == "auto"
    assert scorer.mode == "auto"


def test_open_and_quit_call_their_hooks() -> None:
    seen: list[str] = []
    tray = Tray(AgentApi(FakeHttp()), on_open=lambda: seen.append("open"),
                on_quit=lambda: seen.append("quit"))
    for label in ("Open", "Quit"):
        fn = entry(tray.menu(), label).action
        assert fn is not None
        fn()
    assert seen == ["open", "quit"]


def test_unknown_mode_is_refused_without_a_request() -> None:
    http = FakeHttp()
    with pytest.raises(ValueError):
        AgentApi(http).set_mode("panic")
    assert http.posts() == []


def test_agent_offline_keeps_last_colour_and_says_offline() -> None:
    http = FakeHttp(alerts=[alert("al1", "medium")])
    tray = Tray(AgentApi(http))
    assert tray.refresh() == "yellow" and tray.online
    http.down = True
    assert tray.refresh() == "yellow"
    assert not tray.online
    assert tray.title.endswith("(agent offline)")


# --- against the real API: undo the last high alert --------------------------------------------


class RecordingFirewall:
    def __init__(self) -> None:
        self.undone: list[str] = []

    def undo(self, act: Action) -> Action:
        self.undone.append(act.id)
        act.undone = True
        return Action(id=f"undo-{act.id}", ts_ms=50, kind="undo", target=act.id)

    def undo_all(self) -> Action:
        return Action(id="undo-all", ts_ms=60, kind="undo", target="HomeSOC")

    def quarantine_app(self, exe_path: str) -> Action:
        raise AssertionError("not used")

    def fns(self) -> dict[str, Any]:
        return {"undo": self.undo, "undo_all": self.undo_all,
                "quarantine_app": self.quarantine_app}


@pytest.fixture
def store(tmp_path: Path) -> Store:
    with Store(tmp_path / "homesoc.db") as db:
        yield db


@pytest.fixture
def scorer() -> Scorer:
    from agent import config
    return Scorer(config.load(), Allowlist(frozenset()), mode="notify")


class ApiClient(TestClient):
    """The real API in-process; drops ``timeout=`` (TestClient warns on it, httpx doesn't)."""

    def get(self, url: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        kwargs.pop("timeout", None)
        return super().get(url, **kwargs)

    def post(self, url: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        kwargs.pop("timeout", None)
        return super().post(url, **kwargs)


@pytest.fixture
def api_client(store: Store, scorer: Scorer) -> TestClient:
    app = create_app(store, scorer, FlowTracker(600.0), firewall_fns=RecordingFirewall().fns(),
                     allowlist=Allowlist(frozenset()))
    return ApiClient(app, base_url=BASE)


def _save(store: Store, al: dict[str, Any], *acts: Action) -> None:
    for a in acts:
        store.save_action(a)
    store.save_alert(Alert(**{k: v for k, v in al.items() if k not in ("type", "signals")}))


def q(action_id: str) -> Action:
    return Action(id=action_id, ts_ms=5, kind="quarantine_app", target=EXE,
                  rule_names=[f"HomeSOC quarantine FreeGameCheats.exe out #{action_id}"])


def test_undoing_the_last_high_alert_turns_red_to_green(api_client: TestClient,
                                                         store: Store) -> None:
    _save(store, alert("al1", "high", ["a1"]), q("a1"))
    tray = Tray(AgentApi(api_client))
    assert tray.refresh() == "red"
    assert api_client.post(f"{BASE}/actions/a1/undo", headers=CLIENT_HEADERS).status_code == 200
    assert tray.refresh() == "green"


def test_undoing_the_last_high_alert_leaves_yellow_for_a_medium_one(api_client: TestClient,
                                                                    store: Store) -> None:
    _save(store, alert("al1", "critical", ["a1"], ts_ms=20), q("a1"))
    _save(store, alert("al2", "high", ["a2"], ts_ms=30), q("a2"))
    _save(store, alert("al3", "medium", ts_ms=10))
    tray = Tray(AgentApi(api_client))
    assert tray.refresh() == "red"
    api_client.post(f"{BASE}/actions/a2/undo", headers=CLIENT_HEADERS)
    assert tray.refresh() == "red"  # the critical one is still quarantined
    api_client.post(f"{BASE}/actions/a1/undo", headers=CLIENT_HEADERS)
    assert tray.refresh() == "yellow"


def test_tray_menu_drives_the_real_api(api_client: TestClient, store: Store,
                                       scorer: Scorer) -> None:
    _save(store, alert("al1", "high", ["a1"]), q("a1"))
    tray = Tray(AgentApi(api_client))
    assert tray.refresh() == "red" and tray.mode == "notify"
    mode_auto = entry(entry(tray.menu(), "Mode").children, "auto").action
    undo_all = entry(tray.menu(), "Undo all").action
    assert mode_auto is not None and undo_all is not None
    mode_auto()
    assert scorer.mode == "auto" and tray.mode == "auto"
    undo_all()
    stored = store.get_action("a1")
    assert stored is not None and stored.undone
    assert tray.colour == "green"


def test_get_actions_lists_stored_actions(api_client: TestClient, store: Store) -> None:
    store.save_action(q("a1"))
    store.save_action(Action(id="a2", ts_ms=9, kind="block_ip", target="192.168.56.20",
                             undone=True))
    body = api_client.get(f"{BASE}/actions").json()
    assert [(a["id"], a["undone"], a["type"]) for a in body["actions"]] == [
        ("a2", True, "action"), ("a1", False, "action")]
    only_active = api_client.get(f"{BASE}/actions?undone=false").json()["actions"]
    assert [a["id"] for a in only_active] == ["a1"]
    assert api_client.get(f"{BASE}/actions?limit=0").status_code == 422


# --- polling, config, pystray icon, wiring -----------------------------------------------------


def test_poll_refreshes_until_stopped() -> None:
    http = FakeHttp(alerts=[alert("al1", "low")])
    tray = Tray(AgentApi(http))
    stop = threading.Event()
    seen: list[str] = []

    def on_change(t: Tray) -> None:
        seen.append(t.colour)
        if len(seen) == 3:
            stop.set()

    tray.on_change = on_change
    poll(tray, stop, refresh_s=0.001)
    assert seen == ["yellow", "yellow", "yellow"]


def test_tray_settings_come_from_config() -> None:
    from agent import config
    assert tray_settings(config.load()) == (5.0, 5.0)
    assert tray_settings({}) == (tray_mod.DEFAULT_REFRESH_S, tray_mod.DEFAULT_HTTP_TIMEOUT_S)
    with pytest.raises(ValueError):
        tray_settings({"app": {"tray_refresh_s": 0}})


class FakeMenuItem:
    def __init__(self, text: str, action: Any, default: bool = False, checked: Any = None,
                 radio: bool = False) -> None:
        self.text, self.action, self.default, self.checked, self.radio = (
            text, action, default, checked, radio)


class FakeMenu:
    def __init__(self, *items: FakeMenuItem) -> None:
        self.items = list(items)


class FakeIcon:
    def __init__(self, name: str, icon: Any, title: str, menu: FakeMenu) -> None:
        self.name, self.icon, self.title, self.menu = name, icon, title, menu
        self.menu_updates = 0

    def update_menu(self) -> None:
        self.menu_updates += 1


FAKE_PYSTRAY = SimpleNamespace(Icon=FakeIcon, Menu=FakeMenu, MenuItem=FakeMenuItem)


def test_build_icon_menu_and_colour_follow_the_tray() -> None:
    http = FakeHttp()
    tray = Tray(AgentApi(http))
    icon = build_icon(tray, FAKE_PYSTRAY, image_fn=lambda colour: f"shield-{colour}")
    assert icon.icon == "shield-green"
    items = icon.menu.items
    assert [i.text for i in items] == ["Open", "Mode", "Undo all", "Quit"]
    assert items[0].default is True
    mode_items = items[1].action.items
    assert [i.text for i in mode_items] == ["off", "notify", "auto"]
    assert all(i.radio for i in mode_items)

    mode_items[2].action(icon, mode_items[2])  # click "auto" like pystray does
    assert ("POST", f"{BASE}/mode", {"mode": "auto"}) in http.calls
    assert mode_items[2].checked(mode_items[2]) is True
    assert mode_items[0].checked(mode_items[0]) is False

    http.alerts = [alert("al1", "critical")]
    tray.refresh()
    assert icon.icon == "shield-red"
    assert icon.title == tray_mod.TITLES["red"]
    items[2].action(icon, items[2])  # Undo all
    assert http.posts()[-1] == ("POST", f"{BASE}/undo-all", None)


def test_start_tray_runs_icon_and_quit_closes_window() -> None:
    events: list[str] = []
    window = SimpleNamespace(show=lambda: events.append("show"),
                             destroy=lambda: events.append("destroy"))

    class RunIcon(FakeIcon):
        def run_detached(self) -> None:
            events.append("run")

        def stop(self) -> None:
            events.append("stop")

    fake = SimpleNamespace(Icon=RunIcon, Menu=FakeMenu, MenuItem=FakeMenuItem)
    icon = tray_mod.start_tray(window, cfg={"app": {"tray_refresh_s": 60}}, http=FakeHttp(),
                               pystray=fake, image_fn=lambda colour: colour)
    items = icon.menu.items
    items[0].action(icon, items[0])
    items[3].action(icon, items[3])
    assert events == ["run", "show", "stop", "destroy"]


def test_main_passes_start_tray_as_the_on_started_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(app_main, "run", lambda **kw: seen.update(kw))
    monkeypatch.setattr(app_main.logging, "basicConfig", lambda **kw: None)  # no global handlers
    app_main.main()
    assert seen["on_started"] is tray_mod.start_tray


def test_importing_the_tray_does_not_import_pystray_or_pil() -> None:
    import subprocess
    import sys
    code = ("import sys, app.tray; "
            "bad = [m for m in ('pystray', 'PIL', 'webview') if m in sys.modules]; "
            "sys.exit(1 if bad else 0)")
    repo = Path(__file__).resolve().parent.parent
    assert subprocess.run([sys.executable, "-c", code], cwd=repo).returncode == 0


# --- MoCat logo icon (ticket #63) ---------------------------------------------------------------


def _pil() -> Any:
    return pytest.importorskip("PIL.Image", reason="Pillow is needed to build the real tray image")


def _dot_centre() -> tuple[int, int]:
    s, d = tray_mod.ICON_SIZE, round(tray_mod.ICON_SIZE * tray_mod.DOT_FRACTION)
    c = s - 1 - d // 2
    return c, c


@pytest.mark.parametrize("colour", ["green", "yellow", "red"])
def test_tray_image_is_the_logo_with_a_status_dot_of_the_state_colour(colour: str) -> None:
    image = _pil()
    img = tray_mod.tray_image(colour)  # type: ignore[arg-type]
    assert img.size == (tray_mod.ICON_SIZE, tray_mod.ICON_SIZE) and img.mode == "RGBA"
    assert img.getpixel(_dot_centre()) == (*tray_mod.COLOURS_RGB[colour], 255)
    # Outside the dot it is the logo itself (not the plain shield): same pixels as logo.png.
    with image.open(tray_mod.LOGO_PATH) as logo:
        ref = logo.convert("RGBA").resize(img.size, image.Resampling.LANCZOS)
    s = tray_mod.ICON_SIZE
    for xy in [(0, 0), (s // 2, s // 3), (s // 3, s // 2), (s // 2, s // 8)]:
        assert img.getpixel(xy) == ref.getpixel(xy), xy
    centre = (s // 2, s // 3)
    assert img.getpixel(centre) != tray_mod.shield_image(colour).getpixel(centre)


def test_tray_images_differ_only_by_the_dot_colour() -> None:
    _pil()
    imgs = {c: tray_mod.tray_image(c) for c in ("green", "yellow", "red")}  # type: ignore[misc]
    assert len({im.getpixel(_dot_centre()) for im in imgs.values()}) == 3
    assert imgs["green"].getpixel((0, 0)) == imgs["red"].getpixel((0, 0))


def test_tray_logo_path_is_the_bundled_ui_folder() -> None:
    # app/ui is bundled as app/ui (homesoc.spec) and app.main.UI_DIR follows app/main.py there.
    assert tray_mod.LOGO_PATH == app_main.UI_DIR / "logo.png"
    assert tray_mod.LOGO_PATH.is_file()


@pytest.mark.parametrize("bad", ["missing.png", "not_an_image.png"])
def test_tray_image_falls_back_to_the_plain_shield(bad: str, tmp_path: Path,
                                                    caplog: pytest.LogCaptureFixture) -> None:
    _pil()
    path = tmp_path / bad
    if bad == "not_an_image.png":
        path.write_bytes(b"not a png")
    img = tray_mod.tray_image("red", path)
    plain = tray_mod.shield_image("red")
    assert img.tobytes() == plain.tobytes()
    assert "plain shield" in caplog.text


def test_build_icon_uses_the_logo_image_by_default() -> None:
    _pil()
    http = FakeHttp()
    icon = build_icon(Tray(AgentApi(http)), FAKE_PYSTRAY)
    assert icon.icon.getpixel(_dot_centre()) == (*tray_mod.COLOURS_RGB["green"], 255)
