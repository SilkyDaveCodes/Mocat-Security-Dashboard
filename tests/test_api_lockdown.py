"""#71: the agent API is locked to this PC (CLAUDE.md §6.6).

* ``Host`` other than ``127.0.0.1`` / ``localhost`` -> 400 on every route (DNS rebinding).
* ``WS /ws`` refuses a foreign or ``null`` ``Origin``; loopback origins and no Origin connect.
* Every ``POST`` without ``X-MoCat: 1`` -> 403 and nothing happens (no firewall call, no store
  write, mode unchanged). Preflight (``OPTIONS``) still works for loopback origins.

Routes are enumerated from the real app, so a route added later is covered automatically.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDenialResponse
from starlette.websockets import WebSocketDisconnect

from agent import api, config
from agent.api import FlowTracker, create_app
from agent.bus import Bus
from agent.config import Allowlist
from agent.events import to_json
from agent.scoring import Scorer
from agent.store import Store
from tests.api_helpers import CLIENT_HEADERS, LOCAL_WS_URL, local_client
from tests.test_api import FakeClock, FakeFirewall, make_action, make_alert
from tests.test_api_ws import recv

OTHER_EXE = r"C:\Users\demo\Downloads\Other.exe"  # not yet quarantined (a1 quarantines EXE)


def _build(store: Store, scorer: Scorer, fw: FakeFirewall, bus: Bus | None = None) -> Any:
    return create_app(store, scorer, FlowTracker(600.0, FakeClock()), firewall_fns=fw.fns(),
                      allowlist=Allowlist(frozenset()), clock=FakeClock(), bus=bus,
                      self_exes=frozenset())


def _concrete(path: str) -> str:
    """A request path for a route template (``/actions/{action_id}/undo`` -> ``.../a1/undo``)."""
    filled = {"action_id": "a1", "alert_id": "al1"}
    return re.sub(r"\{(\w+)[^}]*\}", lambda m: filled.get(m.group(1), "x"), path)


def _http_routes() -> list[tuple[str, str]]:
    app = create_app(Store(":memory:"), Scorer(config.load(), Allowlist(frozenset())),
                     FlowTracker(600.0), firewall_fns={}, allowlist=Allowlist(frozenset()))
    routes = []
    for route in app.routes:  # API routes plus FastAPI's own /docs, /openapi.json, ...
        methods = getattr(route, "methods", None) or set()
        routes.extend((method, route.path) for method in sorted(methods))
    assert any(isinstance(r, APIRoute) for r in app.routes)
    return routes


def _ws_routes() -> list[str]:
    app = create_app(Store(":memory:"), Scorer(config.load(), Allowlist(frozenset())),
                     FlowTracker(600.0), firewall_fns={}, allowlist=Allowlist(frozenset()))
    return [r.path for r in app.routes if isinstance(r, APIWebSocketRoute)]


HTTP_ROUTES = _http_routes()
POST_ROUTES = [path for method, path in HTTP_ROUTES if method == "POST"]
POST_BODIES: dict[str, Any] = {"/mode": {"mode": "auto"}}


def test_route_lists_are_not_empty() -> None:
    """Guards the parametrized tests below against passing vacuously."""
    assert set(POST_ROUTES) == {"/mode", "/actions/{action_id}/undo", "/undo-all",
                                "/alerts/{alert_id}/quarantine"}
    assert ("GET", "/alerts") in HTTP_ROUTES
    assert ("GET", "/alerts/{alert_id}/evidence") in HTTP_ROUTES
    assert _ws_routes() == ["/ws"]


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "homesoc.db") as db:
        yield db


@pytest.fixture
def scorer() -> Scorer:
    return Scorer(config.load(), Allowlist(frozenset()), mode="notify")


@pytest.fixture
def fw() -> FakeFirewall:
    return FakeFirewall()


@pytest.fixture
def seeded(store: Store) -> Store:
    """An action and an alert every POST route would act on, if it were allowed to run."""
    store.save_action(make_action("a1"))
    store.save_alert(make_alert("al1", exe_path=OTHER_EXE, process="Other.exe"))
    return store


def _snapshot(store: Store) -> tuple[list[Any], list[Any]]:
    return ([to_json(a) for a in store.list_alerts()], [to_json(a) for a in store.list_actions()])


# --- Host header (DNS rebinding) ----------------------------------------------------------------


@pytest.mark.parametrize(("method", "path"), HTTP_ROUTES)
@pytest.mark.parametrize("host", ["rebind.evil.example", "evil.example:8765", "testserver",
                                  "127.0.0.1.evil.example", "192.168.56.10:8765"])
def test_foreign_host_is_400_on_every_route(seeded: Store, scorer: Scorer, fw: FakeFirewall,
                                            method: str, path: str, host: str) -> None:
    client = TestClient(_build(seeded, scorer, fw), base_url="http://127.0.0.1:8765",
                        headers=CLIENT_HEADERS)
    before = _snapshot(seeded)
    resp = client.request(method, _concrete(path), headers={"Host": host},
                          json=POST_BODIES.get(path) if method == "POST" else None)
    assert resp.status_code == 400
    assert fw.undo_calls == [] and fw.undo_all_calls == 0 and fw.quarantine_calls == []
    assert _snapshot(seeded) == before
    assert scorer.mode == "notify"


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "localhost:8765", "127.0.0.1", "LOCALHOST"])
def test_loopback_hosts_still_work(seeded: Store, scorer: Scorer, fw: FakeFirewall,
                                   host: str) -> None:
    client = local_client(_build(seeded, scorer, fw))
    assert client.get("/status", headers={"Host": host}).status_code == 200
    assert client.get("/alerts", headers={"Host": host}).json()["alerts"][0]["id"] == "al1"
    resp = client.post("/mode", json={"mode": "auto"}, headers={"Host": host})
    assert resp.status_code == 200 and scorer.mode == "auto"


def test_localhost_base_url_works_end_to_end(seeded: Store, scorer: Scorer,
                                             fw: FakeFirewall) -> None:
    client = local_client(_build(seeded, scorer, fw), base_url="http://localhost:8765")
    assert client.post("/undo-all").status_code == 200
    assert fw.undo_all_calls == 1


def test_foreign_host_is_refused_on_the_websocket(store: Store, scorer: Scorer,
                                                  fw: FakeFirewall) -> None:
    bus = Bus(queue_size=100, drop_log_every=1000)
    with local_client(_build(store, scorer, fw, bus)) as client:
        with pytest.raises(WebSocketDenialResponse) as exc:
            with client.websocket_connect("ws://rebind.evil.example:8765/ws"):
                pass
    assert exc.value.status_code == 400


def test_allowed_hosts_are_exactly_loopback() -> None:
    assert api.ALLOWED_HOSTS == ("127.0.0.1", "localhost")
    assert "testserver" not in api.ALLOWED_HOSTS


# --- the custom header on every POST ------------------------------------------------------------


@pytest.mark.parametrize("path", POST_ROUTES)
@pytest.mark.parametrize("headers", [
    {},
    {"X-MoCat": "0"},
    {"X-MoCat": ""},
    {"X-Other": "1"},
    {"Origin": "https://evil.example"},  # the cross-site "simple" POST from the review
    {"Origin": "http://127.0.0.1:53211"},  # even the app's own origin needs the header
])
def test_post_without_the_client_header_is_403_and_changes_nothing(
    seeded: Store, scorer: Scorer, fw: FakeFirewall, path: str, headers: dict[str, str]
) -> None:
    published: list[Any] = []
    app = create_app(seeded, scorer, FlowTracker(600.0), firewall_fns=fw.fns(),
                     allowlist=Allowlist(frozenset()), publish=published.append,
                     self_exes=frozenset())
    client = TestClient(app, base_url="http://127.0.0.1:8765")  # no default headers
    before = _snapshot(seeded)

    resp = client.post(_concrete(path), json=POST_BODIES.get(path), headers=headers)

    assert resp.status_code == 403
    assert "X-MoCat" in resp.json()["detail"]
    assert fw.undo_calls == [] and fw.undo_all_calls == 0 and fw.quarantine_calls == []
    assert _snapshot(seeded) == before
    assert published == []
    assert scorer.mode == "notify"


@pytest.mark.parametrize("path", POST_ROUTES)
def test_post_with_the_client_header_runs(seeded: Store, scorer: Scorer, fw: FakeFirewall,
                                          path: str) -> None:
    """Control for the test above: the same request plus the header reaches the route."""
    client = local_client(_build(seeded, scorer, fw))
    resp = client.post(_concrete(path), json=POST_BODIES.get(path))
    assert resp.status_code == 200, resp.text
    effect = {
        "/mode": lambda: scorer.mode == "auto",
        "/actions/{action_id}/undo": lambda: [a.id for a in fw.undo_calls] == ["a1"],
        "/undo-all": lambda: fw.undo_all_calls == 1,
        "/alerts/{alert_id}/quarantine": lambda: fw.quarantine_calls == [OTHER_EXE],
    }[path]
    assert effect()


def test_get_routes_need_no_client_header(seeded: Store, scorer: Scorer,
                                          fw: FakeFirewall) -> None:
    client = TestClient(_build(seeded, scorer, fw), base_url="http://127.0.0.1:8765")
    for path in ("/status", "/apps", "/alerts", "/actions"):
        assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", POST_ROUTES)
@pytest.mark.parametrize("origin", ["http://127.0.0.1:53211", "http://localhost:8080"])
def test_preflight_from_loopback_passes_without_the_header(
    seeded: Store, scorer: Scorer, fw: FakeFirewall, path: str, origin: str
) -> None:
    client = TestClient(_build(seeded, scorer, fw), base_url="http://127.0.0.1:8765")
    pre = client.options(_concrete(path), headers={
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-mocat,content-type"})
    assert pre.status_code == 200
    assert pre.headers["access-control-allow-origin"] == origin
    allowed = {h.strip().lower() for h in pre.headers["access-control-allow-headers"].split(",")}
    assert {"x-mocat", "content-type"} <= allowed
    assert fw.undo_calls == [] and fw.undo_all_calls == 0 and fw.quarantine_calls == []


# --- WS /ws Origin check ------------------------------------------------------------------------


@pytest.fixture
def ws_env(store: Store, scorer: Scorer, fw: FakeFirewall) -> Iterator[tuple[TestClient, Bus]]:
    bus = Bus(queue_size=100, drop_log_every=1000)
    with local_client(_build(store, scorer, fw, bus)) as client:
        yield client, bus


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://evil.example",
                                    "http://127.0.0.1.evil.example", "https://127.0.0.1:8765",
                                    "http://192.168.56.20:8000", "file://"])
def test_ws_refuses_a_foreign_origin(ws_env: tuple[TestClient, Bus], origin: str) -> None:
    client, bus = ws_env
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(LOCAL_WS_URL, headers={"Origin": origin}) as ws:
            ws.receive_text()
    assert exc.value.code == api.WS_CLOSE_POLICY_VIOLATION
    assert bus.subscribers == ()  # refused before the server subscribed to the bus


@pytest.mark.parametrize("origin", [None, "http://127.0.0.1:53211", "http://localhost:8080",
                                    "http://127.0.0.1"])
def test_ws_accepts_loopback_and_missing_origin(ws_env: tuple[TestClient, Bus],
                                                origin: str | None) -> None:
    client, bus = ws_env
    headers = {"Origin": origin} if origin is not None else {}
    with client.websocket_connect(LOCAL_WS_URL, headers=headers) as ws:
        bus.publish_threadsafe(make_alert("al-origin"))
        msg = recv(ws)
    assert msg["type"] == "alert" and msg["id"] == "al-origin"


@pytest.mark.parametrize(("origin", "allowed"), [
    (None, True), ("http://127.0.0.1:1", True), ("http://localhost", True),
    ("null", False), ("", False), ("https://localhost", False),
    ("http://localhost.evil.example", False), ("http://127.0.0.1:8765/", False),
])
def test_origin_allowed(origin: str | None, allowed: bool) -> None:
    assert api.origin_allowed(origin) is allowed
