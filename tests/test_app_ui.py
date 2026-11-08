"""Tests for the HomeSOC window and UI (CLAUDE.md §6.7, ticket #41).

* The API base URL is exactly ``http://127.0.0.1:8765`` on both the Python and the JS side, and
  no other host appears anywhere in the UI (§9.5: the app only talks to the local agent).
* ``app.main`` builds the pywebview window on ``app/ui/index.html`` (``webview`` is mocked, and
  must not be imported just by importing ``app.main``).
* The JS helpers in ``app/ui/app.js`` are run under Node by ``tests/js/test_app.mjs``: alert card
  rendering (three plain-English sections + escaping), Undo -> ``POST /actions/{id}/undo``,
  Settings -> ``POST /mode``. Skipped with a clear reason when ``node`` is not on PATH.
* The agent API sends CORS headers to the window's loopback origin only.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from agent.api import FlowTracker, create_app
from agent.config import Allowlist
from agent.scoring import Scorer
from agent.store import Store
from app import main as app_main

REPO = Path(__file__).resolve().parent.parent
UI = REPO / "app" / "ui"
APP_JS = UI / "app.js"
INDEX_HTML = UI / "index.html"
STYLES_CSS = UI / "styles.css"
JS_HARNESS = REPO / "tests" / "js" / "test_app.mjs"
NODE = shutil.which("node")

URL_RE = re.compile(r"""\b(?:https?|wss?)://([^/\s"'`<>;:)]+)""", re.IGNORECASE)


# --- API base URL: 127.0.0.1 only --------------------------------------------------------------


def test_api_base_url_is_exactly_the_local_agent() -> None:
    assert app_main.API_BASE_URL == "http://127.0.0.1:8765"
    parts = urlsplit(app_main.API_BASE_URL)
    assert parts.hostname == "127.0.0.1"
    assert parts.port == 8765
    assert urlsplit(app_main.WS_URL).hostname == "127.0.0.1"
    assert app_main.validate_api_url(app_main.API_BASE_URL) == app_main.API_BASE_URL
    assert app_main.validate_api_url(app_main.WS_URL) == app_main.WS_URL


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8765",
    "http://127.0.0.1:8765/status",
    "ws://127.0.0.1:8765/ws",
    "http://127.0.0.1",
])
def test_validate_api_url_accepts_loopback(url: str) -> None:
    assert app_main.validate_api_url(url) == url


@pytest.mark.parametrize("url", [
    "http://0.0.0.0:8765",
    "http://localhost:8765",
    "http://192.168.56.20:8765",
    "http://example.com:8765",
    "http://127.0.0.1.evil.com:8765",
    "http://evil.com@127.0.0.1:8765",
    "http://127.0.0.1@evil.com:8765",
    "http://[::1]:8765",
    "https://127.0.0.1:8765",
    "ftp://127.0.0.1:8765",
    "http://127.0.0.1:9999",
    "http://127.0.0.1:notaport",
    "127.0.0.1:8765",
    "",
])
def test_validate_api_url_rejects_other_hosts(url: str) -> None:
    with pytest.raises(ValueError):
        app_main.validate_api_url(url)


def test_create_window_refuses_a_non_loopback_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_main, "API_BASE_URL", "http://10.0.0.5:8765")
    fake = FakeWebview()
    with pytest.raises(ValueError):
        app_main.create_window(fake)
    assert fake.windows == []


def _ui_hosts(path: Path) -> set[str]:
    return {m.group(1).lower() for m in URL_RE.finditer(path.read_text(encoding="utf-8"))}


def test_app_js_only_mentions_the_local_agent() -> None:
    js = APP_JS.read_text(encoding="utf-8")
    assert f'const API_BASE = "{app_main.API_BASE_URL}";' in js
    assert f'const WS_URL = "{app_main.WS_URL}";' in js
    hosts = _ui_hosts(APP_JS)
    assert hosts == {"127.0.0.1"}, f"app.js mentions other hosts: {hosts}"
    # Every fetch goes through apiUrl(API_BASE + path) and the WebSocket uses WS_URL.
    assert "doFetch(apiUrl(path)" in js
    assert "new win.WebSocket(WS_URL)" in js


@pytest.mark.parametrize("path", [INDEX_HTML, STYLES_CSS])
def test_ui_has_no_external_resources(path: Path) -> None:
    hosts = _ui_hosts(path)
    assert hosts <= {"127.0.0.1"}, f"{path.name} references other hosts: {hosts}"
    text = path.read_text(encoding="utf-8")
    assert "//cdn" not in text and "@import" not in text


def test_url_scanner_would_catch_another_host() -> None:
    """Guards the scanner itself, so the host test above can't pass vacuously."""
    sample = 'const A = "http://127.0.0.1:8765"; const B = "wss://evil.example/ws";'
    hosts = {m.group(1).lower() for m in URL_RE.finditer(sample)}
    assert hosts == {"127.0.0.1", "evil.example"}


def test_index_html_csp_only_allows_the_local_agent() -> None:
    html = INDEX_HTML.read_text(encoding="utf-8")
    csp = re.search(r'Content-Security-Policy"\s+content="([^"]+)"', html)
    assert csp, "index.html must set a Content-Security-Policy"
    directives = dict(
        (d.strip().split(" ", 1) + [""])[:2] for d in csp.group(1).split(";") if d.strip()
    )
    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self'"
    assert set(directives["connect-src"].split()) == {
        "http://127.0.0.1:8765", "ws://127.0.0.1:8765"}


def test_index_html_has_the_four_screens_and_loads_local_assets() -> None:
    html = INDEX_HTML.read_text(encoding="utf-8")
    for screen in ("home", "apps", "alerts", "settings"):
        assert f'id="screen-{screen}"' in html
        assert f'data-screen="{screen}"' in html
    assert '<script src="app.js"' in html
    assert 'href="styles.css"' in html
    for mode in ("off", "notify", "auto"):
        assert f'name="mode" value="{mode}"' in html
    # Every element app.js looks up by id exists in the page.
    ids = set(re.findall(r'\$\("#([\w-]+)"\)', APP_JS.read_text(encoding="utf-8")))
    assert ids, "expected app.js to look up elements by id"
    missing = {i for i in ids if f'id="{i}"' not in html}
    assert not missing, f"index.html lacks ids used by app.js: {missing}"


# --- app.main: the pywebview window --------------------------------------------------------


class FakeWebview:
    """Stands in for the ``webview`` module: records create_window / start calls."""

    def __init__(self) -> None:
        self.windows: list[dict[str, Any]] = []
        self.starts: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def create_window(self, title: str, url: str | None = None, **kwargs: Any) -> Any:
        window = SimpleNamespace(title=title, url=url, kwargs=kwargs)
        self.windows.append({"title": title, "url": url, **kwargs, "window": window})
        return window

    def start(self, *args: Any, **kwargs: Any) -> None:
        self.starts.append((args, kwargs))


def test_importing_app_main_does_not_import_webview() -> None:
    code = "import sys, app.main; sys.exit(1 if 'webview' in sys.modules else 0)"
    result = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                            text=True, check=False)
    assert result.returncode == 0, result.stderr or "app.main imported webview at import time"


def test_create_window_loads_index_html() -> None:
    fake = FakeWebview()
    window = app_main.create_window(fake)
    assert len(fake.windows) == 1
    created = fake.windows[0]
    assert window is created["window"]
    assert created["title"] == "MoCat HomeSOC"
    url = Path(created["url"])
    assert url.is_absolute()
    assert url == INDEX_HTML.resolve()
    assert url.is_file()
    assert created["width"] >= 900 and created["height"] >= 600


def test_run_starts_webview_with_its_local_http_server() -> None:
    fake = FakeWebview()
    app_main.run(fake)
    assert len(fake.windows) == 1
    assert len(fake.starts) == 1
    args, kwargs = fake.starts[0]
    assert args == ()
    # Served from http://127.0.0.1:<port>/ (an origin the API's CORS allows), not file://.
    assert kwargs["http_server"] is True


def test_run_passes_the_window_to_the_on_started_hook() -> None:
    fake = FakeWebview()
    seen: list[Any] = []
    app_main.run(fake, on_started=seen.append)
    args, kwargs = fake.starts[0]
    assert args[0] == seen.append
    assert args[1] is fake.windows[0]["window"]
    assert kwargs["http_server"] is True


def test_create_window_fails_clearly_without_the_ui(monkeypatch: pytest.MonkeyPatch,
                                                    tmp_path: Path) -> None:
    monkeypatch.setattr(app_main, "INDEX_HTML", tmp_path / "missing.html")
    with pytest.raises(FileNotFoundError):
        app_main.create_window(FakeWebview())


# --- app.js under Node --------------------------------------------------------------------

needs_node = pytest.mark.skipif(NODE is None, reason="node is not on PATH; the JS UI tests "
                                "(tests/js/test_app.mjs) need Node.js")


def run_js(filter_: str) -> subprocess.CompletedProcess[str]:
    assert NODE is not None
    result = subprocess.run([NODE, str(JS_HARNESS), filter_], cwd=REPO, capture_output=True,
                            text=True, timeout=60, check=False)
    assert result.returncode == 0, f"JS tests failed:\n{result.stdout}\n{result.stderr}"
    assert "not ok" not in result.stdout
    return result


@needs_node
def test_js_api_base_url() -> None:
    run_js("API base and WS URL are the local agent")


@needs_node
def test_js_alert_card_shows_three_sections() -> None:
    out = run_js("renderAlertCard shows all three sections").stdout
    assert "1/1 passed" in out


@needs_node
def test_js_alert_card_escapes_html() -> None:
    run_js("escapes")


@needs_node
def test_js_undo_posts_to_actions_undo() -> None:
    out = run_js("undoAction").stdout
    assert "2/2 passed" in out


@needs_node
def test_js_set_mode_posts_json_and_rejects_bad_modes() -> None:
    out = run_js("setMode").stdout
    assert "2/2 passed" in out


@needs_node
def test_js_full_harness() -> None:
    """Every JS test (endpoints, error messages, WS state updates, backoff, ...)."""
    out = run_js("").stdout
    assert re.search(r"(\d+)/\1 passed", out)


# --- agent API: CORS for the window's origin -------------------------------------------------


@pytest.fixture
def api_client(tmp_path: Path) -> Any:
    from agent import config

    cfg = config.load()
    with Store(tmp_path / "homesoc.db") as store:
        scorer = Scorer(cfg, Allowlist(frozenset()), mode="notify")
        app = create_app(store, scorer, FlowTracker(600.0), firewall_fns={},
                         allowlist=Allowlist(frozenset()))
        yield TestClient(app), scorer


@pytest.mark.parametrize("origin", ["http://127.0.0.1:53211", "http://localhost:8080",
                                    "http://127.0.0.1"])
def test_cors_allows_the_local_window(api_client: Any, origin: str) -> None:
    client, scorer = api_client
    pre = client.options("/mode", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"})
    assert pre.status_code == 200
    assert pre.headers["access-control-allow-origin"] == origin
    resp = client.post("/mode", json={"mode": "auto"}, headers={"Origin": origin})
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == origin
    assert scorer.mode == "auto"
    got = client.get("/status", headers={"Origin": origin})
    assert got.headers["access-control-allow-origin"] == origin


@pytest.mark.parametrize("origin", ["https://evil.example", "http://127.0.0.1.evil.example",
                                    "null", "http://192.168.56.20:8000",
                                    "https://127.0.0.1:8000"])
def test_cors_refuses_other_origins(api_client: Any, origin: str) -> None:
    client, scorer = api_client
    pre = client.options("/mode", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"})
    assert pre.status_code == 400
    assert "access-control-allow-origin" not in pre.headers
    got = client.get("/status", headers={"Origin": origin})
    assert "access-control-allow-origin" not in got.headers
    assert scorer.mode == "notify"
