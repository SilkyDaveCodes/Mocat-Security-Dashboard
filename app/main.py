"""HomeSOC desktop window (CLAUDE.md §6.7).

Opens a pywebview window on ``app/ui/index.html`` (screens Home, Apps, Alerts, Settings). The app
runs as a normal user and only talks to the agent at :data:`API_BASE_URL` (``127.0.0.1:8765``,
§3, §9.5); the UI's JavaScript holds the same constant (``API_BASE`` in ``app/ui/app.js``) and a
test keeps the two in sync.

``webview`` is imported lazily inside :func:`create_window` / :func:`run`, so this module (and
the test suite) imports on any OS without pywebview installed.

pywebview serves the local UI from its own HTTP server on ``http://127.0.0.1:<port>/``
(``http_server=True``), so ``fetch`` calls to the API are cross-origin; the agent's API allows
loopback origins only (``agent/api.py``, CORS).

The tray icon and toast notifications are a separate ticket: :func:`run` takes an optional
``on_started`` callback (run by pywebview once the GUI loop is up, with the window as argument)
as the hook for them.

Run: ``python -m app.main`` (normal, non-admin terminal).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

API_HOST = "127.0.0.1"
API_PORT = 8765
API_BASE_URL = "http://127.0.0.1:8765"  # single source of truth; app.js has API_BASE = same
WS_URL = "ws://127.0.0.1:8765/ws"

UI_DIR = Path(__file__).resolve().parent / "ui"
INDEX_HTML = UI_DIR / "index.html"

WINDOW_TITLE = "HomeSOC"
WINDOW_SIZE = (1180, 780)
WINDOW_MIN_SIZE = (900, 600)

_ALLOWED_SCHEMES = {"http", "ws"}


def validate_api_url(url: str) -> str:
    """Return ``url`` if it points at the agent on 127.0.0.1, else raise ``ValueError``.

    Only ``http``/``ws`` on host ``127.0.0.1`` (no user info, no other host, not ``localhost``,
    not ``0.0.0.0``) is accepted: the app must never talk to anything but the local agent (§9.5).
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"Invalid API URL {url!r}: {exc}") from exc
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"API URL {url!r} must use http or ws")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError(f"API URL {url!r} must not contain user info")
    if parts.hostname != API_HOST:
        raise ValueError(f"API URL {url!r} must point at {API_HOST}, not {parts.hostname!r}")
    if port is not None and port != API_PORT:
        raise ValueError(f"API URL {url!r} must use port {API_PORT}")
    return url


def create_window(webview_module: Any | None = None) -> Any:
    """Create (but don't start) the HomeSOC window on ``app/ui/index.html``."""
    validate_api_url(API_BASE_URL)
    validate_api_url(WS_URL)
    if not INDEX_HTML.is_file():
        raise FileNotFoundError(f"UI not found: {INDEX_HTML}")
    if webview_module is None:
        import webview as webview_module  # lazy: pywebview is Windows-runtime only

    width, height = WINDOW_SIZE
    return webview_module.create_window(
        WINDOW_TITLE,
        url=str(INDEX_HTML),
        width=width,
        height=height,
        min_size=WINDOW_MIN_SIZE,
    )


def run(
    webview_module: Any | None = None,
    on_started: Callable[[Any], None] | None = None,
    debug: bool = False,
) -> None:
    """Open the window and block until it is closed.

    ``http_server=True`` makes pywebview serve ``app/ui`` on ``http://127.0.0.1:<port>/`` (an
    origin the API's CORS allows) instead of ``file://``.
    """
    if webview_module is None:
        import webview as webview_module  # lazy: pywebview is Windows-runtime only

    window = create_window(webview_module)
    if on_started is None:
        webview_module.start(http_server=True, debug=debug)
    else:
        webview_module.start(on_started, window, http_server=True, debug=debug)


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger.info("Opening the HomeSOC window (agent API at %s)", API_BASE_URL)
    run()


if __name__ == "__main__":
    main()
