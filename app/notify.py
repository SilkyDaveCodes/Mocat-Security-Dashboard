"""HomeSOC toast notifications (CLAUDE.md §6.7).

Every ``high`` / ``critical`` Alert pushed by the agent on ``WS /ws`` (§6.6; alerts arrive whole
as JSON with ``"type": "alert"``) becomes one Windows toast: the alert's title, and the start of
its ``what_you_should_do`` text (cut at ``app.toast_text_chars``). The same alert id never toasts
twice (the last ``app.toast_dedupe_max`` ids are remembered).

* :class:`Notifier` is the pure, tested core: :meth:`Notifier.handle_message` filters, dedupes and
  calls an injected ``toast_fn(title, text)``.
* :func:`windows_toast` is the default ``toast_fn``: a ``winotify`` toast on Windows, a no-op
  elsewhere or when ``winotify`` is missing. ``winotify`` is imported lazily inside it, so this
  module imports on any OS (§10: Windows-only code stays here). :func:`is_windows` is the
  patchable platform check.
* :func:`listen` is the thin WebSocket client (``websockets``, imported lazily): it connects to
  :data:`app.main.WS_URL` (``ws://127.0.0.1:8765/ws`` only, checked with
  :func:`app.main.validate_api_url`), feeds every message to the Notifier and reconnects every
  ``app.ws_reconnect_s`` seconds after a failure. :func:`start_notifier` runs it in a daemon
  thread; ``app.main.main()`` starts it next to the window and tray.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agent import config as config_module
from app.main import WS_URL, validate_api_url

logger = logging.getLogger(__name__)

TOAST_SEVERITIES = frozenset({"high", "critical"})
APP_ID = "MoCat HomeSOC"
DEFAULT_TITLE = "MoCat HomeSOC alert"
ELLIPSIS = "…"

DEFAULT_TEXT_CHARS = 120  # used when config.yaml lacks app.toast_text_chars
DEFAULT_DEDUPE_MAX = 1000  # used when config.yaml lacks app.toast_dedupe_max
DEFAULT_RECONNECT_S = 5.0  # used when config.yaml lacks app.ws_reconnect_s

ToastFn = Callable[[str, str], None]


# --- settings ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class NotifySettings:
    text_chars: int = DEFAULT_TEXT_CHARS
    dedupe_max: int = DEFAULT_DEDUPE_MAX
    reconnect_s: float = DEFAULT_RECONNECT_S


def notify_settings(cfg: Mapping[str, Any]) -> NotifySettings:
    """Toast settings from the ``app`` section of ``config.yaml``."""
    section = cfg.get("app") or {}
    settings = NotifySettings(
        text_chars=int(section.get("toast_text_chars", DEFAULT_TEXT_CHARS)),
        dedupe_max=int(section.get("toast_dedupe_max", DEFAULT_DEDUPE_MAX)),
        reconnect_s=float(section.get("ws_reconnect_s", DEFAULT_RECONNECT_S)),
    )
    if settings.text_chars <= 0 or settings.dedupe_max <= 0 or settings.reconnect_s <= 0:
        raise ValueError(
            "app.toast_text_chars, app.toast_dedupe_max and app.ws_reconnect_s must be > 0"
        )
    return settings


# --- the Windows toast (lazy winotify) --------------------------------------------------------


def is_windows() -> bool:
    """True on Windows. Tests patch this to force either path."""
    return sys.platform == "win32"


def windows_toast(title: str, text: str) -> None:
    """Show a winotify toast; a no-op off Windows or without ``winotify``."""
    if not is_windows():
        logger.debug("Not on Windows: toast %r skipped", title)
        return
    try:
        import winotify  # lazy: Windows runtime only
    except ImportError:
        logger.warning("winotify is not installed: toast %r skipped", title)
        return
    winotify.Notification(app_id=APP_ID, title=title, msg=text).show()


# --- pure core --------------------------------------------------------------------------------


def truncate(text: str, max_chars: int) -> str:
    """``text`` cut to at most ``max_chars`` characters (ending in an ellipsis when cut)."""
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - len(ELLIPSIS)].rstrip() + ELLIPSIS


class Notifier:
    """Turns ``/ws`` messages into toasts: high/critical alerts only, once per alert id."""

    def __init__(self, toast_fn: ToastFn | None = None,
                 settings: NotifySettings | None = None) -> None:
        self._toast = toast_fn if toast_fn is not None else windows_toast
        self._settings = settings or NotifySettings()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def handle_raw(self, raw: str | bytes) -> bool:
        """Parse one WebSocket text frame and handle it; bad JSON is ignored."""
        try:
            msg = json.loads(raw)
        except (TypeError, ValueError):
            logger.debug("Ignoring a non-JSON /ws message")
            return False
        return self.handle_message(msg) if isinstance(msg, dict) else False

    def handle_message(self, msg: Mapping[str, Any]) -> bool:
        """Toast ``msg`` if it is a new high/critical alert. Returns True if a toast was shown.

        Never raises: a failing toast is logged (and the alert still counts as seen, so a broken
        toast backend can't turn into a retry storm).
        """
        if msg.get("type") != "alert" or msg.get("severity") not in TOAST_SEVERITIES:
            return False
        alert_id = msg.get("id")
        if not isinstance(alert_id, str) or not alert_id:
            return False
        with self._lock:
            if alert_id in self._seen:
                return False
            self._seen[alert_id] = None
            while len(self._seen) > self._settings.dedupe_max:
                self._seen.popitem(last=False)
        title = str(msg.get("title") or DEFAULT_TITLE)
        text = truncate(str(msg.get("what_you_should_do") or ""), self._settings.text_chars)
        try:
            self._toast(title, text)
        except Exception:  # noqa: BLE001 - a toast must never take the listener down
            logger.exception("Toast for alert %s failed", alert_id)
            return False
        return True


# --- WebSocket listener (lazy websockets) -----------------------------------------------------


Connect = Callable[[str], Any]  # returns a context manager that iterates text frames


def _default_connect(url: str) -> Any:
    from websockets.sync.client import connect  # lazy: only in the running app

    return connect(url)


def listen(notifier: Notifier, stop: threading.Event, url: str = WS_URL,
           connect: Connect | None = None,
           reconnect_s: float = DEFAULT_RECONNECT_S) -> None:
    """Feed every ``/ws`` message to ``notifier`` until ``stop`` is set; reconnect on failure."""
    validate_api_url(url)
    connect = connect or _default_connect
    while not stop.is_set():
        try:
            with connect(url) as ws:
                logger.info("Listening for alerts on %s", url)
                _drain(notifier, ws, stop)
        except Exception as exc:  # noqa: BLE001 - agent offline / connection dropped
            logger.info("Alert stream %s unavailable (%s); retrying in %.0f s",
                        url, exc, reconnect_s)
        stop.wait(reconnect_s)


def _drain(notifier: Notifier, frames: Iterable[Any], stop: threading.Event) -> None:
    for raw in frames:
        if stop.is_set():
            return
        notifier.handle_raw(raw)


def start_notifier(cfg: Mapping[str, Any] | None = None, connect: Connect | None = None,
                   toast_fn: ToastFn | None = None) -> threading.Event | None:
    """Start the toast listener in a daemon thread; returns its stop event.

    Off Windows (no toasts possible) with the default ``toast_fn`` nothing is started and
    ``None`` is returned.
    """
    if toast_fn is None and not is_windows():
        logger.info("Not on Windows: toast notifications are off")
        return None
    settings = notify_settings(cfg if cfg is not None else config_module.load())
    validate_api_url(WS_URL)
    notifier = Notifier(toast_fn, settings)
    stop = threading.Event()
    threading.Thread(target=listen, args=(notifier, stop),
                     kwargs={"connect": connect, "reconnect_s": settings.reconnect_s},
                     name="homesoc-notify", daemon=True).start()
    return stop
