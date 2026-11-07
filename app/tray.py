"""HomeSOC tray shield (CLAUDE.md §6.7).

A ``pystray`` icon whose shield is

* **green**  no active alert,
* **yellow** only active ``low`` / ``medium`` alerts,
* **red**    at least one active ``high`` / ``critical`` alert,

with the menu Open, Mode ▸ (off / notify / auto), Undo all, Quit.

"Active" alert (:func:`is_active`): an alert stays active until what HomeSOC did about it has been
undone. Concretely, an alert is **no longer active** when it has at least one ``action_id`` and
every one of those actions is known (``GET /actions``) and has ``undone=True``. An alert with no
action (notify/off mode, or an alert-only decision) has nothing to undo, so it stays active; an
action id we can't find is treated as still in force (in doubt, keep warning).

The colour logic is the pure function :func:`tray_state`. Everything else only talks HTTP to
the local agent at :data:`app.main.API_BASE_URL` (``127.0.0.1:8765``, §9.5) through an injected
client with ``get(url, timeout=)`` / ``post(url, json=, timeout=)`` (an ``httpx.Client`` in the
app, a fake in tests). The state is refreshed by polling every ``app.tray_refresh_s`` seconds.

``pystray``, ``PIL`` and ``httpx`` are imported lazily (only when the real icon is built), so
this module and its tests run on any OS without a display.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from agent import config as config_module
from app.main import API_BASE_URL, validate_api_url

logger = logging.getLogger(__name__)

TrayColour = Literal["green", "yellow", "red"]

MODES: tuple[str, ...] = config_module.ALLOWED_MODES
HIGH_SEVERITIES = frozenset({"high", "critical"})
UNDO_KIND = "undo"

DEFAULT_REFRESH_S = 5.0  # used when config.yaml lacks app.tray_refresh_s
DEFAULT_HTTP_TIMEOUT_S = 5.0  # used when config.yaml lacks app.http_timeout_s
ALERTS_LIMIT = 1000  # alerts / actions fetched per refresh (the API's own maximum for alerts)
ACTIONS_LIMIT = 10000

ICON_NAME = "HomeSOC"
ICON_SIZE = 64
COLOURS_RGB: dict[str, tuple[int, int, int]] = {
    "green": (46, 160, 67),
    "yellow": (230, 180, 30),
    "red": (210, 45, 45),
}
TITLES: dict[str, str] = {
    "green": "HomeSOC: all clear",
    "yellow": "HomeSOC: open alerts",
    "red": "HomeSOC: high-severity alert",
}
OFFLINE_SUFFIX = " (agent offline)"


# --- pure colour logic ------------------------------------------------------------------------


def is_active(alert: Mapping[str, Any], actions_by_id: Mapping[str, Mapping[str, Any]]) -> bool:
    """True unless the alert had actions and every one of them has been undone (module doc)."""
    action_ids = list(alert.get("action_ids") or [])
    if not action_ids:
        return True
    for action_id in action_ids:
        action = actions_by_id.get(action_id)
        if action is None or not action.get("undone"):
            return True
    return False


def tray_state(
    alerts: Iterable[Mapping[str, Any]],
    actions: Iterable[Mapping[str, Any]] = (),
) -> TrayColour:
    """Shield colour for ``GET /alerts`` items, given ``GET /actions`` items (both JSON dicts)."""
    by_id = {a["id"]: a for a in actions if a.get("id")}
    active = [a for a in alerts if is_active(a, by_id)]
    if any(a.get("severity") in HIGH_SEVERITIES for a in active):
        return "red"
    return "yellow" if active else "green"


# --- HTTP to the local agent ------------------------------------------------------------------


class HttpClient(Protocol):
    """The part of ``httpx.Client`` the tray uses."""

    def get(self, url: str, **kwargs: Any) -> Any: ...

    def post(self, url: str, **kwargs: Any) -> Any: ...


class AgentApi:
    """Calls the agent's REST API (§6.6). Raises on HTTP / connection errors."""

    def __init__(self, http: HttpClient, base_url: str = API_BASE_URL,
                 timeout_s: float = DEFAULT_HTTP_TIMEOUT_S) -> None:
        self._http = http
        self._base = validate_api_url(base_url).rstrip("/")
        self._timeout_s = timeout_s

    def _get(self, path: str) -> Any:
        resp = self._http.get(self._base + path, timeout=self._timeout_s)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        resp = self._http.post(self._base + path, json=body, timeout=self._timeout_s)
        resp.raise_for_status()
        return resp.json()

    def alerts(self) -> list[dict[str, Any]]:
        return list(self._get(f"/alerts?limit={ALERTS_LIMIT}").get("alerts", []))

    def actions(self) -> list[dict[str, Any]]:
        return list(self._get(f"/actions?limit={ACTIONS_LIMIT}").get("actions", []))

    def mode(self) -> str | None:
        return self._get("/status").get("mode")

    def set_mode(self, mode: str) -> str:
        if mode not in MODES:
            raise ValueError(f"Unknown mode {mode!r}; use one of {', '.join(MODES)}")
        return str(self._post("/mode", {"mode": mode})["mode"])

    def undo_all(self) -> dict[str, Any]:
        return dict(self._post("/undo-all"))


# --- tray controller (no pystray) -------------------------------------------------------------


@dataclass
class MenuEntry:
    """One menu item, independent of pystray (so tests can click it)."""

    label: str
    action: Callable[[], None] | None = None
    children: list[MenuEntry] = field(default_factory=list)
    checked: Callable[[], bool] | None = None
    default: bool = False


class Tray:
    """Holds the shield colour and mode, and carries out the menu commands."""

    def __init__(self, api: AgentApi, on_open: Callable[[], None] = lambda: None,
                 on_quit: Callable[[], None] = lambda: None) -> None:
        self.api = api
        self.colour: TrayColour = "green"
        self.mode: str | None = None
        self.online = False
        self.on_change: Callable[[Tray], None] = lambda _tray: None
        self._on_open = on_open
        self._on_quit = on_quit

    @property
    def title(self) -> str:
        return TITLES[self.colour] + ("" if self.online else OFFLINE_SUFFIX)

    def refresh(self) -> TrayColour:
        """Re-read alerts, actions and mode; on an error keep the last colour, mark offline."""
        try:
            alerts, actions = self.api.alerts(), self.api.actions()
            self.mode = self.api.mode()
        except Exception as exc:
            if self.online:
                logger.warning("Tray could not reach the agent: %s", exc)
            self.online = False
        else:
            self.colour = tray_state(alerts, actions)
            self.online = True
        self.on_change(self)
        return self.colour

    def set_mode(self, mode: str) -> None:
        try:
            self.mode = self.api.set_mode(mode)
            logger.info("Mode set to %s from the tray", self.mode)
        except Exception:
            logger.exception("Could not set mode %s from the tray", mode)
        self.refresh()

    def undo_all(self) -> None:
        try:
            res = self.api.undo_all()
            logger.info("Undo all from the tray: %s action(s) undone", res.get("undone"))
        except Exception:
            logger.exception("Undo all from the tray failed")
        self.refresh()

    def open(self) -> None:
        self._on_open()

    def quit(self) -> None:
        self._on_quit()

    def menu(self) -> list[MenuEntry]:
        """Open, Mode ▸ (off/notify/auto), Undo all, Quit."""
        modes = [MenuEntry(m, action=self._mode_setter(m), checked=self._mode_checker(m))
                 for m in MODES]
        return [
            MenuEntry("Open", action=self.open, default=True),
            MenuEntry("Mode", children=modes),
            MenuEntry("Undo all", action=self.undo_all),
            MenuEntry("Quit", action=self.quit),
        ]

    def _mode_setter(self, mode: str) -> Callable[[], None]:
        return lambda: self.set_mode(mode)

    def _mode_checker(self, mode: str) -> Callable[[], bool]:
        return lambda: self.mode == mode


def poll(tray: Tray, stop: threading.Event, refresh_s: float) -> None:
    """Refresh now and then every ``refresh_s`` seconds until ``stop`` is set."""
    tray.refresh()
    while not stop.wait(refresh_s):
        tray.refresh()


def tray_settings(cfg: Mapping[str, Any]) -> tuple[float, float]:
    """``(refresh_s, http_timeout_s)`` from the ``app`` section of ``config.yaml``."""
    section = cfg.get("app") or {}
    refresh_s = float(section.get("tray_refresh_s", DEFAULT_REFRESH_S))
    timeout_s = float(section.get("http_timeout_s", DEFAULT_HTTP_TIMEOUT_S))
    if refresh_s <= 0 or timeout_s <= 0:
        raise ValueError("app.tray_refresh_s and app.http_timeout_s must be > 0")
    return refresh_s, timeout_s


# --- real pystray icon (lazy imports) ---------------------------------------------------------


def shield_image(colour: TrayColour, image_module: Any | None = None,
                 draw_module: Any | None = None) -> Any:
    """A filled shield of ``colour`` on a transparent square (PIL image)."""
    if image_module is None or draw_module is None:
        from PIL import Image as image_module  # lazy: only for the real icon
        from PIL import ImageDraw as draw_module
    s = ICON_SIZE
    img = image_module.new("RGBA", (s, s), (0, 0, 0, 0))
    points = [(s * 0.5, s * 0.04), (s * 0.92, s * 0.18), (s * 0.86, s * 0.62),
              (s * 0.5, s * 0.96), (s * 0.14, s * 0.62), (s * 0.08, s * 0.18)]
    draw_module.Draw(img).polygon(points, fill=(*COLOURS_RGB[colour], 255))
    return img


def _to_pystray(entries: list[MenuEntry], pystray: Any) -> Any:
    items = []
    for e in entries:
        if e.children:
            items.append(pystray.MenuItem(e.label, _to_pystray(e.children, pystray)))
            continue
        checked = e.checked
        items.append(pystray.MenuItem(
            e.label, _no_args(e.action), default=e.default,
            checked=(lambda _item, c=checked: c()) if checked else None, radio=checked is not None,
        ))
    return pystray.Menu(*items)


def _no_args(fn: Callable[[], None] | None) -> Callable[[Any, Any], None]:
    def action(_icon: Any, _item: Any) -> None:
        if fn is not None:
            fn()
    return action


def build_icon(tray: Tray, pystray: Any | None = None,
               image_fn: Callable[[TrayColour], Any] = shield_image) -> Any:
    """Build the pystray icon; it follows the tray's colour / title on every refresh."""
    if pystray is None:
        import pystray  # lazy: Windows runtime only
    icon = pystray.Icon(ICON_NAME, icon=image_fn(tray.colour), title=tray.title,
                        menu=_to_pystray(tray.menu(), pystray))
    shown: dict[str, Any] = {"colour": tray.colour}

    def follow(t: Tray) -> None:
        if t.colour != shown["colour"]:
            icon.icon = image_fn(t.colour)
            shown["colour"] = t.colour
        icon.title = t.title
        update = getattr(icon, "update_menu", None)
        if update is not None:
            update()

    tray.on_change = follow
    return icon


def start_tray(window: Any, cfg: Mapping[str, Any] | None = None,
               http: HttpClient | None = None, pystray: Any | None = None,
               image_fn: Callable[[TrayColour], Any] = shield_image) -> Any:
    """``app.main.run(on_started=...)`` hook: show the tray for ``window`` and start polling."""
    refresh_s, timeout_s = tray_settings(cfg if cfg is not None else config_module.load())
    if http is None:
        import httpx  # lazy
        http = httpx.Client()
    stop = threading.Event()
    holder: dict[str, Any] = {}

    def quit_app() -> None:
        stop.set()
        holder["icon"].stop()
        window.destroy()

    tray = Tray(AgentApi(http, timeout_s=timeout_s), on_open=lambda: _show(window),
                on_quit=quit_app)
    icon = holder["icon"] = build_icon(tray, pystray, image_fn)
    icon.run_detached()
    threading.Thread(target=poll, args=(tray, stop, refresh_s), name="homesoc-tray",
                     daemon=True).start()
    return icon


def _show(window: Any) -> None:
    window.show()
    restore = getattr(window, "restore", None)
    if restore is not None:
        restore()
