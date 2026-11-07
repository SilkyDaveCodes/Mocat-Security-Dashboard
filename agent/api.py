"""Local REST API for the HomeSOC app (CLAUDE.md §6.6, §9.5).

The app (normal user) talks to the agent (admin) only through this API on ``127.0.0.1:8765``.
It never binds anywhere else: :func:`server_settings` refuses any host but
:data:`API_HOST`, and ``config.load`` already rejects a non-loopback ``api.host``.

Routes
    ``GET  /status``                    mode, uptime, alert / active-action / app counts
    ``GET  /apps``                      per-process bytes + destinations, last ``api.apps_window_s``
    ``GET  /alerts?limit=N``            stored alerts, newest first
    ``POST /actions/{id}/undo``         remove that action's firewall rules, mark it undone
    ``POST /undo-all``                  remove every rule in group HomeSOC, mark all undone
    ``POST /mode``                      ``{"mode": "off" | "notify" | "auto"}`` (else 422)
    ``POST /alerts/{id}/quarantine``    the user asks to quarantine the alert's app
    ``WS   /ws``                        pushes every Alert and Action, plus throttled flow summaries
    (``GET /alerts/{id}/evidence`` is a separate ticket.)

CORS
    The app's window (pywebview, ``http://127.0.0.1:<port>/``) is another origin, so responses
    carry CORS headers for loopback ``http`` origins only (:data:`CORS_ORIGIN_REGEX`).

Error codes
    404 unknown alert / action id. 409 the request conflicts with the current state (action
    already undone or not undoable, alert without a known exe path, app on the allowlist, app
    already quarantined). 400 the stored exe path is unsafe for PowerShell. 502 the firewall
    (PowerShell) call failed; nothing is marked as done. 422 a body that fails validation.

Design
    * :func:`create_app` gets every dependency injected (store, the object whose ``mode`` the
      scorer reads, the flow tracker, firewall functions, allowlist, publish, clock), so tests
      run on any OS with a temp store and a fake firewall; nothing here imports PowerShell code
      at call time except through ``firewall_fns``.
    * ``POST /mode`` sets ``mode_holder.mode``; in the agent that is the pipeline's
      :class:`agent.scoring.Scorer`, so the very next signal is scored with the new mode. The
      mode is not persisted: after a restart it comes from ``config.yaml`` again.
    * Undo / quarantine Actions (including ``kind="undo"`` records) are saved in the store and
      published on the bus. Counts of "active" actions ignore ``undo`` records.
    * Route handlers are plain ``def``: FastAPI runs them in its thread pool, so a slow
      PowerShell call never blocks the server loop. :class:`Store` and :class:`FlowTracker`
      are thread-safe.
    * ``WS /ws``: each connection gets its own bus subscription (made before the handshake is
      accepted, closed on disconnect). Alerts and Actions are sent whole (``to_json``), never
      dropped by the throttle; FlowEvents become a small ``"type": "flow"`` summary (no
      ``features``), at most ``api.ws_flow_rate_limit_per_s`` per sliding 1-second window per
      client (the injected clock); Signals are not sent. In the agent the bus lives on the main
      loop while uvicorn runs its own loop in a thread, so :class:`_BusFeed` subscribes and reads
      on the bus loop and hands each event across with ``run_coroutine_threadsafe``. A receive
      task watches for the client's disconnect, so an idle closed socket is cleaned up at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import PureWindowsPath
from typing import Any, Literal, Protocol

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agent import alerts_text
from agent import config as config_module
from agent.bus import Bus, Subscription, SubscriptionClosed
from agent.config import Allowlist
from agent.events import Action, Alert, FlowEvent, to_json
from agent.response import firewall
from agent.response.firewall import FirewallError
from agent.store import Store

logger = logging.getLogger(__name__)

API_HOST = config_module.LOOPBACK_HOST  # §9.5: the only host the API may bind to
DEFAULT_PORT = 8765
DEFAULT_APPS_WINDOW_S = 600.0  # used when config.yaml lacks api.apps_window_s
DEFAULT_ALERTS_LIMIT = 100
DEFAULT_WS_FLOW_RATE_PER_S = 5  # used when config.yaml lacks api.ws_flow_rate_limit_per_s
WS_FLOW_WINDOW_S = 1.0  # the throttle counts flow messages per this many seconds ("per second")
WS_CLOSE_UNAVAILABLE = 1011  # no bus to read from (server error)
WS_CLOSE_GOING_AWAY = 1001  # the agent is shutting down
MAX_ALERTS_LIMIT = 1000
UNKNOWN_PROCESS = "unknown"
UNDO_KIND = "undo"
# The app's pywebview window serves its UI from http://127.0.0.1:<random port>/, a different
# origin than the API, so browsers need CORS headers. Only loopback http origins are allowed:
# a web page from the internet (or a sandboxed "null" origin) never gets them.
CORS_ORIGIN_REGEX = r"^http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?$"

Mode = Literal["off", "notify", "auto"]
Publish = Callable[[Any], None]


class ModeHolder(Protocol):
    """Anything with a read/write ``mode`` (the pipeline's Scorer)."""

    mode: str


# --- /apps: per-process flow tracker ----------------------------------------------------------


@dataclass(frozen=True)
class _Seen:
    at_s: float
    event: FlowEvent


class FlowTracker:
    """Keeps the FlowEvents of the last ``window_s`` seconds for ``GET /apps``.

    A flow counts from the moment it is added (the injected clock), not ``FlowEvent.ts_ms``:
    NFStream reports a flow up to ``active_timeout`` after it started, and a clock we control
    makes the window testable. Old flows are dropped on every ``add`` and ``apps`` call, so
    memory stays bounded by the traffic of one window. Safe to call from any thread.
    """

    def __init__(self, window_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        if window_s <= 0:
            raise ValueError(f"apps window must be > 0 s, got {window_s}")
        self.window_s = float(window_s)
        self._clock = clock
        self._lock = threading.Lock()
        self._flows: deque[_Seen] = deque()

    @classmethod
    def from_config(
        cls, cfg: dict[str, Any], clock: Callable[[], float] = time.monotonic
    ) -> FlowTracker:
        api_cfg = cfg.get("api") or {}
        return cls(float(api_cfg.get("apps_window_s", DEFAULT_APPS_WINDOW_S)), clock)

    def add(self, event: FlowEvent) -> None:
        with self._lock:
            now = self._clock()
            self._expire(now)
            self._flows.append(_Seen(now, event))

    def apps(self) -> list[dict[str, Any]]:
        """One dict per process, most traffic first (see :func:`_summarise`)."""
        with self._lock:
            self._expire(self._clock())
            events = [seen.event for seen in self._flows]
        return _summarise(events)

    def _expire(self, now: float) -> None:
        cutoff = now - self.window_s
        while self._flows and self._flows[0].at_s <= cutoff:
            self._flows.popleft()


def _summarise(events: list[FlowEvent]) -> list[dict[str, Any]]:
    apps: dict[str, dict[str, Any]] = {}
    for ev in events:
        name = ev.process or UNKNOWN_PROCESS
        app = apps.setdefault(name, {
            "process": name, "pids": set(), "exe_path": None, "bytes_out": 0, "bytes_in": 0,
            "flows": 0, "destinations": {},
        })
        if ev.pid >= 0:
            app["pids"].add(ev.pid)
        app["exe_path"] = ev.exe_path or app["exe_path"]
        app["bytes_out"] += ev.bytes_out
        app["bytes_in"] += ev.bytes_in
        app["flows"] += 1
        remote = ev.dst_ip if ev.direction == "outbound" else ev.src_ip
        port = ev.dst_port if ev.direction == "outbound" else ev.src_port
        dest = app["destinations"].setdefault(remote, {
            "ip": remote, "hostname": None, "ports": set(), "direction": ev.direction,
            "bytes_out": 0, "bytes_in": 0, "flows": 0,
        })
        dest["hostname"] = ev.hostname or dest["hostname"]
        dest["ports"].add(port)
        dest["bytes_out"] += ev.bytes_out
        dest["bytes_in"] += ev.bytes_in
        dest["flows"] += 1

    def total(d: dict[str, Any]) -> int:
        return d["bytes_out"] + d["bytes_in"]

    result = []
    for app in apps.values():
        dests = sorted(app["destinations"].values(), key=total, reverse=True)
        for dest in dests:
            dest["ports"] = sorted(dest["ports"])
        result.append({**app, "pids": sorted(app["pids"]), "destinations": dests})
    return sorted(result, key=total, reverse=True)


# --- WS /ws: flow summaries, throttle, bus feed --------------------------------------------

FLOW_SUMMARY_FIELDS = (
    "ts_ms", "process", "pid", "src_ip", "dst_ip", "dst_port", "hostname", "app_proto",
    "bytes_out", "bytes_in", "direction",
)


def flow_summary(event: FlowEvent) -> dict[str, Any]:
    """The small ``"type": "flow"`` message /ws sends for a FlowEvent (no ``features``)."""
    return {"type": "flow", **{name: getattr(event, name) for name in FLOW_SUMMARY_FIELDS}}


class FlowThrottle:
    """Allows at most ``rate_per_s`` flow messages in any ``WS_FLOW_WINDOW_S`` (sliding window).

    One per /ws client. Not thread-safe (each connection's handler uses its own).
    """

    def __init__(self, rate_per_s: int, clock: Callable[[], float] = time.monotonic) -> None:
        if rate_per_s < 0:
            raise ValueError(f"ws flow rate must be >= 0, got {rate_per_s}")
        self.rate_per_s = rate_per_s
        self._clock = clock
        self._sent: deque[float] = deque()

    def allow(self) -> bool:
        now = self._clock()
        cutoff = now - WS_FLOW_WINDOW_S
        while self._sent and self._sent[0] <= cutoff:
            self._sent.popleft()
        if len(self._sent) >= self.rate_per_s:
            return False
        self._sent.append(now)
        return True


def ws_flow_rate_from_config(cfg: dict[str, Any]) -> int:
    """``api.ws_flow_rate_limit_per_s`` (default :data:`DEFAULT_WS_FLOW_RATE_PER_S`)."""
    api_cfg = cfg.get("api") or {}
    return int(api_cfg.get("ws_flow_rate_limit_per_s", DEFAULT_WS_FLOW_RATE_PER_S))


def ws_message(event: Any, throttle: FlowThrottle) -> dict[str, Any] | None:
    """The JSON to send for a bus event, or ``None`` to skip it (Signals, throttled flows)."""
    if isinstance(event, (Alert, Action)):
        return to_json(event)
    if isinstance(event, FlowEvent) and throttle.allow():
        return flow_summary(event)
    return None


class _BusFeed:
    """One /ws connection's bus subscription, readable from the server's event loop.

    ``asyncio.Queue`` (inside a Subscription) belongs to the bus loop. When the server runs on
    that same loop (or the bus has none yet) the subscription is used directly; otherwise it is
    created, read and closed on the bus loop and each event is handed over with
    ``run_coroutine_threadsafe``.
    """

    def __init__(self, bus: Bus, name: str) -> None:
        self._bus = bus
        self._name = name
        self._sub: Subscription | None = None
        self._remote: asyncio.AbstractEventLoop | None = None

    async def open(self) -> None:
        """Subscribe. Raises ``RuntimeError`` if the bus loop is closed."""
        here = asyncio.get_running_loop()
        bus_loop = self._bus.loop
        if bus_loop is None or bus_loop is here:
            self._sub = self._bus.subscribe(self._name)
            return

        async def subscribe() -> Subscription:
            return self._bus.subscribe(self._name)

        self._remote = bus_loop
        self._sub = await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(subscribe(), bus_loop))

    async def get(self) -> Any:
        """The next event. Raises SubscriptionClosed (or RuntimeError: bus loop closed)."""
        assert self._sub is not None, "open() first"
        if self._remote is None:
            return await self._sub.get()
        return await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(self._sub.get(), self._remote))

    def close(self) -> None:
        sub, self._sub = self._sub, None
        if sub is None:
            return
        if self._remote is None:
            sub.close()
        else:
            with contextlib.suppress(RuntimeError):  # bus loop already closed
                self._remote.call_soon_threadsafe(sub.close)


async def _serve_ws(websocket: WebSocket, feed: _BusFeed, throttle: FlowThrottle) -> None:
    """Send bus events until the client disconnects or the bus subscription ends."""

    async def pump() -> None:
        while True:
            try:
                event = await feed.get()
            except (SubscriptionClosed, RuntimeError):
                with contextlib.suppress(Exception):
                    await websocket.close(code=WS_CLOSE_GOING_AWAY)
                return
            message = ws_message(event, throttle)
            if message is None:
                continue
            try:
                await websocket.send_json(message)
            except Exception:  # the client went away mid-send
                return

    async def watch() -> None:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return

    tasks = {asyncio.create_task(pump()), asyncio.create_task(watch())}
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(BaseException):
                await task


# --- request bodies -----------------------------------------------------------------------


class ModeBody(BaseModel):
    mode: Mode


# --- firewall seam ------------------------------------------------------------------------


def default_firewall() -> dict[str, Callable[..., Action]]:
    """Firewall functions, looked up at call time so tests can patch the module."""
    return {
        "undo": lambda action: firewall.undo(action),
        "undo_all": lambda: firewall.undo_all(),
        "quarantine_app": lambda exe_path: firewall.quarantine_app(exe_path),
    }


def allowlist_from_config(cfg: dict[str, Any]) -> Allowlist:
    """The allowlist at ``paths.allowlist`` (default ``data/allowlist.txt``), like the Scorer."""
    path = (cfg.get("paths") or {}).get("allowlist")
    return config_module.load_allowlist(config_module.REPO_ROOT / path if path else None)


def _no_publish(_: Any) -> None:
    return None


# --- app factory --------------------------------------------------------------------------


def create_app(
    store: Store,
    mode_holder: ModeHolder,
    tracker: FlowTracker,
    *,
    firewall_fns: Mapping[str, Callable[..., Action]] | None = None,
    allowlist: Allowlist | None = None,
    publish: Publish | None = None,
    clock: Callable[[], float] = time.monotonic,
    bus: Bus | None = None,
    ws_flow_rate_per_s: int = DEFAULT_WS_FLOW_RATE_PER_S,
) -> FastAPI:
    """Build the API.

    Args:
        store: Alerts and Actions (undo needs the stored rule names).
        mode_holder: The object whose ``mode`` the pipeline reads (the Scorer).
        tracker: Recent flows for ``GET /apps``.
        firewall_fns: ``{"undo": f(action), "undo_all": f(), "quarantine_app": f(exe_path)}``,
            each returning an Action. Defaults to :func:`default_firewall`.
        allowlist: Exe names ``POST /alerts/{id}/quarantine`` refuses. Defaults to
            ``data/allowlist.txt``.
        publish: Puts new Actions / updated Alerts on the bus (thread-safe). Default: no-op.
        clock: Monotonic seconds, for ``uptime_s`` and the /ws flow throttle.
        bus: The event bus ``WS /ws`` subscribes to (one subscription per connection). Without
            it, /ws closes every connection with code 1011.
        ws_flow_rate_per_s: Max flow summaries per second per /ws client
            (``api.ws_flow_rate_limit_per_s``, see :func:`ws_flow_rate_from_config`).
    """
    fw = dict(firewall_fns) if firewall_fns is not None else default_firewall()
    trusted = allowlist if allowlist is not None else config_module.load_allowlist()
    send = publish or _no_publish
    started = clock()
    FlowThrottle(ws_flow_rate_per_s, clock)  # validate the rate now, not on the first connect
    ws_ids = itertools.count(1)
    app = FastAPI(title="HomeSOC agent API")
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=CORS_ORIGIN_REGEX,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    def emit(item: Alert | Action) -> None:
        try:
            send(item)
        except Exception:
            logger.exception("Could not publish %s %s", item.type, item.id)

    @app.get("/status")
    def status() -> dict[str, Any]:
        active = [a for a in store.list_actions(undone=False) if a.kind != UNDO_KIND]
        return {
            "status": "running",
            "mode": mode_holder.mode,
            "uptime_s": round(clock() - started, 3),
            "alerts": len(store.list_alerts()),
            "active_actions": len(active),
            "apps": len(tracker.apps()),
        }

    @app.get("/apps")
    def apps() -> dict[str, Any]:
        return {"window_s": tracker.window_s, "apps": tracker.apps()}

    @app.get("/alerts")
    def alerts(
        limit: int = Query(DEFAULT_ALERTS_LIMIT, ge=1, le=MAX_ALERTS_LIMIT),
    ) -> dict[str, Any]:
        return {"alerts": [to_json(a) for a in store.list_alerts(limit)]}

    @app.post("/mode")
    def set_mode(body: ModeBody) -> dict[str, Any]:
        old = mode_holder.mode
        mode_holder.mode = body.mode
        logger.warning("Mode changed from %s to %s via the API", old, body.mode)
        return {"mode": mode_holder.mode}

    @app.post("/actions/{action_id}/undo")
    def undo_action(action_id: str) -> dict[str, Any]:
        action = store.get_action(action_id)
        if action is None:
            raise HTTPException(404, f"No action with id {action_id!r}")
        if action.undone:
            raise HTTPException(409, f"Action {action_id} is already undone")
        if action.kind == UNDO_KIND:
            raise HTTPException(409, f"Action {action_id} is an undo record; it cannot be undone")
        try:
            undo_record = fw["undo"](action)
        except FirewallError as exc:
            logger.error("Undo of action %s failed: %s", action_id, exc)
            raise HTTPException(502, f"Firewall undo failed: {exc}") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        store.mark_undone(action_id)
        store.save_action(undo_record)
        updated = store.get_action(action_id) or replace(action, undone=True)
        emit(updated)
        emit(undo_record)
        return {"action": to_json(updated), "undo": to_json(undo_record)}

    @app.post("/undo-all")
    def undo_all() -> dict[str, Any]:
        try:
            undo_record = fw["undo_all"]()
        except FirewallError as exc:
            logger.error("Undo all failed: %s", exc)
            raise HTTPException(502, f"Firewall undo-all failed: {exc}") from exc
        count = store.mark_all_undone()
        store.save_action(undo_record)
        emit(undo_record)
        return {"undone": count, "undo": to_json(undo_record)}

    @app.post("/alerts/{alert_id}/quarantine")
    def quarantine(alert_id: str) -> dict[str, Any]:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404, f"No alert with id {alert_id!r}")
        exe_path = alert.exe_path
        if not exe_path:
            # §9.6: no known exe path -> we can't be sure which program to block.
            raise HTTPException(409, f"The exe path of {alert.process} is unknown; "
                                     "it cannot be quarantined")
        exe_name = PureWindowsPath(exe_path).name
        if alert.process in trusted or exe_name in trusted:
            raise HTTPException(409, f"{exe_name} is on the trusted apps list and is never "
                                     "quarantined")
        if _already_quarantined(store, exe_path):
            raise HTTPException(409, f"{exe_name} is already quarantined")
        try:
            action = fw["quarantine_app"](exe_path)
        except FirewallError as exc:
            logger.error("Quarantine of %s failed: %s", exe_path, exc)
            raise HTTPException(502, f"Firewall quarantine failed: {exc}") from exc
        except ValueError as exc:  # includes UnsafePathError
            raise HTTPException(400, f"Cannot quarantine {exe_path!r}: {exc}") from exc
        logger.warning("Quarantined %s at the user's request (alert %s, action %s)",
                       exe_path, alert_id, action.id)
        store.save_action(action)
        emit(action)
        updated = _with_action(store, alert, action, mode_holder.mode)
        store.save_alert(updated)
        emit(updated)
        return {"alert": to_json(updated), "action": to_json(action)}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        if bus is None:
            await websocket.close(code=WS_CLOSE_UNAVAILABLE)
            return
        feed = _BusFeed(bus, f"ws{next(ws_ids)}")
        try:
            # Subscribe before accepting, so a client that is connected never misses an event.
            await feed.open()
        except RuntimeError:
            logger.warning("WS /ws refused: the bus loop is closed")
            await websocket.close(code=WS_CLOSE_UNAVAILABLE)
            return
        try:
            await websocket.accept()
            await _serve_ws(websocket, feed, FlowThrottle(ws_flow_rate_per_s, clock))
        finally:
            feed.close()

    return app


def _already_quarantined(store: Store, exe_path: str) -> bool:
    wanted = exe_path.casefold()  # Windows paths are case-insensitive
    return any(
        a.kind == "quarantine_app" and a.target.casefold() == wanted
        for a in store.list_actions(undone=False)
    )


def _with_action(store: Store, alert: Alert, action: Action, mode: str) -> Alert:
    """The alert with ``action`` appended to ``action_ids`` and its text rewritten."""
    actions = [a for a in (store.get_action(i) for i in alert.action_ids) if a is not None]
    actions.append(action)
    text = alerts_text.build_alert_text(alert.process, alert.signals, actions, mode=mode)
    return replace(alert, **text.as_fields(), action_ids=[*alert.action_ids, action.id])


# --- server -------------------------------------------------------------------------------


def server_settings(cfg: dict[str, Any]) -> tuple[str, int]:
    """``(host, port)`` from the ``api`` section. Refuses any host but 127.0.0.1 (§9.5)."""
    api_cfg = cfg.get("api") or {}
    host = str(api_cfg.get("host", API_HOST))
    if host != API_HOST:
        raise ValueError(f"Refusing to bind the API to {host!r}; only {API_HOST} is allowed")
    return host, int(api_cfg.get("port", DEFAULT_PORT))


def make_server(app: FastAPI, cfg: dict[str, Any]) -> Any:
    """A ``uvicorn.Server`` for ``app`` on the loopback host/port from config."""
    import uvicorn  # imported here so the API module is importable without uvicorn

    host, port = server_settings(cfg)
    server_cfg = uvicorn.Config(app, host=host, port=port, log_level="info", access_log=False)
    if server_cfg.host != API_HOST:  # belt and braces: never 0.0.0.0
        raise ValueError(f"uvicorn would bind to {server_cfg.host!r}")
    return uvicorn.Server(server_cfg)


class ApiServer:
    """Runs a uvicorn server in a daemon thread (its own event loop, no signal handlers)."""

    def __init__(self, server: Any) -> None:
        self._server = server
        self._thread = threading.Thread(target=server.run, name="api", daemon=True)

    def start(self) -> ApiServer:
        self._thread.start()
        return self

    def stop(self, timeout_s: float = 5.0) -> None:
        self._server.should_exit = True
        self._thread.join(timeout_s)


def start_in_thread(app: FastAPI, cfg: dict[str, Any]) -> ApiServer:
    """Start the API on 127.0.0.1 in the background. Call ``.stop()`` on shutdown."""
    host, port = server_settings(cfg)
    logger.info("HomeSOC API listening on http://%s:%d", host, port)
    return ApiServer(make_server(app, cfg)).start()
