"""Tests for ``WS /ws`` in agent.api (CLAUDE.md §6.6): Alerts and Actions pushed as JSON, flow
summaries throttled to ``api.ws_flow_rate_limit_per_s`` per second per client.

Every test publishes on a real :class:`agent.bus.Bus` and reads what a real WebSocket client
(``TestClient.websocket_connect``) actually receives. The server subscribes before it accepts
the handshake, so anything published after ``websocket_connect`` returns is delivered. Every
receive has a timeout, so a broken /ws fails the test instead of hanging it.
"""

from __future__ import annotations

import asyncio
import copy
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from agent import api, config
from agent.api import FlowThrottle, FlowTracker, create_app, flow_summary
from agent.bus import Bus
from agent.config import Allowlist
from agent.events import Signal
from agent.main import NamedDetector, run_agent
from agent.scoring import Scorer
from agent.store import Store
from tests.test_api import LAB_C2, PC_IP, PROC, FakeClock, flow, make_action, make_alert

RECV_TIMEOUT_S = 5.0
RATE = 5


def recv(ws: WebSocketTestSession, timeout_s: float = RECV_TIMEOUT_S) -> dict[str, Any]:
    """Next JSON message from the server; raises TimeoutError instead of blocking forever."""

    async def _get() -> Any:
        with anyio.fail_after(timeout_s):
            return await ws._send_rx.receive()

    message = ws.portal.call(_get)
    assert message["type"] == "websocket.send", message
    return json.loads(message["text"])


def recv_until_alert(ws: WebSocketTestSession, alert_id: str) -> list[dict[str, Any]]:
    """Every message up to and including the alert ``alert_id`` (used as an end marker)."""
    messages = []
    while True:
        msg = recv(ws)
        messages.append(msg)
        if msg["type"] == "alert" and msg["id"] == alert_id:
            return messages


@pytest.fixture
def cfg() -> dict[str, Any]:
    return copy.deepcopy(config.load())


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "homesoc.db") as db:
        yield db


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def bus() -> Bus:
    return Bus(queue_size=1000, drop_log_every=1000)


@pytest.fixture
def client(cfg: dict[str, Any], store: Store, clock: FakeClock, bus: Bus) -> Iterator[TestClient]:
    scorer = Scorer(cfg, Allowlist(frozenset({"chrome.exe"})), mode="notify")
    app = create_app(store, scorer, FlowTracker(600.0, clock), firewall_fns={},
                     allowlist=Allowlist(frozenset()), clock=clock, bus=bus,
                     ws_flow_rate_per_s=RATE)
    with TestClient(app) as c:  # one portal / event loop shared by every websocket
        yield c


# --- acceptance: alerts and actions --------------------------------------------------------


def test_published_alert_reaches_client_as_json(client: TestClient, bus: Bus) -> None:
    with client.websocket_connect("/ws") as ws:
        alert = make_alert("al-ws", action_ids=["a1"])
        bus.publish_threadsafe(alert)
        msg = recv(ws)
    assert msg["type"] == "alert"
    assert msg["id"] == "al-ws"
    assert msg["process"] == PROC
    assert msg["severity"] == "high"
    assert msg["action_ids"] == ["a1"]
    assert msg["signals"][0]["type"] == "signal"
    assert msg["signals"][0]["detector"] == "beacon"
    assert msg["signals"][0]["target"] == LAB_C2


def test_published_action_reaches_client(client: TestClient, bus: Bus) -> None:
    with client.websocket_connect("/ws") as ws:
        bus.publish_threadsafe(make_action("act-ws"))
        msg = recv(ws)
    assert msg["type"] == "action"
    assert msg["id"] == "act-ws"
    assert msg["kind"] == "quarantine_app"
    assert msg["rule_names"] == [f"HomeSOC quarantine FreeGameCheats.exe {d} #a1a1a1a1"
                                 for d in ("out", "in")]
    assert msg["undone"] is False


def test_signals_are_not_sent(client: TestClient, bus: Bus) -> None:
    with client.websocket_connect("/ws") as ws:
        bus.publish_threadsafe(Signal(detector="dga", process=PROC, target="x.example"))
        bus.publish_threadsafe(make_alert("marker"))
        messages = recv_until_alert(ws, "marker")
    assert [m["type"] for m in messages] == ["alert"]


# --- acceptance: flow throttle ---------------------------------------------------------------


def test_100_flows_in_one_second_give_at_most_5_flow_messages(
    client: TestClient, bus: Bus, clock: FakeClock
) -> None:
    with client.websocket_connect("/ws") as ws:
        for i in range(100):
            clock.now = 1000.0 + i * 0.009  # all 100 inside one second (1000.0 .. 1000.891)
            bus.publish_threadsafe(flow(src_port=40000 + i))
        bus.publish_threadsafe(make_action("act-mid"))  # never throttled
        bus.publish_threadsafe(make_alert("end-1"))
        first_second = recv_until_alert(ws, "end-1")

        clock.now = 1001.5  # a new second: flows flow again
        bus.publish_threadsafe(flow(dst_ip="10.0.0.9"))
        bus.publish_threadsafe(make_alert("end-2"))
        next_second = recv_until_alert(ws, "end-2")

    flows = [m for m in first_second if m["type"] == "flow"]
    assert len(flows) == RATE
    assert [m["type"] for m in first_second[-2:]] == ["action", "alert"]
    assert [m["type"] for m in next_second] == ["flow", "alert"]
    assert next_second[0]["dst_ip"] == "10.0.0.9"


def test_flow_message_is_a_small_summary(client: TestClient, bus: Bus) -> None:
    with client.websocket_connect("/ws") as ws:
        bus.publish_threadsafe(flow(hostname="c2.lab", features={"big": list(range(100))},
                                    ts_ms=123, bytes_out=500, bytes_in=40))
        msg = recv(ws)
    assert msg == {
        "type": "flow", "ts_ms": 123, "process": PROC, "pid": 42, "src_ip": PC_IP,
        "dst_ip": LAB_C2, "dst_port": 8080, "hostname": "c2.lab", "app_proto": None,
        "bytes_out": 500, "bytes_in": 40, "direction": "outbound",
    }


def test_throttle_is_per_client(client: TestClient, bus: Bus) -> None:
    with client.websocket_connect("/ws") as a, client.websocket_connect("/ws") as b:
        for _ in range(20):
            bus.publish_threadsafe(flow())
        bus.publish_threadsafe(make_alert("end"))
        got_a = recv_until_alert(a, "end")
        got_b = recv_until_alert(b, "end")
    assert sum(m["type"] == "flow" for m in got_a) == RATE
    assert sum(m["type"] == "flow" for m in got_b) == RATE


def test_flow_throttle_sliding_window() -> None:
    clock = FakeClock(0.0)
    throttle = FlowThrottle(2, clock)
    assert [throttle.allow(), throttle.allow(), throttle.allow()] == [True, True, False]
    clock.now = 0.999
    assert throttle.allow() is False
    clock.now = 1.0  # the first two sends left the 1 s window
    assert [throttle.allow(), throttle.allow(), throttle.allow()] == [True, True, False]
    with pytest.raises(ValueError):
        FlowThrottle(-1, clock)


def test_rate_comes_from_config(cfg: dict[str, Any]) -> None:
    assert api.ws_flow_rate_from_config(cfg) == cfg["api"]["ws_flow_rate_limit_per_s"] == 5
    cfg["api"]["ws_flow_rate_limit_per_s"] = 2
    assert api.ws_flow_rate_from_config(cfg) == 2
    del cfg["api"]["ws_flow_rate_limit_per_s"]
    assert api.ws_flow_rate_from_config(cfg) == api.DEFAULT_WS_FLOW_RATE_PER_S


# --- acceptance: disconnects -------------------------------------------------------------------


def test_disconnecting_client_does_not_break_delivery_to_others(
    client: TestClient, bus: Bus
) -> None:
    with client.websocket_connect("/ws") as stays:
        with client.websocket_connect("/ws") as leaves:
            assert len(bus.subscribers) == 2
            bus.publish_threadsafe(make_alert("both"))
            assert recv(leaves)["id"] == "both"
            assert recv(stays)["id"] == "both"
        # `leaves` disconnected: its handler has returned and unsubscribed.
        assert len(bus.subscribers) == 1

        bus.publish_threadsafe(make_alert("after"))
        bus.publish_threadsafe(make_action("act-after"))
        assert recv(stays)["id"] == "after"
        assert recv(stays)["id"] == "act-after"

        with client.websocket_connect("/ws") as joins:  # a new client still works too
            bus.publish_threadsafe(make_alert("late"))
            assert recv(joins)["id"] == "late"
            assert recv(stays)["id"] == "late"
    assert bus.subscribers == ()


def test_ws_without_bus_closes(cfg: dict[str, Any], store: Store) -> None:
    scorer = Scorer(cfg, Allowlist(frozenset()), mode="notify")
    app = create_app(store, scorer, FlowTracker(600.0), firewall_fns={},
                     allowlist=Allowlist(frozenset()))
    with TestClient(app) as c, pytest.raises(WebSocketDisconnect) as exc:
        with c.websocket_connect("/ws") as ws:
            ws.receive_json()
    assert exc.value.code == api.WS_CLOSE_UNAVAILABLE


# --- the agent's layout: bus on one loop, server on another ------------------------------------


def test_bus_on_another_loop_thread(cfg: dict[str, Any], store: Store, clock: FakeClock) -> None:
    """In the agent the bus lives on the main loop and uvicorn on its own thread's loop."""
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        bus = Bus(queue_size=1000, drop_log_every=1000, loop=loop)
        scorer = Scorer(cfg, Allowlist(frozenset()), mode="notify")
        app = create_app(store, scorer, FlowTracker(600.0, clock), firewall_fns={},
                         allowlist=Allowlist(frozenset()), clock=clock, bus=bus,
                         ws_flow_rate_per_s=RATE)
        with TestClient(app) as c:
            with c.websocket_connect("/ws") as stays:
                with c.websocket_connect("/ws") as leaves:
                    for _ in range(10):
                        bus.publish_threadsafe(flow())
                    bus.publish_threadsafe(make_alert("x1"))
                    got = recv_until_alert(stays, "x1")
                    assert recv_until_alert(leaves, "x1")[-1]["id"] == "x1"
                assert sum(m["type"] == "flow" for m in got) == RATE
                bus.publish_threadsafe(make_action("x2"))
                assert recv(stays)["id"] == "x2"
        # Unsubscribing happens on the bus loop; wait for it there.
        asyncio.run_coroutine_threadsafe(asyncio.sleep(0), loop).result(RECV_TIMEOUT_S)
        assert bus.subscribers == ()
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(RECV_TIMEOUT_S)
        loop.close()


def test_run_agent_gives_ws_clients_the_agents_bus(cfg: dict[str, Any], store: Store) -> None:
    """End to end through run_agent: captured flows reach a /ws client as flow summaries."""
    nflows = [SimpleNamespace(system_process_name=PROC, system_process_pid=42, src_ip=PC_IP,
                              dst_ip=LAB_C2, src_port=52000 + i, dst_port=8080, protocol=6,
                              src2dst_bytes=100, dst2src_bytes=10,
                              bidirectional_first_seen_ms=1_700_000_000_000 + i * 5000)
              for i in range(3)]
    connected = threading.Event()
    finished = threading.Event()
    received: list[dict[str, Any]] = []
    errors: list[BaseException] = []

    def streamer(_: Any) -> Iterator[Any]:
        assert connected.wait(RECV_TIMEOUT_S), "ws client never connected"
        yield from nflows
        finished.wait(RECV_TIMEOUT_S)  # keep the agent up until the client is done

    def ws_client(app: Any) -> None:
        try:
            with TestClient(app) as c, c.websocket_connect("/ws") as ws:
                connected.set()
                received.extend(recv(ws) for _ in nflows)
        except BaseException as exc:
            errors.append(exc)
        finally:
            connected.set()
            finished.set()

    class FakeServer:
        def stop(self) -> None:
            pass

    def starter(app: Any, c: dict[str, Any]) -> FakeServer:
        threading.Thread(target=ws_client, args=(app,), daemon=True).start()
        return FakeServer()

    asyncio.run(asyncio.wait_for(
        run_agent(cfg, threading.Event(), streamer_factory=streamer,
                  detectors=[NamedDetector("none", lambda e: [])], store=store,
                  api_starter=starter),
        10.0,
    ))

    assert not errors, errors
    assert [m["type"] for m in received] == ["flow"] * 3
    assert [m["dst_ip"] for m in received] == [LAB_C2] * 3
    assert all("features" not in m for m in received)


def test_flow_summary_drops_features() -> None:
    summary = flow_summary(flow(features={"x": 1}))
    assert summary["type"] == "flow" and "features" not in summary
