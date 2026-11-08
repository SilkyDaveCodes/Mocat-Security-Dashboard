"""Tests for agent.bus: fan-out order, drop-oldest on full queues, unsubscribe, threading."""

from __future__ import annotations

import asyncio
import logging
import threading
import time

import pytest

from agent import config
from agent.bus import Bus, Subscription, SubscriptionClosed
from agent.events import Alert, FlowEvent, Signal

TIMEOUT_S = 2.0


def _flows(n: int) -> list[FlowEvent]:
    return [FlowEvent(ts_ms=i, process="chrome.exe", dst_ip="10.0.0.1", dst_port=443)
            for i in range(n)]


def _drain(sub: Subscription) -> list:
    items = []
    while True:
        try:
            items.append(sub.get_nowait())
        except asyncio.QueueEmpty:
            return items


# --- config ---------------------------------------------------------------------------------


def test_config_has_bus_queue_size() -> None:
    cfg = config.load()
    assert cfg["bus"]["queue_size"] == 1000
    assert cfg["bus"]["drop_log_every"] >= 1


def test_bus_from_config_uses_queue_size() -> None:
    async def main() -> None:
        bus = Bus.from_config({"bus": {"queue_size": 3, "drop_log_every": 10}})
        sub = bus.subscribe("s")
        for event in _flows(5):
            bus.publish(event)
        assert sub.qsize() == 3
        assert sub.drops == 2

    asyncio.run(main())


@pytest.mark.parametrize("bad", [0, -1])
def test_invalid_sizes_are_rejected(bad: int) -> None:
    with pytest.raises(ValueError):
        Bus(queue_size=bad, drop_log_every=1)
    with pytest.raises(ValueError):
        Bus(queue_size=1, drop_log_every=bad)


# --- AC1: every subscriber receives every event, in order -------------------------------------


def test_three_subscribers_receive_every_event_in_order() -> None:
    events = _flows(50) + [Signal(detector="beacon", score=0.9), Alert(id="a1")]

    async def consume(sub: Subscription, n: int) -> list:
        return [await sub.get() for _ in range(n)]

    async def main() -> None:
        bus = Bus(queue_size=100, drop_log_every=1)
        subs = [bus.subscribe(f"s{i}") for i in range(3)]
        tasks = [asyncio.create_task(consume(s, len(events))) for s in subs]
        for event in events:
            bus.publish(event)
        results = await asyncio.wait_for(asyncio.gather(*tasks), TIMEOUT_S)
        for sub, got in zip(subs, results, strict=True):
            assert got == events
            assert all(a is b for a, b in zip(got, events, strict=True))
            assert sub.drops == 0
            assert sub.qsize() == 0

    asyncio.run(main())


def test_async_for_yields_events_then_stops_on_close() -> None:
    events = _flows(5)

    async def main() -> None:
        bus = Bus(queue_size=10, drop_log_every=1)
        sub = bus.subscribe()
        for event in events:
            bus.publish(event)
        sub.close()
        got = [e async for e in sub]
        assert got == events

    asyncio.run(main())


def test_publish_with_zero_subscribers_is_a_no_op() -> None:
    bus = Bus(queue_size=1, drop_log_every=1)
    bus.publish(FlowEvent())
    assert bus.subscribers == ()


# --- AC2: full queue -> publish returns immediately, oldest dropped, counter up --------------


def test_full_queue_drops_oldest_and_counts(caplog: pytest.LogCaptureFixture) -> None:
    events = _flows(10)

    async def main() -> None:
        bus = Bus(queue_size=3, drop_log_every=1000)
        slow = bus.subscribe("slow")
        fast = bus.subscribe("fast")
        fast_got: list = []

        start = time.monotonic()
        for event in events:
            result = bus.publish(event)  # plain call: would be a coroutine if it awaited
            assert result is None
            fast_got.extend(_drain(fast))  # the fast consumer keeps up
        assert time.monotonic() - start < 0.5

        assert _drain(slow) == events[-3:]  # newest three, in order
        assert slow.drops == 7
        assert fast_got == events
        assert fast.drops == 0

    with caplog.at_level(logging.WARNING, logger="agent.bus"):
        asyncio.run(main())
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    # throttled: only the first drop is logged (next log would be at drop 1000)
    assert len(warnings) == 1
    assert "slow" in warnings[0].getMessage()
    assert "1 dropped" in warnings[0].getMessage()


def test_drop_warning_is_throttled_and_shows_running_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def main() -> None:
        bus = Bus(queue_size=1, drop_log_every=5)
        sub = bus.subscribe("flood")
        for event in _flows(13):  # 12 drops
            bus.publish(event)
        assert sub.drops == 12

    with caplog.at_level(logging.WARNING, logger="agent.bus"):
        asyncio.run(main())
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(messages) == 3  # drops 1, 5, 10
    assert "(1 dropped" in messages[0]
    assert "(5 dropped" in messages[1]
    assert "(10 dropped" in messages[2]


def test_publish_returns_while_a_consumer_is_blocked_elsewhere() -> None:
    """A full subscriber that nobody reads must not stall publishing to a live consumer."""

    async def main() -> None:
        bus = Bus(queue_size=2, drop_log_every=1000)
        stuck = bus.subscribe("stuck")
        live = bus.subscribe("live")
        events = _flows(20)

        async def reader() -> list:
            return [await live.get() for _ in range(len(events))]

        task = asyncio.create_task(reader())
        for event in events:
            bus.publish(event)
            await asyncio.sleep(0)  # let the live reader run
        assert await asyncio.wait_for(task, TIMEOUT_S) == events
        assert live.drops == 0
        assert stuck.drops == 18
        assert _drain(stuck) == events[-2:]

    asyncio.run(main())


# --- AC3: unsubscribing stops delivery to that subscriber only ------------------------------


def test_unsubscribe_stops_delivery_to_that_subscriber_only() -> None:
    first, second = _flows(3), _flows(6)[3:]

    async def main() -> None:
        bus = Bus(queue_size=10, drop_log_every=1)
        a, b, c = bus.subscribe("a"), bus.subscribe("b"), bus.subscribe("c")
        for event in first:
            bus.publish(event)
        bus.unsubscribe(b)
        for event in second:
            bus.publish(event)

        assert bus.subscribers == (a, c)
        assert b.closed
        assert _drain(a) == first + second
        assert _drain(c) == first + second
        # b keeps what arrived before it unsubscribed, then reports closed
        assert [await b.get() for _ in first] == first
        with pytest.raises(SubscriptionClosed):
            await b.get()
        with pytest.raises(SubscriptionClosed):
            b.get_nowait()

    asyncio.run(main())


def test_unsubscribe_twice_is_harmless() -> None:
    async def main() -> None:
        bus = Bus(queue_size=10, drop_log_every=1)
        a, b = bus.subscribe("a"), bus.subscribe("b")
        bus.unsubscribe(a)
        bus.unsubscribe(a)
        a.close()
        assert bus.subscribers == (b,)
        bus.publish(FlowEvent(ts_ms=1))
        assert _drain(b) == [FlowEvent(ts_ms=1)]
        with pytest.raises(SubscriptionClosed):
            await a.get()

    asyncio.run(main())


def test_close_wakes_a_waiting_consumer() -> None:
    async def main() -> None:
        bus = Bus(queue_size=10, drop_log_every=1)
        sub = bus.subscribe()

        async def wait() -> list:
            return [e async for e in sub]

        task = asyncio.create_task(wait())
        await asyncio.sleep(0)
        bus.publish(FlowEvent(ts_ms=7))
        await asyncio.sleep(0)
        sub.close()
        assert await asyncio.wait_for(task, TIMEOUT_S) == [FlowEvent(ts_ms=7)]

    asyncio.run(main())


def test_context_manager_unsubscribes() -> None:
    async def main() -> None:
        bus = Bus(queue_size=10, drop_log_every=1)
        with bus.subscribe("ctx") as sub:
            assert bus.subscribers == (sub,)
        assert sub.closed
        assert bus.subscribers == ()

    asyncio.run(main())


# --- threading: publish_threadsafe from a real thread -----------------------------------------


def test_publish_threadsafe_from_a_real_thread_delivers_in_order() -> None:
    events = _flows(200)

    async def main() -> None:
        bus = Bus(queue_size=1000, drop_log_every=1)
        subs = [bus.subscribe(f"s{i}") for i in range(3)]  # attaches the running loop
        loop_thread = threading.get_ident()
        seen_threads: set[int] = set()
        original = bus.publish

        def spy(event: object) -> None:
            seen_threads.add(threading.get_ident())
            original(event)

        bus.publish = spy  # type: ignore[method-assign]

        def producer() -> None:
            for event in events:
                bus.publish_threadsafe(event)

        thread = threading.Thread(target=producer)
        thread.start()

        async def consume(sub: Subscription) -> list:
            return [await sub.get() for _ in range(len(events))]

        results = await asyncio.wait_for(
            asyncio.gather(*(consume(s) for s in subs)), TIMEOUT_S
        )
        await asyncio.to_thread(thread.join, TIMEOUT_S)
        assert not thread.is_alive()
        for got in results:
            assert got == events
        assert seen_threads == {loop_thread}  # delivery happened on the loop thread

    asyncio.run(main())


def test_publish_threadsafe_without_loop_raises() -> None:
    bus = Bus(queue_size=1, drop_log_every=1)
    bus.subscribe()  # no running loop here, so none is attached
    with pytest.raises(RuntimeError):
        bus.publish_threadsafe(FlowEvent())


def test_publish_threadsafe_after_loop_closed_does_not_raise() -> None:
    loop = asyncio.new_event_loop()
    bus = Bus(queue_size=1, drop_log_every=1, loop=loop)
    loop.close()
    bus.publish_threadsafe(FlowEvent())  # agent shutting down: dropped quietly
