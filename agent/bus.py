"""Asyncio publish/subscribe fan-out bus (CLAUDE.md §3, §6.1, §6.6).

Capture publishes events; detectors, scoring and the API each hold a :class:`Subscription`
with its own bounded queue, so a slow subscriber never slows the others down.

Threading: ``asyncio.Queue`` is not thread-safe. :meth:`Bus.publish` must be called on the
event-loop thread. Code running in another thread (e.g. the synchronous NFStream capture loop)
calls :meth:`Bus.publish_threadsafe`, which hands the event to the loop thread with
``loop.call_soon_threadsafe``. Both calls are plain, non-async and never block.

Drop policy: when a subscriber's queue is full, its oldest event is dropped to make room for the
new one and that subscriber's ``drops`` counter goes up. A warning is logged on the first drop
and then every ``drop_log_every`` drops (with the running total), so a flood can't spam the log.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from agent.events import Action, Alert, FlowEvent, Signal

logger = logging.getLogger(__name__)

Event = FlowEvent | Signal | Alert | Action
"""The event types the bus is meant to carry. Any object is accepted at runtime."""


class SubscriptionClosed(Exception):
    """Raised by :meth:`Subscription.get` once the subscription is closed and drained."""


class _Closed:
    """Sentinel put on a queue to wake a consumer waiting in ``get()`` when it is closed."""


_CLOSED = _Closed()


class Subscription:
    """One subscriber's bounded queue. Create it with :meth:`Bus.subscribe`.

    Consume with ``await sub.get()`` or ``async for event in sub``. Close with ``sub.close()``,
    ``bus.unsubscribe(sub)`` or by using it as a context manager.
    """

    def __init__(self, bus: Bus, name: str, queue_size: int, drop_log_every: int) -> None:
        self.name = name
        self._bus = bus
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=queue_size)
        self._drop_log_every = drop_log_every
        self._drops = 0
        self._closed = False

    @property
    def drops(self) -> int:
        """How many events were dropped because this subscriber's queue was full."""
        return self._drops

    @property
    def closed(self) -> bool:
        return self._closed

    def qsize(self) -> int:
        """Number of items waiting in the queue."""
        return self._queue.qsize()

    async def get(self) -> Any:
        """Wait for the next event.

        Raises:
            SubscriptionClosed: If the subscription is closed and no events are left.
        """
        if self._closed and self._queue.empty():
            raise SubscriptionClosed(self.name)
        item = await self._queue.get()
        if item is _CLOSED:
            raise SubscriptionClosed(self.name)
        return item

    def get_nowait(self) -> Any:
        """Return the next event without waiting.

        Raises:
            asyncio.QueueEmpty: If no event is waiting.
            SubscriptionClosed: If the subscription is closed and no events are left.
        """
        if self._closed and self._queue.empty():
            raise SubscriptionClosed(self.name)
        item = self._queue.get_nowait()
        if item is _CLOSED:
            raise SubscriptionClosed(self.name)
        return item

    def close(self) -> None:
        """Stop delivery to this subscriber. Safe to call more than once."""
        if self._closed:
            return
        self._bus._remove(self)
        self._closed = True
        # Wake a consumer blocked in get(); events queued before the close are still delivered.
        self._put_dropping_oldest(_CLOSED)

    def _deliver(self, event: Any) -> None:
        if not self._closed:
            self._put_dropping_oldest(event)

    def _put_dropping_oldest(self, item: Any) -> None:
        try:
            self._queue.put_nowait(item)
            return
        except asyncio.QueueFull:
            pass
        self._queue.get_nowait()  # drop the oldest item; the queue is full so it can't be empty
        self._drops += 1
        if self._drops == 1 or self._drops % self._drop_log_every == 0:
            logger.warning(
                "Bus subscriber %r is full (size %d); dropped oldest event (%d dropped so far)",
                self.name,
                self._queue.maxsize,
                self._drops,
            )
        self._queue.put_nowait(item)

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Any:
        try:
            return await self.get()
        except SubscriptionClosed:
            raise StopAsyncIteration from None

    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class Bus:
    """Fan-out bus: every published event goes to every open subscription, in order."""

    def __init__(
        self,
        queue_size: int,
        drop_log_every: int,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if queue_size < 1:
            raise ValueError(f"bus queue_size must be >= 1, got {queue_size}")
        if drop_log_every < 1:
            raise ValueError(f"bus drop_log_every must be >= 1, got {drop_log_every}")
        self._queue_size = queue_size
        self._drop_log_every = drop_log_every
        self._loop = loop
        self._subs: list[Subscription] = []

    @classmethod
    def from_config(
        cls, cfg: dict[str, Any], loop: asyncio.AbstractEventLoop | None = None
    ) -> Bus:
        """Build a bus from the ``bus`` section of a loaded ``config.yaml``."""
        bus_cfg = cfg["bus"]
        return cls(bus_cfg["queue_size"], bus_cfg["drop_log_every"], loop=loop)

    @property
    def subscribers(self) -> tuple[Subscription, ...]:
        return tuple(self._subs)

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Set the event loop that :meth:`publish_threadsafe` hands events to."""
        self._loop = loop

    def subscribe(self, name: str = "") -> Subscription:
        """Create a new subscription. Call on the loop thread.

        If no loop is attached yet and one is running, it is attached for
        :meth:`publish_threadsafe`.
        """
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        sub = Subscription(self, name or f"sub{len(self._subs)}", self._queue_size,
                           self._drop_log_every)
        self._subs.append(sub)
        logger.debug("Bus subscriber %r added", sub.name)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        """Stop delivery to ``sub``. Safe to call more than once."""
        sub.close()

    def publish(self, event: Any) -> None:
        """Deliver ``event`` to every subscriber without blocking. Loop thread only."""
        for sub in tuple(self._subs):
            sub._deliver(event)

    def publish_threadsafe(self, event: Any) -> None:
        """Like :meth:`publish`, but callable from any thread. Returns immediately.

        Raises:
            RuntimeError: If no event loop is attached.
        """
        if self._loop is None:
            raise RuntimeError("Bus has no event loop attached; call attach_loop() first")
        try:
            self._loop.call_soon_threadsafe(self.publish, event)
        except RuntimeError:
            # The loop is closed (agent shutting down); there is no one left to deliver to.
            logger.debug("Bus loop is closed; dropped event published from another thread")

    def _remove(self, sub: Subscription) -> None:
        if sub in self._subs:
            self._subs.remove(sub)
            logger.debug("Bus subscriber %r removed", sub.name)
