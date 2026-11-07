"""HomeSOC agent entry point: capture -> detectors -> scoring -> response -> store + bus.

CLAUDE.md §3. ``python -m agent.main`` (admin terminal on the Windows VM) starts live capture and
the detection pipeline, logs every FlowEvent, and stops on Ctrl+C.

Design
    * :class:`Pipeline` is the only place the detectors meet (§10: detectors never import each
      other). Every dependency (detectors, scorer, store, bus, firewall functions, process
      lookup) is injected, so the whole event -> detectors -> scorer -> actions -> store + bus
      path is testable without NFStream, PowerShell or a network.
    * Threads: NFStream capture blocks, so it runs in its own daemon thread and publishes with
      ``bus.publish_threadsafe`` (agent/capture.py). The pipeline holds its own bus subscription
      (bounded, drop-oldest), so slow detection or firewall work never blocks capture (§6.1).
      :meth:`Pipeline.run` takes FlowEvents off that subscription on the loop thread and hands
      each to :meth:`Pipeline.handle` in a worker thread (PowerShell can take seconds), one at a
      time, so the stateful detectors and the scorer never run concurrently.
    * :meth:`Pipeline.handle` never raises: a detector that raises is logged and skipped, so the
      other detectors' signals still reach the scorer. A failed firewall call is logged and the
      alert still goes out, with :func:`agent.scoring.finalize_alert` describing what really
      happened (no action).
    * Scoring owns the policy (mode, allowlist, unknown exe path); the pipeline only carries out
      the :class:`agent.scoring.ActionRequest` it is given and adds no block paths of its own.

Adding a detector (anomaly, flow_model): write its module with a ``process(event)`` method and
add one ``(name, factory)`` entry to :data:`DETECTOR_FACTORIES`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent import api, capture, config, evidence, procinfo
from agent.bus import Bus, Subscription
from agent.detectors.beacon import BeaconDetector
from agent.detectors.dga import DgaDetector
from agent.detectors.intel import IntelDetector
from agent.events import Action, Alert, FlowEvent, Signal
from agent.procinfo import ProcInfo
from agent.response import firewall
from agent.response.firewall import FirewallError
from agent.scoring import Decision, Scorer, finalize_alert
from agent.store import Store

logger = logging.getLogger(__name__)

UNKNOWN_PROCESS = "unknown"
FLOW_MODEL = "flow_model"  # inbound signals are about a remote IP, not a local process
DEFAULT_PROCINFO_CACHE_TTL_S = 30.0  # used when config.yaml lacks pipeline.procinfo_cache_ttl_s
DEFAULT_PRUNE_INTERVAL_S = 60.0  # used when config.yaml lacks pipeline.prune_interval_s
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
LOG_FILE_NAME = "agent.log"  # in the data root, installed (frozen) agent only

DetectorFn = Callable[[FlowEvent], list[Signal]]
DetectorFactory = Callable[[dict[str, Any]], DetectorFn]
ProcLookup = Callable[[int], ProcInfo | None]
FirewallFn = Callable[[str], Action]
Publish = Callable[[Any], None]
ApiStarter = Callable[[Any, dict[str, Any]], Any]  # (FastAPI app, cfg) -> object with .stop()
RingStarter = Callable[[dict[str, Any]], Any]  # cfg -> started ring capture with .stop()


@dataclass(frozen=True)
class NamedDetector:
    """A detector's ``process`` function plus a name for log messages."""

    name: str
    process: DetectorFn


DETECTOR_FACTORIES: tuple[tuple[str, DetectorFactory], ...] = (
    ("intel", lambda cfg: IntelDetector(cfg).process),
    ("dga", lambda cfg: DgaDetector(cfg).process),
    ("beacon", lambda cfg: BeaconDetector(cfg).process),
    # ("anomaly", ...) and ("flow_model", ...) go here once those detectors exist.
)
"""Detectors the agent runs, in order. One entry per detector module."""


def build_detectors(
    cfg: dict[str, Any],
    factories: Iterable[tuple[str, DetectorFactory]] = DETECTOR_FACTORIES,
) -> list[NamedDetector]:
    """Build every detector. One that fails to start is logged and left out."""
    detectors: list[NamedDetector] = []
    for name, factory in factories:
        try:
            detectors.append(NamedDetector(name, factory(cfg)))
        except Exception:
            logger.exception("Detector %r could not start; running without it", name)
    logger.info("Detectors running: %s", ", ".join(d.name for d in detectors) or "none")
    return detectors


def default_firewall() -> dict[str, FirewallFn]:
    """``ActionRequest.kind`` -> firewall function. Looked up at call time so tests can patch."""
    return {
        "quarantine_app": lambda target: firewall.quarantine_app(target),
        "block_ip": lambda target: firewall.block_ip(target),
    }


class CachedProcLookup:
    """``procinfo.info`` with a per-PID cache, so a burst of signals costs one lookup.

    The signature check behind ``procinfo.info`` runs PowerShell, which is slow. Entries live
    ``ttl_s`` seconds. An unknown PID (``< 0``) gives ``None``. If the PID now belongs to a
    process with a different name than the signal's (PID reused), ``None`` is returned too:
    in doubt, no exe path, so scoring alerts but never quarantines (§9.6).
    """

    def __init__(
        self,
        ttl_s: float,
        lookup: Callable[[int], ProcInfo] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl_s = ttl_s
        self._lookup = lookup or (lambda pid: procinfo.info(pid))
        self._clock = clock
        self._cache: dict[int, tuple[float, ProcInfo | None]] = {}

    def __call__(self, pid: int, process: str = "") -> ProcInfo | None:
        if pid < 0:
            return None
        now = self._clock()
        cached = self._cache.get(pid)
        if cached is not None and now - cached[0] < self._ttl_s:
            info = cached[1]
        else:
            try:
                info = self._lookup(pid)
            except Exception:  # procinfo.info should never raise; be safe anyway
                logger.exception("Process lookup for PID %d failed", pid)
                info = None
            self._cache = {p: v for p, v in self._cache.items() if now - v[0] < self._ttl_s}
            self._cache[pid] = (now, info)
        if info is None:
            return None
        if _names_differ(process, info.name):
            logger.debug("PID %d is now %r, not %r; treating it as unknown", pid, info.name,
                         process)
            return None
        return info


def _names_differ(expected: str, actual: str) -> bool:
    known = {UNKNOWN_PROCESS, ""}
    if expected in known or actual in known:
        return False
    return expected.casefold() != actual.casefold()


class Pipeline:
    """Runs every FlowEvent through the detectors, scores the signals, and carries out the
    decisions: firewall action -> store + bus, then the alert -> store + bus."""

    def __init__(
        self,
        detectors: Sequence[NamedDetector],
        scorer: Scorer,
        store: Store,
        publish: Publish,
        *,
        firewall_fns: Mapping[str, FirewallFn] | None = None,
        proc_lookup: Callable[[int, str], ProcInfo | None] | None = None,
        prune_interval_s: float = DEFAULT_PRUNE_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Args:
            detectors: Detectors to run on every FlowEvent, in order.
            scorer: Combines signals and decides (policy, mode, allowlist).
            store: Where Alerts and Actions are saved.
            publish: Puts an Alert / Action on the bus; must be callable from a worker thread
                (normally ``bus.publish_threadsafe``).
            firewall_fns: ``ActionRequest.kind`` -> function returning the new Action.
                Defaults to :func:`default_firewall`.
            proc_lookup: ``(pid, process name) -> ProcInfo | None``. Defaults to a
                :class:`CachedProcLookup` over ``procinfo.info``.
            prune_interval_s: How often the scorer drops expired windows.
            clock: Monotonic seconds, for pruning.
        """
        self.detectors = list(detectors)
        self.scorer = scorer
        self._store = store
        self._publish = publish
        self._firewall = dict(firewall_fns) if firewall_fns is not None else default_firewall()
        self._proc_lookup = proc_lookup or CachedProcLookup(DEFAULT_PROCINFO_CACHE_TTL_S)
        self._prune_interval_s = prune_interval_s
        self._clock = clock
        self._last_prune = clock()

    @classmethod
    def from_config(
        cls,
        cfg: dict[str, Any],
        store: Store,
        publish: Publish,
        detectors: Sequence[NamedDetector] | None = None,
    ) -> Pipeline:
        """Build the real pipeline: detectors, scorer and process lookup from ``config.yaml``."""
        pipeline_cfg = cfg.get("pipeline") or {}
        return cls(
            detectors if detectors is not None else build_detectors(cfg),
            Scorer(cfg),
            store,
            publish,
            proc_lookup=CachedProcLookup(
                float(pipeline_cfg.get("procinfo_cache_ttl_s", DEFAULT_PROCINFO_CACHE_TTL_S))
            ),
            prune_interval_s=float(pipeline_cfg.get("prune_interval_s", DEFAULT_PRUNE_INTERVAL_S)),
        )

    # --- per event --------------------------------------------------------------------------

    def handle(self, event: FlowEvent) -> list[Alert]:
        """Process one FlowEvent. Returns the alerts raised (already saved and published).

        Never raises: every failure is logged so one bad event can't stop the pipeline.
        """
        logger.info(
            "flow %s pid=%s host=%s %s:%s -> %s:%s (%s, out=%dB in=%dB)",
            event.process, event.pid, event.hostname, event.src_ip, event.src_port,
            event.dst_ip, event.dst_port, event.direction, event.bytes_out, event.bytes_in,
        )
        alerts: list[Alert] = []
        for signal in self.detect(event):
            try:
                alert = self._score(signal)
            except Exception:
                logger.exception("Scoring/response failed for a %s signal from %s",
                                 signal.detector, signal.process)
                continue
            if alert is not None:
                alerts.append(alert)
        self._maybe_prune()
        return alerts

    def detect(self, event: FlowEvent) -> list[Signal]:
        """Run every detector on ``event``. A detector that raises is logged and skipped."""
        signals: list[Signal] = []
        for detector in self.detectors:
            try:
                signals.extend(detector.process(event))
            except Exception:
                logger.exception("Detector %r raised on a flow from %s; skipping it for this "
                                 "flow", detector.name, event.process)
        return signals

    def _score(self, signal: Signal) -> Alert | None:
        proc = None if signal.detector == FLOW_MODEL else self._proc_lookup(
            signal.pid, signal.process
        )
        decision = self.scorer.add(signal, proc)
        if decision.alert is None:
            return None
        actions = self._carry_out(decision)
        alert = finalize_alert(decision, actions)
        self._save_and_publish(alert)
        return alert

    def _carry_out(self, decision: Decision) -> list[Action]:
        """Run the requested firewall action. Returns the Actions really taken (maybe none)."""
        request = decision.action
        if request is None:
            return []
        fn = self._firewall.get(request.kind)
        if fn is None:
            logger.error("No firewall function for action %r; alert only", request.kind)
            return []
        try:
            action = fn(request.target)
        except (FirewallError, ValueError) as exc:  # ValueError includes UnsafePathError
            logger.error("%s on %s failed (%s); the alert says nothing was blocked",
                         request.kind, request.target, exc)
            return []
        logger.warning("%s %s for %s (action %s)", request.kind, request.target,
                       request.process, action.id)
        self._save_and_publish(action)
        return [action]

    def _save_and_publish(self, item: Alert | Action) -> None:
        try:
            if isinstance(item, Alert):
                self._store.save_alert(item)
            else:
                self._store.save_action(item)
        except Exception:  # still tell the UI, even if the disk write failed
            logger.exception("Could not save %s %s", item.type, item.id)
        try:
            self._publish(item)
        except Exception:
            logger.exception("Could not publish %s %s", item.type, item.id)

    def _maybe_prune(self) -> None:
        now = self._clock()
        if now - self._last_prune >= self._prune_interval_s:
            self._last_prune = now
            self.scorer.prune()

    # --- async loop -------------------------------------------------------------------------

    async def run(self, sub: Subscription) -> None:
        """Consume FlowEvents from ``sub`` until it is closed. Other event types are ignored
        (the pipeline sees its own Alerts / Actions on the bus)."""
        async for event in sub:
            if isinstance(event, FlowEvent):
                await asyncio.to_thread(self.handle, event)


# --- agent --------------------------------------------------------------------------------


async def run_agent(
    cfg: dict[str, Any],
    stop_event: threading.Event,
    *,
    streamer_factory: capture.StreamerFactory = capture.make_streamer,
    detectors: Sequence[NamedDetector] | None = None,
    store: Store | None = None,
    api_starter: ApiStarter | None = None,
    tracker: api.FlowTracker | None = None,
    ring_starter: RingStarter | None = None,
) -> None:
    """Start capture and the pipeline; return when capture ends (or on cancel / Ctrl+C).

    ``api_starter`` (``main()`` passes :func:`agent.api.start_in_thread`) starts the REST API
    on 127.0.0.1; without it no server is started (tests). Its ``POST /mode`` changes the
    pipeline's scorer mode, ``GET /apps`` reads ``tracker``, fed from its own bus
    subscription, and every ``WS /ws`` client gets its own subscription to ``bus``.

    ``ring_starter`` (``main()`` passes :func:`agent.evidence.start_ring_capture`) starts the
    rolling dumpcap capture (§6.8); it is stopped on shutdown. Without it (tests) none runs.
    A dumpcap that can't start is logged and the agent carries on.
    """
    loop = asyncio.get_running_loop()
    bus = Bus.from_config(cfg, loop=loop)
    own_store = store is None
    db = Store.from_config(cfg) if store is None else store
    pipeline = Pipeline.from_config(cfg, db, bus.publish_threadsafe, detectors=detectors)
    flows = tracker if tracker is not None else api.FlowTracker.from_config(cfg)
    sub = bus.subscribe("pipeline")
    apps_sub = bus.subscribe("apps")
    worker = asyncio.create_task(pipeline.run(sub))
    apps_worker = asyncio.create_task(_track_flows(apps_sub, flows))
    server = None
    ring = None
    if api_starter is not None:
        app = api.create_app(db, pipeline.scorer, flows, allowlist=api.allowlist_from_config(cfg),
                             publish=bus.publish_threadsafe, bus=bus,
                             ws_flow_rate_per_s=api.ws_flow_rate_from_config(cfg),
                             evidence=evidence.EvidenceExporter.from_config(cfg))
        server = api_starter(app, cfg)
    if ring_starter is not None:
        try:
            ring = ring_starter(cfg)
        except Exception:  # evidence capture is optional; never stop the agent for it
            logger.exception("Rolling capture could not start; running without it")
    capture_done: asyncio.Future[int] = loop.create_future()

    def _capture() -> None:
        try:
            result: int | BaseException = capture.run(
                bus, cfg, streamer_factory=streamer_factory, stop_event=stop_event
            )
        except BaseException as exc:  # handed to the loop thread, re-raised there
            result = exc
        with contextlib.suppress(RuntimeError):  # loop already closed on shutdown
            loop.call_soon_threadsafe(_finish, result)

    def _finish(result: int | BaseException) -> None:
        if capture_done.done():
            return
        if isinstance(result, BaseException):
            capture_done.set_exception(result)
        else:
            capture_done.set_result(result)

    # A daemon thread, not asyncio.to_thread: NFStream blocks until the next flow, and a
    # default-executor thread would make Ctrl+C wait for it.
    threading.Thread(target=_capture, name="capture", daemon=True).start()
    logger.info("HomeSOC agent running (mode=%s, interface=%r); Ctrl+C to stop",
                pipeline.scorer.mode, cfg["capture"]["interface"])
    try:
        await capture_done
    except BaseException:
        worker.cancel()  # Ctrl+C / capture error: don't drain the backlog
        apps_worker.cancel()
        raise
    finally:
        stop_event.set()  # the capture thread exits at its next flow
        sub.close()  # on a normal end, events already queued are still handled
        apps_sub.close()
        try:
            with contextlib.suppress(asyncio.CancelledError):
                await worker
            with contextlib.suppress(asyncio.CancelledError):
                await apps_worker
        finally:
            if server is not None:
                server.stop()
            if ring is not None:
                try:
                    ring.stop()
                except Exception:
                    logger.exception("Could not stop the rolling capture")
            if own_store:
                db.close()


async def _track_flows(sub: Subscription, tracker: api.FlowTracker) -> None:
    """Feed every FlowEvent on ``sub`` to the ``GET /apps`` tracker until it is closed."""
    async for event in sub:
        if isinstance(event, FlowEvent):
            tracker.add(event)


def main() -> None:
    """``python -m agent.main`` (or the installed ``HomeSOC-Agent.exe``): run until Ctrl+C.

    Installed (frozen), the data root ``%PROGRAMDATA%\\HomeSOC`` is seeded from the bundle
    first and the log also goes to ``agent.log`` there (the exe has no console).
    """
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    try:
        config.seed_data_root()  # a no-op when running from source
        if config.FROZEN:
            handler = logging.FileHandler(config.REPO_ROOT / LOG_FILE_NAME, encoding="utf-8")
            handler.setFormatter(logging.Formatter(LOG_FORMAT))
            logging.getLogger().addHandler(handler)
        cfg = config.load()
    except OSError as exc:
        logger.error("Could not prepare the data folder %s: %s", config.REPO_ROOT, exc)
        raise SystemExit(1) from exc
    except config.ConfigError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
    stop_event = threading.Event()
    try:
        asyncio.run(run_agent(cfg, stop_event, api_starter=api.start_in_thread,
                              ring_starter=evidence.start_ring_capture))
    except KeyboardInterrupt:
        logger.info("Stopping HomeSOC agent")
    except capture.CaptureError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
