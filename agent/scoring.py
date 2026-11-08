"""Combine detector signals into a risk score and apply the response policy (CLAUDE.md §6.4).

The :class:`Scorer` keeps a sliding window (``scoring.window_s``) of signals per process and, for
every new signal, returns a :class:`Decision`: the current risk, an optional :class:`Alert`, and
an optional :class:`ActionRequest`. Scoring never touches the firewall or the OS: the pipeline
carries out the request and then calls :func:`finalize_alert` to attach the real actions.

Risk:
    ``risk = 1 - prod(1 - score)`` over **distinct detectors** (each detector counts once, with its
    highest score in the window), then ``x context_boost`` when the exe is known to be unsigned or
    in a risky directory, capped at 1.0. ``None`` from :class:`agent.procinfo.ProcInfo` means
    "unknown", so it never triggers the boost (§6.2).

Policy (``mode``: ``off | notify | auto``):
    * ``risk >= alert_threshold`` -> Alert (medium / high / critical by ``scoring.severity``).
      Alerts are raised in every mode; only ``auto`` acts.
    * ``auto`` and (intel hit, or ``risk >= auto_quarantine.risk`` from
      ``>= auto_quarantine.min_detectors`` detectors) -> request ``quarantine_app`` on the exe path.
      Allowlisted apps and apps whose exe path is unknown are never quarantined: alert only (§9.6).
      Nor is HomeSOC's own executable (:func:`own_executables`: ``sys.executable`` and, from
      source, the base interpreter): blocking it would cut off HomeSOC itself (#69).
    * Inbound ``flow_model`` signals are about a remote attacker, not a local app, so they are
      windowed per attacker IP (``signal.target``). In ``auto`` with
      ``risk >= auto_block_ip.risk`` -> request ``block_ip`` on that IP. The exe allowlist does not
      apply (no app is touched), but an empty or loopback target is never blocked.

Repeat suppression: within one window "episode" (until every signal of a key has expired) an
alert is raised again only when the severity rises, a new detector joins, or a new action is
requested. The same action (kind, target) is requested at most once per episode.

Timing: the window uses the injected clock (ms) at the moment a signal is added, not
``Signal.ts_ms``, because a flow's start time can lag by up to the NFStream active timeout.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import ntpath
import os
import sys
import time
import uuid
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from agent import alerts_text
from agent import config as config_module
from agent.config import Allowlist
from agent.events import Action, Alert, Signal
from agent.procinfo import ProcInfo

logger = logging.getLogger(__name__)

MS_PER_S = 1000
RISK_EPSILON = 1e-9  # float slack so e.g. 0.8999999999 still counts as >= 0.9
MAX_RISK = 1.0
MODES: tuple[str, ...] = ("off", "notify", "auto")
SEVERITY_ORDER: tuple[str, ...] = ("medium", "high", "critical")  # lowest first
INTEL = "intel"
FLOW_MODEL = "flow_model"
INBOUND_KEY_PREFIX = "inbound:"

ActionKind = Literal["block_ip", "quarantine_app"]


@dataclass(frozen=True)
class ActionRequest:
    """An action the pipeline should carry out (via ``agent.response.firewall``)."""

    kind: ActionKind
    target: str  # exe path (quarantine_app) or IP (block_ip)
    process: str


@dataclass
class Decision:
    """What scoring decided after one signal. ``alert``/``action`` are ``None`` when not needed."""

    process: str
    risk: float
    detectors: list[str]
    mode: str
    allowlisted: bool = False
    alert: Alert | None = None
    action: ActionRequest | None = None
    own_exe: bool = False  # the exe is HomeSOC's own (never quarantined, #69)


@dataclass
class _Window:
    """Signals of one key (a process, or an inbound attacker IP) plus repeat-suppression state."""

    entries: list[tuple[int, Signal]] = field(default_factory=list)  # (added_at_ms, signal)
    proc: ProcInfo | None = None
    alerted_severity: str | None = None
    alerted_detectors: frozenset[str] = frozenset()
    requested: set[tuple[str, str]] = field(default_factory=set)


# --- pure helpers ---------------------------------------------------------------------------


def best_per_detector(signals: Sequence[Signal]) -> dict[str, float]:
    """The highest score of each detector (a detector counts once)."""
    best: dict[str, float] = {}
    for sig in signals:
        det = str(sig.detector)
        best[det] = max(best.get(det, 0.0), _clamp(sig.score))
    return best


def combine_risk(signals: Sequence[Signal], boost: float = 1.0) -> float:
    """``1 - prod(1 - score)`` over distinct detectors, times ``boost``, capped at 1.0."""
    scores = best_per_detector(signals).values()
    risk = 1.0 - math.prod(1.0 - s for s in scores)
    return min(MAX_RISK, risk * boost)


def has_risky_context(proc: ProcInfo | None) -> bool:
    """True only when the exe is *known* to be unsigned or in a risky directory."""
    if proc is None:
        return False
    return proc.signed is False or proc.in_risky_dir is True


def _clamp(score: float) -> float:
    return min(MAX_RISK, max(0.0, float(score)))


def _at_least(value: float, threshold: float) -> bool:
    return value + RISK_EPSILON >= threshold


def _is_blockable_ip(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def _now_ms() -> int:
    return int(time.time() * MS_PER_S)


# --- HomeSOC's own executable (#69) ---------------------------------------------------------


def normalize_exe_path(path: str) -> str:
    """A Windows exe path in comparable form: normalised separators / ``..``, case-folded.

    Uses ``ntpath`` (not ``os.path``) so the comparison is Windows-style on every OS: the paths
    come from Windows processes even when the tests run elsewhere.
    """
    return ntpath.normcase(ntpath.normpath(path)).casefold()


def own_executables(sys_module: Any = sys) -> frozenset[str]:
    """Normalised paths of the executable(s) HomeSOC itself runs on, never to be quarantined.

    Always ``sys.executable`` (``HomeSOC-Agent.exe`` when frozen). From source (not frozen) also
    ``sys._base_executable``: a venv's ``python.exe`` is a launcher that hands off to the base
    interpreter, so the agent's traffic really comes from that one. Each path is added both as
    given (made absolute) and with links resolved. ``sys_module`` is injectable for tests.
    """
    candidates = [getattr(sys_module, "executable", None)]
    if not getattr(sys_module, "frozen", False):
        candidates.append(getattr(sys_module, "_base_executable", None))
    found: set[str] = set()
    for path in candidates:
        if not path:
            continue
        path = str(path)
        found.add(normalize_exe_path(os.path.abspath(path)))
        try:
            found.add(normalize_exe_path(os.path.realpath(path)))
        except (OSError, ValueError):
            pass
    return frozenset(found)


def is_own_executable(exe_path: str | None, own: Collection[str] | None = None) -> bool:
    """True when ``exe_path`` is one of HomeSOC's own executables (case-insensitive).

    ``own`` is a set from :func:`own_executables` (computed now when omitted); its entries are
    normalised again, so a test may pass raw paths.
    """
    if not exe_path:
        return False
    own_set = own_executables() if own is None else {normalize_exe_path(p) for p in own}
    return normalize_exe_path(exe_path) in own_set


# --- scorer ---------------------------------------------------------------------------------


class Scorer:
    """Per-process signal windows, risk scoring and the response policy (§6.4)."""

    def __init__(
        self,
        cfg: dict[str, Any] | None = None,
        allowlist: Allowlist | None = None,
        *,
        clock: Callable[[], int] = _now_ms,
        mode: str | None = None,
        id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
        self_exes: Collection[str] | None = None,
    ) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
            allowlist: Exe names never auto-contained. Loaded from ``paths.allowlist`` (or the
                default ``data/allowlist.txt``) when omitted.
            clock: Returns the current time in ms. Inject a fake one in tests.
            mode: ``off | notify | auto``. Defaults to ``cfg["mode"]``.
            id_factory: Makes alert IDs.
            self_exes: Exe paths of HomeSOC itself, never quarantined. Defaults to
                :func:`own_executables`.
        """
        cfg = cfg if cfg is not None else config_module.load()
        sc = cfg["scoring"]
        self._window_ms = int(float(sc["window_s"]) * MS_PER_S)
        self._boost = float(sc["context_boost"])
        self._alert_threshold = float(sc["alert_threshold"])
        severity = sc["severity"]
        self._severity = [(name, float(severity[name])) for name in reversed(SEVERITY_ORDER)]
        self._quarantine_risk = float(sc["auto_quarantine"]["risk"])
        self._quarantine_min_detectors = int(sc["auto_quarantine"]["min_detectors"])
        self._block_ip_risk = float(sc["auto_block_ip"]["risk"])
        if allowlist is None:
            path = cfg.get("paths", {}).get("allowlist")
            allowlist = config_module.load_allowlist(
                config_module.REPO_ROOT / path if path else None
            )
        self._allowlist = allowlist
        self._clock = clock
        self._id_factory = id_factory
        self._windows: dict[str, _Window] = {}
        self._self_exes = frozenset(
            normalize_exe_path(p) for p in (own_executables() if self_exes is None else self_exes)
        )
        self.mode = mode if mode is not None else str(cfg["mode"])

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str) -> None:
        if value not in MODES:
            raise ValueError(f"Invalid mode {value!r}; allowed: {', '.join(MODES)}")
        self._mode = value

    def severity_for(self, risk: float) -> str | None:
        """``medium`` / ``high`` / ``critical`` for a risk; ``None`` below the alert threshold."""
        if not _at_least(risk, self._alert_threshold):
            return None
        for name, lower in self._severity:  # highest first
            if _at_least(risk, lower):
                return name
        return SEVERITY_ORDER[0]

    def add(self, signal: Signal, proc: ProcInfo | None = None) -> Decision:
        """Add one signal (with optional process context) and decide what to do."""
        now = self._clock()
        inbound = signal.detector == FLOW_MODEL
        key = f"{INBOUND_KEY_PREFIX}{signal.target}" if inbound else signal.process
        window = self._windows.setdefault(key, _Window())
        self._expire(window, now)
        window.entries.append((now, signal))
        if proc is not None and not inbound:
            window.proc = proc
        return self._decide(window, signal, inbound)

    def prune(self) -> None:
        """Drop expired signals and empty windows (call now and then to bound memory)."""
        now = self._clock()
        for key in list(self._windows):
            window = self._windows[key]
            self._expire(window, now)
            if not window.entries:
                del self._windows[key]

    def risk_of(self, process: str) -> float:
        """Current risk of a process (0.0 if it has no live signals)."""
        window = self._windows.get(process)
        if window is None:
            return 0.0
        self._expire(window, self._clock())
        return self._risk(window, inbound=False)

    # --- internals --------------------------------------------------------------------------

    def _expire(self, window: _Window, now: int) -> None:
        cutoff = now - self._window_ms
        window.entries = [(t, s) for t, s in window.entries if t > cutoff]
        if not window.entries:  # episode over: forget what we alerted / requested
            window.alerted_severity = None
            window.alerted_detectors = frozenset()
            window.requested.clear()

    def _risk(self, window: _Window, inbound: bool) -> float:
        signals = [s for _, s in window.entries]
        boost = self._boost if not inbound and has_risky_context(window.proc) else 1.0
        return combine_risk(signals, boost)

    def _decide(self, window: _Window, latest: Signal, inbound: bool) -> Decision:
        signals = [s for _, s in window.entries]
        detectors = list(best_per_detector(signals))
        risk = self._risk(window, inbound)
        proc = None if inbound else window.proc
        process = latest.process or "unknown"
        allowlisted = not inbound and process in self._allowlist
        own_exe = (
            not inbound
            and proc is not None
            and is_own_executable(proc.exe_path, self._self_exes)
        )
        decision = Decision(
            process=process, risk=risk, detectors=detectors, mode=self.mode,
            allowlisted=allowlisted, own_exe=own_exe,
        )
        severity = self.severity_for(risk)
        if severity is None:
            return decision

        request = self._action_request(
            window, latest, inbound, risk, detectors, allowlisted or own_exe
        )
        if request is not None and (request.kind, request.target) in window.requested:
            request = None  # already requested in this episode
        if not self._should_alert(window, severity, detectors, request):
            return decision

        if request is not None:
            window.requested.add((request.kind, request.target))
        window.alerted_severity = severity
        window.alerted_detectors = window.alerted_detectors | frozenset(detectors)
        decision.action = request
        decision.alert = self._build_alert(process, proc, risk, severity, signals, request,
                                           allowlisted, own_exe)
        logger.info(
            "Alert %s: %s risk=%.2f detectors=%s action=%s",
            severity, process, risk, ",".join(detectors), request.kind if request else None,
        )
        return decision

    def _action_request(
        self,
        window: _Window,
        latest: Signal,
        inbound: bool,
        risk: float,
        detectors: list[str],
        protected: bool,
    ) -> ActionRequest | None:
        """The action to request; ``protected`` = allowlisted or HomeSOC's own exe."""
        if self.mode != "auto":
            return None
        if inbound:
            if _at_least(risk, self._block_ip_risk) and _is_blockable_ip(latest.target):
                return ActionRequest("block_ip", latest.target, latest.process)
            return None
        intel_hit = INTEL in detectors
        strong = _at_least(risk, self._quarantine_risk) and (
            len(detectors) >= self._quarantine_min_detectors
        )
        if not (intel_hit or strong):
            return None
        exe_path = window.proc.exe_path if window.proc is not None else None
        if protected or not exe_path:
            # §9.6: in doubt (trusted app, HomeSOC's own exe, or no exe path) -> alert only.
            return None
        return ActionRequest("quarantine_app", exe_path, latest.process)

    def _should_alert(
        self,
        window: _Window,
        severity: str,
        detectors: list[str],
        request: ActionRequest | None,
    ) -> bool:
        if window.alerted_severity is None or request is not None:
            return True
        if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(window.alerted_severity):
            return True
        return not set(detectors) <= window.alerted_detectors

    def _build_alert(
        self,
        process: str,
        proc: ProcInfo | None,
        risk: float,
        severity: str,
        signals: list[Signal],
        request: ActionRequest | None,
        allowlisted: bool,
        own_exe: bool,
    ) -> Alert:
        alert = Alert(
            id=self._id_factory(),
            ts_ms=self._clock(),
            severity=severity,  # type: ignore[arg-type]
            process=process,
            exe_path=proc.exe_path if proc is not None else None,
            risk=risk,
            signals=list(signals),
        )
        # Text assumes the requested action succeeds; finalize_alert() rewrites it with the
        # real outcome once the pipeline has carried it out.
        pending = [Action(kind=request.kind, target=request.target)] if request else []
        return _with_text(alert, pending, self.mode, allowlisted, own_exe)


def _with_text(
    alert: Alert, actions: Sequence[Action], mode: str, allowlisted: bool, own_exe: bool = False
) -> Alert:
    text = alerts_text.build_alert_text(
        alert.process, alert.signals, actions, mode=mode, allowlisted=allowlisted,
        own_exe=own_exe,
    )
    return replace(alert, **text.as_fields())


def finalize_alert(decision: Decision, actions: Sequence[Action]) -> Alert:
    """The decision's alert with the actions the pipeline really took (IDs + rewritten text).

    Pass an empty list if the requested action failed, so the text says nothing was blocked.
    """
    if decision.alert is None:
        raise ValueError("decision has no alert to finalize")
    alert = _with_text(decision.alert, actions, decision.mode, decision.allowlisted,
                       decision.own_exe)
    return replace(alert, action_ids=[a.id for a in actions if a.id])
