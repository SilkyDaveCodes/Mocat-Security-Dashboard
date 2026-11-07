"""Plain-English alert text (CLAUDE.md §6.4 "Build the text with alerts_text.py").

Turns a process name, its signals and the actions taken into the four text fields of an
``Alert`` (``title``, ``what_happened``, ``what_we_did``, ``what_you_should_do``), written for a
non-technical home user. The MITRE ATT&CK IDs of every signal are listed (deduplicated, in the
order they first appear) at the end of ``what_happened`` and in ``AlertText.mitre``.

Usage::

    text = build_alert_text("freegamecheats.exe", signals, actions, mode="auto")
    alert = Alert(..., **text.as_fields())

Pure Python, no Windows-only code. Never raises on an unknown detector or action kind: it falls
back to generic text and logs a warning.
"""

from __future__ import annotations

import logging
import ntpath
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from agent.events import Action, Signal

logger = logging.getLogger(__name__)

MAX_TARGETS_SHOWN = 3
ALERTS_SCREEN_UNDO = "You can undo this at any time from the Alerts screen."

# flow_model labels, keyed by the MITRE ID the detector attaches (§6.3 flow_model.py).
FLOW_MODEL_ATTACKS: dict[str, str] = {
    "T1046": "scanning your PC for open doors (a port scan)",
    "T1110": "trying to guess a password to log in to your PC (a brute-force attack)",
    "T1498": "flooding your PC with traffic to knock it offline (a denial-of-service attack)",
}


@dataclass(frozen=True)
class AlertText:
    """The four plain-English fields of an Alert, plus the MITRE IDs they mention."""

    title: str
    what_happened: str
    what_we_did: str
    what_you_should_do: str
    mitre: list[str] = field(default_factory=list)

    def as_fields(self) -> dict[str, str]:
        """The four text fields, ready for ``Alert(**text.as_fields())``."""
        return {
            "title": self.title,
            "what_happened": self.what_happened,
            "what_we_did": self.what_we_did,
            "what_you_should_do": self.what_you_should_do,
        }


# --- helpers -------------------------------------------------------------------------------


def _targets(signals: Sequence[Signal]) -> str:
    """Up to MAX_TARGETS_SHOWN distinct targets, e.g. ``"a.com, b.com and 2 more"``."""
    seen = list(dict.fromkeys(s.target for s in signals if s.target))
    if not seen:
        return "a remote computer"
    shown = ", ".join(seen[:MAX_TARGETS_SHOWN])
    extra = len(seen) - MAX_TARGETS_SHOWN
    return f"{shown} and {extra} more" if extra > 0 else shown


def _group_by_detector(signals: Sequence[Signal]) -> dict[str, list[Signal]]:
    """Signals grouped by detector, in the order each detector first appears."""
    groups: dict[str, list[Signal]] = {}
    for sig in signals:
        groups.setdefault(str(sig.detector), []).append(sig)
    return groups


def mitre_ids(signals: Sequence[Signal]) -> list[str]:
    """The signals' MITRE IDs, deduplicated, keeping first-seen order."""
    return list(dict.fromkeys(s.mitre for s in signals if s.mitre))


def _exe_name(target: str, fallback: str) -> str:
    """The file name of an exe path (Windows or POSIX separators), or ``fallback``."""
    name = ntpath.basename(target) if target else ""
    return name or fallback


# --- what happened: one sentence per detector ---------------------------------------------


def _happened_intel(sigs: list[Signal]) -> str:
    return (
        f"It exchanged traffic with {_targets(sigs)}, an address on a public list of "
        "known malicious servers."
    )


def _happened_dga(sigs: list[Signal]) -> str:
    return (
        f"It looked up random-looking web addresses (such as {_targets(sigs)}). Malware "
        "makes up names like these to find its control server."
    )


def _happened_beacon(sigs: list[Signal]) -> str:
    return (
        f"It keeps checking in with {_targets(sigs)} on a regular timer, the way malware "
        "phones home to whoever controls it."
    )


def _happened_anomaly(sigs: list[Signal]) -> str:
    return (
        f"It sent an unusually large amount of data out of your PC (to {_targets(sigs)}). "
        "This can mean your files are being copied off your computer."
    )


def _happened_flow_model(sigs: list[Signal]) -> str:
    attacks = [FLOW_MODEL_ATTACKS[m] for m in mitre_ids(sigs) if m in FLOW_MODEL_ATTACKS]
    what = " and ".join(attacks) if attacks else "attacking your PC over the network"
    return f"Another computer ({_targets(sigs)}) is {what}."


def _happened_generic(sigs: list[Signal]) -> str:
    return (
        f"It did something suspicious on the network involving {_targets(sigs)} "
        f"(flagged by the {sigs[0].detector} check)."
    )


HAPPENED: dict[str, Callable[[list[Signal]], str]] = {
    "intel": _happened_intel,
    "dga": _happened_dga,
    "beacon": _happened_beacon,
    "anomaly": _happened_anomaly,
    "flow_model": _happened_flow_model,
}


def _happened_sentence(detector: str, sigs: list[Signal]) -> str:
    template = HAPPENED.get(detector)
    if template is None:
        logger.warning("No alert template for detector %r; using generic text", detector)
        template = _happened_generic
    return template(sigs)


def _details(signals: Sequence[Signal]) -> str:
    reasons = list(dict.fromkeys(r for s in signals for r in s.reasons if r))
    return f"Details: {'; '.join(reasons)}." if reasons else ""


def _what_happened(process: str, signals: Sequence[Signal]) -> str:
    groups = _group_by_detector(signals)
    if not groups:
        return f"HomeSOC noticed suspicious network activity from {process}."
    parts = [f"HomeSOC noticed {process} behaving like malware."]
    parts += [_happened_sentence(det, sigs) for det, sigs in groups.items()]
    parts.append(_details(signals))
    ids = mitre_ids(signals)
    if ids:
        parts.append(f"(MITRE ATT&CK: {', '.join(ids)})")
    return " ".join(p for p in parts if p)


# --- title --------------------------------------------------------------------------------

TITLES: dict[str, str] = {
    "intel": "{process} contacted a known malicious server",
    "dga": "{process} looked up suspicious random web addresses",
    "beacon": "{process} is secretly checking in with a remote server",
    "anomaly": "{process} sent out an unusual amount of data",
    "flow_model": "Your PC is being attacked from {target}",
}


def _title(process: str, signals: Sequence[Signal]) -> str:
    groups = _group_by_detector(signals)
    if len(groups) > 1:
        return f"{process} is acting like malware"
    if not groups:
        return f"Suspicious activity from {process}"
    detector, sigs = next(iter(groups.items()))
    template = TITLES.get(detector, "Suspicious activity from {process}")
    return template.format(process=process, target=_targets(sigs))


# --- what we did --------------------------------------------------------------------------


def _did_sentence(action: Action, process: str) -> str:
    kind = action.kind
    if kind == "block_ip":
        done = f"We blocked all traffic to and from {action.target} with a Windows Firewall rule"
    elif kind == "quarantine_app":
        app = _exe_name(action.target, process)
        done = f"We quarantined {app}: a firewall rule now stops it from using the network"
    elif kind == "kill_process":
        done = f"We stopped {_exe_name(action.target, process)} from running"
    elif kind == "undo":
        return f"We removed an earlier HomeSOC block ({action.target}), so it is allowed again."
    else:
        logger.warning("No alert template for action kind %r; using generic text", kind)
        done = f"We took a protective action ({kind}) on {action.target or process}"
    return f"{done}, but that was later undone." if action.undone else f"{done}."


def _nothing_blocked(process: str, mode: str, allowlisted: bool) -> str:
    if allowlisted:
        return (
            f"Nothing was blocked, because {process} is on your trusted apps list. "
            "HomeSOC only warns you about trusted apps and never blocks them on its own."
        )
    if mode == "notify":
        return (
            "Nothing was blocked, because HomeSOC is in Notify mode (it warns you but does "
            "not block). Turn on Auto-protect in Settings to block threats like this "
            "automatically."
        )
    if mode == "off":
        return "Nothing was blocked, because HomeSOC protection is turned off."
    return (
        "Nothing was blocked, because we were not sure enough that this is a real threat. "
        "We are leaving the decision to you."
    )


def _is_containment(action: Action) -> bool:
    return action.kind != "undo" and not action.undone


def _what_we_did(
    process: str, actions: Sequence[Action], mode: str, allowlisted: bool
) -> str:
    if not actions:
        return _nothing_blocked(process, mode, allowlisted)
    sentences = [_did_sentence(a, process) for a in actions]
    if any(_is_containment(a) for a in actions):
        sentences.append(ALERTS_SCREEN_UNDO)
    return " ".join(sentences)


# --- what you should do -------------------------------------------------------------------


def _should_do(
    process: str, signals: Sequence[Signal], actions: Sequence[Action], allowlisted: bool
) -> str:
    detectors = set(_group_by_detector(signals))
    active = {a.kind for a in actions if _is_containment(a)}
    steps: list[str] = []
    if "quarantine_app" in active or "kill_process" in active:
        steps.append(
            f"If you don't recognise {process}, uninstall or delete it, then run a full scan "
            "with Microsoft Defender. If you trust it, you can undo the quarantine on the "
            "Alerts screen."
        )
    elif allowlisted:
        steps.append(
            f"{process} is a trusted app, so this may be a false alarm. Make sure it is up to "
            "date, and if you didn't expect this, run a full scan with Microsoft Defender."
        )
    elif detectors - {"flow_model"}:
        steps.append(
            f"If you don't recognise {process}, quarantine it from this alert, then run a "
            "full scan with Microsoft Defender."
        )
    if "anomaly" in detectors:
        steps.append(
            "If you think files were stolen, change the passwords of your important accounts "
            "from another device."
        )
    if "flow_model" in detectors:
        if "block_ip" not in active:
            steps.append("You can block the attacking address from this alert.")
        steps.append(
            "Check that you recognise every device on your home network and that your Wi-Fi "
            "and PC passwords are strong."
        )
    if not steps:
        steps.append("Keep an eye on this app. If you see more alerts like this, quarantine it.")
    return " ".join(steps)


# --- public API ---------------------------------------------------------------------------


def build_alert_text(
    process: str,
    signals: Sequence[Signal],
    actions: Sequence[Action] = (),
    *,
    mode: str = "notify",
    allowlisted: bool = False,
) -> AlertText:
    """Build the plain-English text of an alert.

    Args:
        process: the process name, e.g. ``"freegamecheats.exe"``.
        signals: the alert's signals (any detector; unknown ones get generic text).
        actions: the actions taken for this alert (empty -> "nothing was blocked").
        mode: the response mode at alert time (``off | notify | auto``); explains why
            nothing was blocked.
        allowlisted: the app is on the allowlist, so it was never auto-contained.
    """
    process = process or "unknown"
    return AlertText(
        title=_title(process, signals),
        what_happened=_what_happened(process, signals),
        what_we_did=_what_we_did(process, actions, mode, allowlisted),
        what_you_should_do=_should_do(process, signals, actions, allowlisted),
        mitre=mitre_ids(signals),
    )
