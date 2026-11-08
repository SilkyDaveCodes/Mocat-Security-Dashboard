"""Containment through Windows Firewall rules: block_ip, quarantine_app, undo, undo_all.

CLAUDE.md §6.5 / §9.3. Windows-only code (PowerShell) is allowed here (§10). Every PowerShell
call goes through ``subprocess.run`` at module level, so tests patch that one name and run on
any OS.

Safety
    * Every rule is named ``HomeSOC ...`` and created in group ``HomeSOC``. Undo only ever
      touches rules that are both named as stored *and* in group ``HomeSOC``.
    * Rule names are unique per action: each ends with `` #<first 8 hex chars of the action
      id>`` (e.g. ``HomeSOC block 1.2.3.4 out #a1b2c3d4``). Two same-named exes in different
      folders, or the same IP blocked twice, get disjoint names, so undoing one action never
      removes another action's rules.
    * IPs are parsed with :mod:`ipaddress` and only the canonical string reaches PowerShell.
      Loopback and unspecified addresses are refused.
    * Exe paths and every rule display name (which embeds the exe file name) are passed as
      PowerShell single-quoted literals via :func:`agent.procinfo.ps_quote` (``'`` and the
      Unicode single quotes are doubled; ``$``, backticks, ``;`` and ``"`` stay literal).
      Paths with NUL / CR / LF, or that are not absolute Windows paths, are refused.
    * Bad input raises before anything is run.

Failure reporting (design choice)
    Each rule is one PowerShell call with ``-ErrorAction Stop`` so a failing cmdlet gives a
    non-zero exit. A non-zero exit, a timeout or a missing ``powershell`` is logged and raised
    as :class:`FirewallError`; it is never treated as success.

    * ``block_ip`` / ``quarantine_app``: if a later rule fails, the rules already created by
      that call are rolled back (removed by name, group ``HomeSOC`` only) and
      :class:`FirewallError` is raised. ``FirewallError.rule_names`` lists the rules that were
      created; ``FirewallError.leftover_rules`` lists any whose rollback also failed (these stay
      in group ``HomeSOC``, so ``undo_all`` still removes them).
    * ``undo``: tries every stored rule name, then raises :class:`FirewallError` listing the
      ones that could not be removed. The original Action is only marked ``undone`` when all
      removals succeeded. A rule that is already gone (e.g. after ``undo_all``) counts as
      removed, so undo is idempotent.

Exact-match removal
    ``Get-NetFirewallRule -DisplayName`` treats its argument as a wildcard pattern (``[``,
    ``]``, ``*``, ``?``), so a stored name like ``HomeSOC quarantine setup[1].exe out ...``
    would silently match nothing. Removal therefore lists group ``HomeSOC`` and filters with
    ``Where-Object { $_.DisplayName -ceq '<name>' }``. ``-ceq`` is a plain, case-sensitive
    string comparison (no wildcards); case-sensitive because the stored name is byte-for-byte
    the one we created, so the strictest match is the right one.

Errors vs. "nothing to remove"
    ``Get-NetFirewallRule -Group 'HomeSOC' -ErrorAction Stop`` raises an ``ObjectNotFound``
    error when the group has no rules at all. The script catches that one category and exits 0
    (idempotent undo / undo_all). Any other error (e.g. access denied) is written to stderr and
    exits 1, which this module reports as :class:`FirewallError`. Nothing uses
    ``-ErrorAction SilentlyContinue``. ``Remove-NetFirewallRule`` is only called with an
    explicit, non-empty ``-InputObject`` (never with empty input, which would match every rule).

Undo design
    ``undo(action)`` sets ``action.undone = True`` and returns a new ``Action(kind="undo")``
    whose ``target`` is the original action id and whose ``rule_names`` are the removed rules.
    Undo needs only the stored ``rule_names``, so it works after an agent restart.

Store seam
    This module does not persist anything. Callers (scoring / API) save the returned Action in
    ``agent/store.py`` (§6.5).
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import time
import uuid
from collections.abc import Sequence
from pathlib import PureWindowsPath

from agent.events import Action
from agent.procinfo import UnsafePathError, ps_quote

logger = logging.getLogger(__name__)

POWERSHELL_ARGV: tuple[str, ...] = ("powershell", "-NoProfile", "-Command")
POWERSHELL_TIMEOUT_S = 30.0  # a hung PowerShell must not stall the response path forever

RULE_GROUP = "HomeSOC"
RULE_PREFIX = "HomeSOC "
DIRECTIONS: tuple[tuple[str, str], ...] = (("out", "Outbound"), ("in", "Inbound"))
UNDOABLE_KINDS: frozenset[str] = frozenset({"block_ip", "quarantine_app"})

NEW_RULE_TEMPLATE = (
    "New-NetFirewallRule -DisplayName {name} -Group {group} -Direction {direction} "
    "{match} -Action Block -ErrorAction Stop | Out-Null"
)
# Both scripts list group HomeSOC first. An empty group (ObjectNotFound) means "nothing to
# remove" -> exit 0; any other error -> stderr + exit 1. See the module docstring.
_GET_GROUP_SCRIPT = (
    "try {{ $rules = @(Get-NetFirewallRule -Group {group} -ErrorAction Stop) }} "
    "catch {{ if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {{ exit 0 }}; "
    "[Console]::Error.WriteLine($_); exit 1 }}; "
)
# Remove-NetFirewallRule only ever gets an explicit, non-empty -InputObject: it is never run
# with no input (a bare Remove-NetFirewallRule would delete every rule on the machine).
_REMOVE_MATCHES_SCRIPT = (
    "if ($match.Count -gt 0) {{ try {{ Remove-NetFirewallRule -InputObject $match "
    "-ErrorAction Stop }} catch {{ [Console]::Error.WriteLine($_); exit 1 }} }}"
)
# Remove one rule by exact display name (-ceq: no wildcards), only from group HomeSOC.
REMOVE_RULE_TEMPLATE = (
    _GET_GROUP_SCRIPT
    + "$match = @($rules | Where-Object {{ $_.DisplayName -ceq {name} }}); "
    + _REMOVE_MATCHES_SCRIPT
)
# Remove every rule in group HomeSOC.
REMOVE_GROUP_TEMPLATE = _GET_GROUP_SCRIPT + "$match = $rules; " + _REMOVE_MATCHES_SCRIPT
SUFFIX_LEN = 8  # hex chars of the action id appended to every rule name


class FirewallError(RuntimeError):
    """A firewall change failed (non-zero exit, timeout, PowerShell missing).

    Attributes:
        rule_names: Rules this operation created (block/quarantine) or tried to remove (undo).
        leftover_rules: Rules that may still exist after the failure (failed rollback for
            block/quarantine; failed removals for undo).
    """

    def __init__(
        self,
        message: str,
        rule_names: Sequence[str] = (),
        leftover_rules: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.rule_names = list(rule_names)
        self.leftover_rules = list(leftover_rules)


# --- input validation ------------------------------------------------------------------------


def normalize_ip(ip: str) -> str:
    """Return the canonical form of ``ip``. Raises ``ValueError`` for anything else."""
    if not isinstance(ip, str):
        raise ValueError(f"IP must be a string, got {type(ip).__name__}")
    addr = ipaddress.ip_address(ip)  # ValueError on anything else, including surrounding spaces
    if addr.is_loopback or addr.is_unspecified:
        raise ValueError(f"Refusing to block loopback/unspecified address {addr}")
    return str(addr)


def validate_exe_path(exe_path: str) -> str:
    """Check that ``exe_path`` is an absolute Windows path safe to quote. Returns it unchanged.

    Raises:
        UnsafePathError: Control characters (NUL, CR, LF), empty, or not absolute.
    """
    if not isinstance(exe_path, str) or not exe_path.strip():
        raise UnsafePathError(f"Exe path must be a non-empty string: {exe_path!r}")
    ps_quote(exe_path)  # raises UnsafePathError on NUL / CR / LF
    path = PureWindowsPath(exe_path)
    if not path.is_absolute() or not path.name:
        raise UnsafePathError(f"Exe path must be an absolute Windows file path: {exe_path!r}")
    return exe_path


# --- command builders ------------------------------------------------------------------------


def rule_suffix(action_id: str) -> str:
    """The per-action tag appended to every rule name, e.g. ``#a1b2c3d4``."""
    return f"#{action_id[:SUFFIX_LEN]}"


def block_rule_names(ip: str, action_id: str) -> list[str]:
    """Display names for ``block_ip`` (out first, then in). ``ip`` must be canonical."""
    tag = rule_suffix(action_id)
    return [f"{RULE_PREFIX}block {ip} {short} {tag}" for short, _ in DIRECTIONS]


def quarantine_rule_names(exe_path: str, action_id: str) -> list[str]:
    """Display names for ``quarantine_app`` (out first, then in), using the exe file name."""
    exe_name = PureWindowsPath(exe_path).name
    tag = rule_suffix(action_id)
    return [f"{RULE_PREFIX}quarantine {exe_name} {short} {tag}" for short, _ in DIRECTIONS]


def build_new_rule_command(name: str, direction: str, match: str) -> str:
    """``match`` is a pre-quoted ``-RemoteAddress '...'`` or ``-Program '...'`` clause."""
    return NEW_RULE_TEMPLATE.format(
        name=ps_quote(name), group=ps_quote(RULE_GROUP), direction=direction, match=match
    )


def build_remove_rule_command(name: str) -> str:
    return REMOVE_RULE_TEMPLATE.format(name=ps_quote(name), group=ps_quote(RULE_GROUP))


def build_remove_group_command() -> str:
    return REMOVE_GROUP_TEMPLATE.format(group=ps_quote(RULE_GROUP))


# --- PowerShell runner -----------------------------------------------------------------------


def _run_powershell(cmd: str) -> None:
    """Run one PowerShell command. Raises :class:`FirewallError` unless it exits 0."""
    try:
        result = subprocess.run(
            [*POWERSHELL_ARGV, cmd],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=POWERSHELL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("PowerShell could not run %r: %s", cmd, exc)
        raise FirewallError(f"PowerShell could not run: {exc}") from exc
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        logger.error("PowerShell exited with %d for %r: %s", result.returncode, cmd, stderr)
        raise FirewallError(f"PowerShell exited with {result.returncode}: {stderr}")


def _new_action_id() -> str:
    return uuid.uuid4().hex


def _new_action(kind: str, target: str, rule_names: list[str], action_id: str = "") -> Action:
    return Action(
        id=action_id or _new_action_id(),
        ts_ms=int(time.time() * 1000),
        kind=kind,  # type: ignore[arg-type]
        target=target,
        rule_names=rule_names,
    )


def _create_rules(rules: list[tuple[str, str]], match: str) -> list[str]:
    """Create ``(name, direction)`` rules in order; roll back on the first failure."""
    created: list[str] = []
    for name, direction in rules:
        try:
            _run_powershell(build_new_rule_command(name, direction, match))
        except FirewallError as exc:
            leftover = _rollback(created)
            raise FirewallError(
                f"Creating rule {name!r} failed: {exc}", rule_names=created, leftover_rules=leftover
            ) from exc
        created.append(name)
    return created


def _rollback(created: list[str]) -> list[str]:
    """Remove rules created by a failed call. Returns the names that could not be removed."""
    leftover: list[str] = []
    for name in created:
        try:
            _run_powershell(build_remove_rule_command(name))
            logger.warning("Rolled back firewall rule %r", name)
        except FirewallError:
            logger.error("Rollback of firewall rule %r failed; it stays in group HomeSOC", name)
            leftover.append(name)
    return leftover


# --- public API ------------------------------------------------------------------------------


def block_ip(ip: str) -> Action:
    """Block all traffic to and from ``ip`` (two rules: out and in).

    Raises:
        ValueError: ``ip`` is not a valid IP, or is loopback/unspecified (nothing is run).
        FirewallError: A rule could not be created (see module docstring for rollback).
    """
    canonical = normalize_ip(ip)
    action_id = _new_action_id()
    names = block_rule_names(canonical, action_id)
    rules = [(name, direction) for name, (_, direction) in zip(names, DIRECTIONS, strict=True)]
    created = _create_rules(rules, f"-RemoteAddress {ps_quote(canonical)}")
    logger.info("Blocked IP %s (rules %s)", canonical, created)
    return _new_action("block_ip", canonical, created, action_id)


def quarantine_app(exe_path: str) -> Action:
    """Block all network traffic of the program at ``exe_path`` (two rules: out and in).

    Raises:
        UnsafePathError: The path has control characters or is not absolute (nothing is run).
        FirewallError: A rule could not be created (see module docstring for rollback).
    """
    validate_exe_path(exe_path)
    action_id = _new_action_id()
    names = quarantine_rule_names(exe_path, action_id)
    rules = [(name, direction) for name, (_, direction) in zip(names, DIRECTIONS, strict=True)]
    created = _create_rules(rules, f"-Program {ps_quote(exe_path)}")
    logger.info("Quarantined %s (rules %s)", exe_path, created)
    return _new_action("quarantine_app", exe_path, created, action_id)


def undo(action: Action) -> Action:
    """Remove exactly the rules stored in ``action.rule_names`` (group ``HomeSOC`` only).

    On success sets ``action.undone = True`` and returns ``Action(kind="undo",
    target=action.id, rule_names=<removed>)``.

    Raises:
        ValueError: ``action`` is not an undoable kind, is already undone, or holds a rule name
            that does not start with ``HomeSOC `` (nothing is run).
        FirewallError: One or more rules could not be removed; ``leftover_rules`` lists them and
            ``action.undone`` stays ``False``.
    """
    if action.kind not in UNDOABLE_KINDS:
        raise ValueError(f"Cannot undo an action of kind {action.kind!r}")
    if action.undone:
        raise ValueError(f"Action {action.id} is already undone")
    names = list(action.rule_names)
    for name in names:
        if not isinstance(name, str) or not name.startswith(RULE_PREFIX):
            raise ValueError(f"Refusing to remove a rule not named {RULE_PREFIX!r}: {name!r}")
        ps_quote(name)  # raises UnsafePathError (a ValueError) on control characters
    failed: list[str] = []
    for name in names:
        try:
            _run_powershell(build_remove_rule_command(name))
        except FirewallError:
            failed.append(name)
    if failed:
        raise FirewallError(
            f"Undo of action {action.id} could not remove {failed}",
            rule_names=names,
            leftover_rules=failed,
        )
    action.undone = True
    logger.info("Undid action %s (removed %s)", action.id, names)
    return _new_action("undo", action.id, names)


def undo_all() -> Action:
    """Remove every rule in group ``HomeSOC`` (and nothing else).

    Returns ``Action(kind="undo", target="HomeSOC", rule_names=[])``: the individual names are
    not known here. Callers should mark their stored actions as undone.

    Raises:
        FirewallError: The removal failed.
    """
    _run_powershell(build_remove_group_command())
    logger.info("Removed all firewall rules in group %s", RULE_GROUP)
    return _new_action("undo", RULE_GROUP, [])
