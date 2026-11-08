"""Tests for agent.response.firewall. No real PowerShell: subprocess.run is patched at the module
boundary and the exact command strings are inspected."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent.events import Action
from agent.procinfo import UnsafePathError
from agent.response import firewall
from agent.response.firewall import FirewallError

LAB_IP = "192.168.56.20"
EXE = r"C:\Users\bob\Downloads\FreeGameCheats.exe"
PS_QUOTES = "'\u2018\u2019\u201a\u201b"


@dataclass
class FakeRun:
    """Stands in for subprocess.run; records every call. ``fail_on(cmd)`` picks failures."""

    fail_on: Callable[[str], bool] = lambda cmd: False
    calls: list[list[str]] = field(default_factory=list)
    kwargs: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        self.kwargs.append(kwargs)
        if self.fail_on(args[-1]):
            return subprocess.CompletedProcess(args, 1, "", "Access is denied.")
        return subprocess.CompletedProcess(args, 0, "", "")

    @property
    def cmds(self) -> list[str]:
        return [call[-1] for call in self.calls]


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> FakeRun:
    fake = FakeRun()
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    return fake


def ps_single_quoted_literals(cmd: str) -> list[str]:
    """Minimal PowerShell lexer: return the values of every single-quoted string in ``cmd``.

    Inside a single-quoted string any of the PowerShell single-quote characters ends the string
    unless it is immediately followed by another quote character (a doubled quote = one literal
    quote). Nothing else is special.
    """
    out: list[str] = []
    i = 0
    while i < len(cmd):
        if cmd[i] in PS_QUOTES:
            i += 1
            buf: list[str] = []
            while True:
                assert i < len(cmd), f"unterminated string in {cmd!r}"
                ch = cmd[i]
                if ch in PS_QUOTES:
                    if i + 1 < len(cmd) and cmd[i + 1] in PS_QUOTES:
                        buf.append(ch)
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(ch)
                i += 1
            out.append("".join(buf))
        else:
            i += 1
    return out


def param_value(cmd: str, param: str) -> str:
    """The single-quoted literal value following ``-<param> `` in ``cmd``."""
    start = cmd.index(f"-{param} ") + len(param) + 2
    return ps_single_quoted_literals(cmd[start:])[0]


GET_GROUP = (
    "try { $rules = @(Get-NetFirewallRule -Group 'HomeSOC' -ErrorAction Stop) } "
    "catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { exit 0 }; "
    "[Console]::Error.WriteLine($_); exit 1 }; "
)
REMOVE_MATCHES = (
    "if ($match.Count -gt 0) { try { Remove-NetFirewallRule -InputObject $match "
    "-ErrorAction Stop } catch { [Console]::Error.WriteLine($_); exit 1 } }"
)


def expected_remove_cmd(quoted_name: str) -> str:
    """The exact undo script for one rule; ``quoted_name`` is the PowerShell literal."""
    return (
        GET_GROUP
        + f"$match = @($rules | Where-Object {{ $_.DisplayName -ceq {quoted_name} }}); "
        + REMOVE_MATCHES
    )


def removed_name(cmd: str) -> str:
    """The rule name an undo script removes (the literal compared with ``-ceq``)."""
    return param_value(cmd, "ceq")


def tag(action: Action) -> str:
    return f"#{action.id[:8]}"


def assert_argv_shape(fake: FakeRun) -> None:
    for call, kwargs in zip(fake.calls, fake.kwargs, strict=True):
        assert call[:3] == ["powershell", "-NoProfile", "-Command"]
        assert len(call) == 4
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True


# --- block_ip --------------------------------------------------------------------------------


def test_block_ip_runs_out_and_in_rules_in_group(fake_run: FakeRun) -> None:
    action = firewall.block_ip(LAB_IP)
    t = tag(action)

    assert_argv_shape(fake_run)
    assert re.fullmatch(r"#[0-9a-f]{8}", t)
    assert fake_run.cmds == [
        f"New-NetFirewallRule -DisplayName 'HomeSOC block 192.168.56.20 out {t}' "
        "-Group 'HomeSOC' -Direction Outbound -RemoteAddress '192.168.56.20' -Action Block "
        "-ErrorAction Stop | Out-Null",
        f"New-NetFirewallRule -DisplayName 'HomeSOC block 192.168.56.20 in {t}' "
        "-Group 'HomeSOC' -Direction Inbound -RemoteAddress '192.168.56.20' -Action Block "
        "-ErrorAction Stop | Out-Null",
    ]
    assert action.kind == "block_ip"
    assert action.type == "action"
    assert action.target == LAB_IP
    assert action.rule_names == [
        f"HomeSOC block 192.168.56.20 out {t}",
        f"HomeSOC block 192.168.56.20 in {t}",
    ]
    assert action.undone is False
    assert action.id and action.ts_ms > 0


def test_block_ip_uses_canonical_ip(fake_run: FakeRun) -> None:
    action = firewall.block_ip("2001:DB8:0:0:0:0:0:1")
    assert action.target == "2001:db8::1"
    assert all(param_value(cmd, "RemoteAddress") == "2001:db8::1" for cmd in fake_run.cmds)


@pytest.mark.parametrize(
    "bad",
    [
        "1.2.3.4; Remove-Item C:\\",
        "1.2.3.4' ; Remove-Item C:\\ ; '",
        "$(Remove-Item C:\\)",
        "1.2.3.4\n",
        " 1.2.3.4",
        "",
        "999.1.1.1",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    ],
)
def test_block_ip_rejects_bad_input_without_running(fake_run: FakeRun, bad: str) -> None:
    with pytest.raises(ValueError):
        firewall.block_ip(bad)
    assert fake_run.calls == []


def test_block_ip_rejects_non_string(fake_run: FakeRun) -> None:
    with pytest.raises(ValueError):
        firewall.block_ip(3232250388)  # type: ignore[arg-type]
    assert fake_run.calls == []


# --- quarantine_app --------------------------------------------------------------------------


def test_quarantine_app_creates_program_rules(fake_run: FakeRun) -> None:
    action = firewall.quarantine_app(EXE)
    t = tag(action)

    assert_argv_shape(fake_run)
    assert fake_run.cmds == [
        f"New-NetFirewallRule -DisplayName 'HomeSOC quarantine FreeGameCheats.exe out {t}' "
        "-Group 'HomeSOC' -Direction Outbound "
        "-Program 'C:\\Users\\bob\\Downloads\\FreeGameCheats.exe' -Action Block "
        "-ErrorAction Stop | Out-Null",
        f"New-NetFirewallRule -DisplayName 'HomeSOC quarantine FreeGameCheats.exe in {t}' "
        "-Group 'HomeSOC' -Direction Inbound "
        "-Program 'C:\\Users\\bob\\Downloads\\FreeGameCheats.exe' -Action Block "
        "-ErrorAction Stop | Out-Null",
    ]
    assert action.kind == "quarantine_app"
    assert action.target == EXE
    assert action.rule_names == [
        f"HomeSOC quarantine FreeGameCheats.exe out {t}",
        f"HomeSOC quarantine FreeGameCheats.exe in {t}",
    ]


@pytest.mark.parametrize(
    "bad",
    ["C:\\x\x00.exe", "C:\\x\n.exe", "C:\\x\r.exe", "", "   ", "relative\\x.exe", "x.exe", "C:\\"],
)
def test_quarantine_app_rejects_unsafe_paths_without_running(fake_run: FakeRun, bad: str) -> None:
    with pytest.raises(UnsafePathError):
        firewall.quarantine_app(bad)
    assert fake_run.calls == []


def test_quarantine_app_quotes_special_characters_exactly(fake_run: FakeRun) -> None:
    path = "C:\\Users\\bob\\Down\"loads\\it's $(evil) `n \u2019x.exe"
    action = firewall.quarantine_app(path)

    out_cmd = fake_run.cmds[0]
    expected_path = "'C:\\Users\\bob\\Down\"loads\\it''s $(evil) `n \u2019\u2019x.exe'"
    t = tag(action)
    expected_name = f"'HomeSOC quarantine it''s $(evil) `n \u2019\u2019x.exe out {t}'"
    assert f"-Program {expected_path} -Action Block" in out_cmd
    assert out_cmd.startswith(f"New-NetFirewallRule -DisplayName {expected_name} -Group ")
    assert action.rule_names[0] == f"HomeSOC quarantine it's $(evil) `n \u2019x.exe out {t}"


@pytest.mark.parametrize(
    "path",
    [
        'C:\\a"b\\c.exe',
        "C:\\a'b\\c'.exe",
        "C:\\$env:TEMP\\$(Remove-Item C:\\).exe",
        "C:\\back`tick\\`$x.exe",
        "C:\\smart\u2018\u2019\u201a\u201b\\q.exe",
        "C:\\mix '' \" $ ` ; | & \u2019'\\z.exe",
    ],
)
def test_quarantine_path_round_trips_as_one_literal(fake_run: FakeRun, path: str) -> None:
    action = firewall.quarantine_app(path)
    for cmd, rule_name in zip(fake_run.cmds, action.rule_names, strict=True):
        literals = ps_single_quoted_literals(cmd)
        # Exactly three literals: display name, group, program path. Nothing leaks outside them.
        assert literals == [rule_name, "HomeSOC", path]
        outside = re.sub(r"\s+", " ", _strip_literals(cmd))
        assert outside in (
            "New-NetFirewallRule -DisplayName -Group -Direction Outbound -Program -Action Block "
            "-ErrorAction Stop | Out-Null",
            "New-NetFirewallRule -DisplayName -Group -Direction Inbound -Program -Action Block "
            "-ErrorAction Stop | Out-Null",
        )


def _strip_literals(cmd: str) -> str:
    """``cmd`` with every single-quoted literal removed (same lexing rules as above)."""
    out: list[str] = []
    i = 0
    while i < len(cmd):
        if cmd[i] in PS_QUOTES:
            i += 1
            while True:
                if cmd[i] in PS_QUOTES:
                    if i + 1 < len(cmd) and cmd[i + 1] in PS_QUOTES:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
        else:
            out.append(cmd[i])
            i += 1
    return "".join(out)


# --- undo / undo_all -------------------------------------------------------------------------


def test_undo_removes_exactly_the_stored_rule_names(fake_run: FakeRun) -> None:
    # As if loaded from the store after an agent restart: only the stored names are known.
    stored = Action(
        id="abc", kind="quarantine_app", target=EXE,
        rule_names=["HomeSOC quarantine it's.exe out", "HomeSOC quarantine it's.exe in"],
    )
    result = firewall.undo(stored)

    assert_argv_shape(fake_run)
    assert fake_run.cmds == [
        expected_remove_cmd("'HomeSOC quarantine it''s.exe out'"),
        expected_remove_cmd("'HomeSOC quarantine it''s.exe in'"),
    ]
    for cmd, name in zip(fake_run.cmds, stored.rule_names, strict=True):
        assert removed_name(cmd) == name
    assert stored.undone is True
    assert result.kind == "undo"
    assert result.target == "abc"
    assert result.rule_names == stored.rule_names


def test_undo_after_block_ip_round_trip(fake_run: FakeRun) -> None:
    action = firewall.block_ip(LAB_IP)
    firewall.undo(action)
    removed = [removed_name(cmd) for cmd in fake_run.cmds[2:]]
    assert removed == action.rule_names


@pytest.mark.parametrize(
    "action",
    [
        Action(kind="undo", rule_names=["HomeSOC x"]),
        Action(kind="kill_process", rule_names=[]),
        Action(kind="block_ip", rule_names=["HomeSOC x"], undone=True),
        Action(kind="block_ip", rule_names=["HomeSOC ok", "Core Networking - DNS"]),
        Action(kind="block_ip", rule_names=["HomeSOC bad\nname"]),
    ],
)
def test_undo_refuses_invalid_actions_without_running(fake_run: FakeRun, action: Action) -> None:
    with pytest.raises(ValueError):
        firewall.undo(action)
    assert fake_run.calls == []


def test_undo_all_removes_group_only(fake_run: FakeRun) -> None:
    result = firewall.undo_all()

    assert_argv_shape(fake_run)
    assert fake_run.cmds == [GET_GROUP + "$match = $rules; " + REMOVE_MATCHES]
    assert "-DisplayName" not in fake_run.cmds[0]
    assert result.kind == "undo"
    assert result.target == "HomeSOC"


# --- failure reporting -----------------------------------------------------------------------


def test_block_ip_failure_raises_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeRun(fail_on=lambda cmd: True)
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    with caplog.at_level("ERROR"), pytest.raises(FirewallError) as info:
        firewall.block_ip(LAB_IP)
    assert "exited with 1" in str(info.value)
    assert info.value.rule_names == []
    assert len(fake.calls) == 1  # stopped at the first failure
    assert any("Access is denied." in r.getMessage() for r in caplog.records)


def test_partial_failure_rolls_back_created_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun(fail_on=lambda cmd: cmd.startswith("New-") and "-Direction Inbound" in cmd)
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    with pytest.raises(FirewallError) as info:
        firewall.block_ip(LAB_IP)

    assert len(fake.cmds) == 3
    assert "-Direction Outbound" in fake.cmds[0]
    assert "-Direction Inbound" in fake.cmds[1]
    out_name = param_value(fake.cmds[0], "DisplayName")
    assert re.fullmatch(r"HomeSOC block 192\.168\.56\.20 out #[0-9a-f]{8}", out_name)
    assert fake.cmds[2] == expected_remove_cmd(f"'{out_name}'")
    assert info.value.rule_names == [out_name]
    assert info.value.leftover_rules == []


def test_partial_failure_reports_failed_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun(fail_on=lambda cmd: "-Direction Inbound" in cmd or "-ceq" in cmd)
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    with pytest.raises(FirewallError) as info:
        firewall.quarantine_app(EXE)
    out_name = param_value(fake.cmds[0], "DisplayName")
    assert re.fullmatch(r"HomeSOC quarantine FreeGameCheats\.exe out #[0-9a-f]{8}", out_name)
    assert info.value.leftover_rules == [out_name]


def test_undo_failure_is_reported_and_action_not_marked_undone(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeRun(fail_on=lambda cmd: "-ceq 'HomeSOC block 1.2.3.4 out'" in cmd)
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    action = Action(id="a1", kind="block_ip", rule_names=["HomeSOC block 1.2.3.4 out",
                                                          "HomeSOC block 1.2.3.4 in"])
    with caplog.at_level("ERROR"), pytest.raises(FirewallError) as info:
        firewall.undo(action)
    assert len(fake.calls) == 2  # still tried the second rule
    assert info.value.leftover_rules == ["HomeSOC block 1.2.3.4 out"]
    assert action.undone is False
    assert caplog.records


def test_undo_all_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firewall.subprocess, "run", FakeRun(fail_on=lambda cmd: True))
    with pytest.raises(FirewallError):
        firewall.undo_all()


@pytest.mark.parametrize(
    "exc", [FileNotFoundError("powershell"), subprocess.TimeoutExpired("powershell", 30)]
)
def test_powershell_not_running_is_a_failure(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    def boom(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise exc

    monkeypatch.setattr(firewall.subprocess, "run", boom)
    with pytest.raises(FirewallError):
        firewall.block_ip(LAB_IP)


# --- exact-match removal (no wildcards) --------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "HomeSOC quarantine setup[1].exe out #a1b2c3d4",
        "HomeSOC quarantine a*b.exe in #a1b2c3d4",
        "HomeSOC quarantine what?.exe out #a1b2c3d4",
        "HomeSOC quarantine [*?]`[.exe in #a1b2c3d4",
    ],
)
def test_undo_matches_wildcard_characters_literally(fake_run: FakeRun, name: str) -> None:
    firewall.undo(Action(id="w1", kind="quarantine_app", rule_names=[name]))

    (cmd,) = fake_run.cmds
    # No wildcard-sensitive lookup: -DisplayName / -like / -match never appear.
    assert "-DisplayName" not in cmd
    assert "-like" not in cmd and "-match" not in cmd
    # The rules come from group HomeSOC and are filtered with the literal comparison -ceq.
    assert "Get-NetFirewallRule -Group 'HomeSOC' -ErrorAction Stop" in cmd
    assert "Where-Object { $_.DisplayName -ceq " in cmd
    assert removed_name(cmd) == name
    assert cmd == expected_remove_cmd(firewall.ps_quote(name))


def test_quarantine_bracketed_exe_round_trips_to_exact_undo(fake_run: FakeRun) -> None:
    action = firewall.quarantine_app(r"C:\Users\bob\Downloads\setup[1].exe")
    firewall.undo(action)
    undo_cmds = fake_run.cmds[2:]
    assert [removed_name(cmd) for cmd in undo_cmds] == action.rule_names
    assert all("-DisplayName" not in cmd for cmd in undo_cmds)


# --- unique rule names per action --------------------------------------------------------------


def test_same_named_exes_in_different_dirs_get_disjoint_rule_names(fake_run: FakeRun) -> None:
    a = firewall.quarantine_app(r"C:\Users\bob\Downloads\update.exe")
    b = firewall.quarantine_app(r"C:\Program Files\Vendor\update.exe")
    assert a.id != b.id
    assert set(a.rule_names).isdisjoint(b.rule_names)
    assert all(n.startswith("HomeSOC quarantine update.exe ") for n in a.rule_names + b.rule_names)
    assert all(n.endswith(tag(a)) for n in a.rule_names)
    assert all(n.endswith(tag(b)) for n in b.rule_names)


def test_blocking_same_ip_twice_gives_disjoint_rule_names(fake_run: FakeRun) -> None:
    a = firewall.block_ip(LAB_IP)
    b = firewall.block_ip(LAB_IP)
    assert set(a.rule_names).isdisjoint(b.rule_names)
    assert all(n.startswith("HomeSOC block 192.168.56.20 ") for n in a.rule_names + b.rule_names)


def test_undo_of_one_action_only_references_its_own_names(fake_run: FakeRun) -> None:
    a = firewall.quarantine_app(r"C:\Users\bob\Downloads\update.exe")
    b = firewall.quarantine_app(r"C:\Program Files\Vendor\update.exe")
    fake_run.calls.clear()
    fake_run.kwargs.clear()

    firewall.undo(a)

    assert [removed_name(cmd) for cmd in fake_run.cmds] == a.rule_names
    for cmd in fake_run.cmds:
        for other in b.rule_names:
            assert other not in cmd
    assert a.undone is True and b.undone is False


def test_rule_suffix_comes_from_action_id(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(firewall, "_new_action_id", lambda: "deadbeef" + "0" * 24)
    action = firewall.block_ip(LAB_IP)
    assert action.id == "deadbeef" + "0" * 24
    assert action.rule_names == [
        "HomeSOC block 192.168.56.20 out #deadbeef",
        "HomeSOC block 192.168.56.20 in #deadbeef",
    ]


# --- errors vs. "nothing to remove" ------------------------------------------------------------


def test_remove_scripts_never_silence_errors(fake_run: FakeRun) -> None:
    firewall.undo(Action(id="e1", kind="block_ip", rule_names=["HomeSOC block 1.2.3.4 out #x"]))
    firewall.undo_all()
    for cmd in fake_run.cmds:
        assert "SilentlyContinue" not in cmd
        assert "Get-NetFirewallRule -Group 'HomeSOC' -ErrorAction Stop" in cmd
        # Only an empty group (ObjectNotFound) is swallowed; anything else exits 1.
        assert "if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { exit 0 }" in cmd
        assert cmd.count("exit 1") == 2
        # Remove-NetFirewallRule is never run without explicit, non-empty input.
        assert "if ($match.Count -gt 0) { try { Remove-NetFirewallRule -InputObject $match " in cmd
        assert "| Remove-NetFirewallRule" not in cmd


def test_undo_non_zero_exit_from_remove_script_is_firewall_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeRun(fail_on=lambda cmd: "Remove-NetFirewallRule" in cmd)
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    names = ["HomeSOC quarantine x.exe out #e2", "HomeSOC quarantine x.exe in #e2"]
    action = Action(id="e2", kind="quarantine_app", rule_names=names)
    with caplog.at_level("ERROR"), pytest.raises(FirewallError) as info:
        firewall.undo(action)
    assert info.value.leftover_rules == action.rule_names
    assert action.undone is False
    assert any("Access is denied." in r.getMessage() for r in caplog.records)


def test_undo_all_non_zero_exit_is_firewall_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun(fail_on=lambda cmd: "Get-NetFirewallRule -Group 'HomeSOC'" in cmd)
    monkeypatch.setattr(firewall.subprocess, "run", fake)
    with pytest.raises(FirewallError, match="exited with 1"):
        firewall.undo_all()
