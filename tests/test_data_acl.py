"""Tests for agent/data_acl.py and its wiring in agent/main.py (ticket #72).

The icacls runner is injected, so everything but the last section runs on any OS. The last
section applies the real ACL to a temp folder with the real ``icacls.exe`` (Windows only) and
checks it from a normal (non-admin) process, like the ticket's manual check.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import Any

import pytest

from agent import config, data_acl
from agent.data_acl import (
    SID_ADMINISTRATORS,
    SID_AUTHENTICATED_USERS,
    SID_CREATOR_OWNER,
    SID_EVERYONE,
    SID_SYSTEM,
    SID_USERS,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ICACLS = r"C:\Windows\System32\icacls.exe"


class FakeRun:
    """subprocess.run stand-in: records every call; ``codes`` gives each call's exit code."""

    def __init__(self, codes: list[int] | None = None, raises: list[BaseException | None] | None
                 = None) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.codes = codes or []
        self.raises = raises or []

    def __call__(self, args: list[str], **kwargs: Any) -> SimpleNamespace:
        i = len(self.calls)
        self.calls.append((list(args), kwargs))
        if i < len(self.raises) and self.raises[i] is not None:
            raise self.raises[i]
        code = self.codes[i] if i < len(self.codes) else 0
        return SimpleNamespace(returncode=code, stdout="out text" if code else "",
                               stderr="Access is denied." if code else "")

    @property
    def args(self) -> list[list[str]]:
        return [a for a, _ in self.calls]


# --- the icacls argument lists ---------------------------------------------------------------


def test_acl_commands_are_the_exact_icacls_argument_lists() -> None:
    root = PureWindowsPath(r"C:\ProgramData\HomeSOC")
    evidence = root / "data" / "evidence"
    assert data_acl.acl_commands(root, evidence, ICACLS) == [
        [ICACLS, r"C:\ProgramData\HomeSOC", "/inheritance:r", "/grant:r",
         "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"],
        [ICACLS, r"C:\ProgramData\HomeSOC", "/setowner", "*S-1-5-32-544", "/T", "/Q"],
        [ICACLS, r"C:\ProgramData\HomeSOC", "/remove:g",
         "*S-1-5-32-545", "*S-1-5-11", "*S-1-1-0", "*S-1-3-0", "/T", "/Q"],
        [ICACLS, r"C:\ProgramData\HomeSOC\data\evidence", "/grant:r",
         "*S-1-5-32-545:(OI)(CI)RX", "/Q"],
    ]


def test_well_known_sids_are_the_language_independent_ones() -> None:
    assert (SID_SYSTEM, SID_ADMINISTRATORS, SID_USERS) == (
        "*S-1-5-18", "*S-1-5-32-544", "*S-1-5-32-545")
    assert (SID_AUTHENTICATED_USERS, SID_EVERYONE, SID_CREATOR_OWNER) == (
        "*S-1-5-11", "*S-1-1-0", "*S-1-3-0")


def _grants(commands: list[list[str]]) -> list[tuple[str, str, str]]:
    """(path, sid, rights) for every ``/grant`` entry in the commands."""
    out = []
    for cmd in commands:
        if any(a.startswith("/grant") for a in cmd):
            for arg in cmd[2:]:
                if arg.startswith("*S-") and ":" in arg:
                    sid, rights = arg.split(":", 1)
                    out.append((cmd[1], sid, rights))
    return out


def test_users_get_read_on_evidence_only_and_no_write_anywhere() -> None:
    root = PureWindowsPath(r"C:\ProgramData\HomeSOC")
    commands = data_acl.acl_commands(root, root / "data" / "evidence", ICACLS)
    grants = _grants(commands)
    broad = {SID_USERS, SID_AUTHENTICATED_USERS, SID_EVERYONE, SID_CREATOR_OWNER}
    assert [g for g in grants if g[1] in broad] == [
        (r"C:\ProgramData\HomeSOC\data\evidence", SID_USERS, "(OI)(CI)RX")]
    # full control only for SYSTEM and Administrators, on the root, inherited
    assert sorted((p, s) for p, s, r in grants if "F" in r.split(")")[-1]) == sorted([
        (r"C:\ProgramData\HomeSOC", SID_SYSTEM), (r"C:\ProgramData\HomeSOC", SID_ADMINISTRATORS)])
    for _path, _sid, rights in grants:
        assert rights.startswith("(OI)(CI)")
    # /grant:r replaces (never adds to) an earlier grant for the same SID
    assert all("/grant:r" in c for c in commands if any(a.startswith("/grant") for a in c))


def test_root_inheritance_is_cut_first_and_the_tree_scrubbed() -> None:
    commands = data_acl.acl_commands(PureWindowsPath(r"D:\Data\HomeSOC"), None, ICACLS)
    assert commands[0][2] == "/inheritance:r"  # the main hole (ProgramData's Users RX) closes first
    assert len(commands) == 3  # no evidence dir: nothing granted to Users at all
    assert not [g for g in _grants(commands) if g[1] == SID_USERS]
    remove = commands[2]
    assert remove[2] == "/remove:g" and "/T" in remove
    assert set(remove[3:7]) == {SID_USERS, SID_AUTHENTICATED_USERS, SID_EVERYONE, SID_CREATOR_OWNER}
    setowner = commands[1]
    assert setowner[2:] == ["/setowner", SID_ADMINISTRATORS, "/T", "/Q"]


def test_icacls_path_is_absolute_under_system_root() -> None:
    assert data_acl.icacls_path({"SystemRoot": r"D:\Win"}) == str(Path(r"D:\Win") / "System32"
                                                                 / "icacls.exe")
    assert data_acl.icacls_path({}) == str(Path(r"C:\Windows") / "System32" / "icacls.exe")


# --- secure_data_root: runner, folders, failures ---------------------------------------------


def test_secure_runs_every_command_as_an_argument_list_and_creates_the_folders(
        tmp_path: Path) -> None:
    root = tmp_path / "PD" / "HomeSOC"
    evidence = root / "data" / "evidence"
    run = FakeRun()
    assert data_acl.secure_data_root(root, evidence, run=run, icacls="icacls.exe",
                                     timeout_s=7) is True
    assert root.is_dir() and evidence.is_dir()  # evidence exists before it is granted
    assert run.args == data_acl.acl_commands(root, evidence, "icacls.exe")
    for args, kwargs in run.calls:
        assert isinstance(args, list)
        assert not kwargs.get("shell")
        assert kwargs["timeout"] == 7 and kwargs["check"] is False


def test_a_failed_icacls_call_is_logged_and_the_rest_still_run(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    root = tmp_path / "HomeSOC"
    run = FakeRun(codes=[0, 1307, 0, 0])
    with caplog.at_level(logging.ERROR, logger="agent.data_acl"):
        ok = data_acl.secure_data_root(root, root / "data" / "evidence", run=run,
                                       icacls="icacls.exe")
    assert ok is False
    assert len(run.calls) == 4
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("exited with 1307" in r.getMessage() and "/setowner" in r.getMessage()
               and "Access is denied." in r.getMessage() for r in errors)
    assert any("other accounts may be able to read captured traffic" in r.getMessage()
               for r in errors)


@pytest.mark.parametrize("exc", [
    FileNotFoundError("icacls.exe not found"),
    subprocess.TimeoutExpired(["icacls.exe"], 30),
])
def test_missing_icacls_or_a_timeout_is_a_failure(tmp_path: Path, exc: BaseException,
                                                  caplog: pytest.LogCaptureFixture) -> None:
    run = FakeRun(raises=[exc])
    with caplog.at_level(logging.ERROR, logger="agent.data_acl"):
        assert data_acl.secure_data_root(tmp_path / "H", None, run=run, icacls="icacls") is False
    assert len(run.calls) == 3  # one bad call does not stop the others
    assert caplog.records[0].levelno == logging.ERROR


def test_evidence_dir_outside_the_data_root_is_never_made_readable(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    root, outside = tmp_path / "HomeSOC", tmp_path / "elsewhere" / "evidence"
    run = FakeRun()
    with caplog.at_level(logging.WARNING, logger="agent.data_acl"):
        assert data_acl.secure_data_root(root, outside, run=run, icacls="icacls") is True
    assert run.args == data_acl.acl_commands(root, None, "icacls")
    assert not [g for g in _grants(run.args) if g[1] == SID_USERS]
    assert not outside.exists()
    assert "outside the data folder" in caplog.text


# --- only the installed agent, never the dev repo --------------------------------------------


def test_should_secure_only_frozen_with_a_separate_data_root(tmp_path: Path) -> None:
    assert data_acl.should_secure(False, REPO_ROOT, REPO_ROOT) is False  # from source
    assert data_acl.should_secure(False, tmp_path / "PD", REPO_ROOT) is False
    assert data_acl.should_secure(True, REPO_ROOT, REPO_ROOT) is False  # never the repo
    assert data_acl.should_secure(True, tmp_path / "PD" / "HomeSOC", tmp_path / "MEI") is True


def test_from_source_nothing_runs_and_no_folder_is_created(tmp_path: Path) -> None:
    run = FakeRun()
    cfg = config.load(REPO_ROOT / "config.yaml")
    result = data_acl.secure_installed_data_root(
        cfg, tmp_path / "data" / "evidence", frozen=False, data_root=tmp_path,
        bundle_root=REPO_ROOT, run=run)
    assert result is None
    assert run.calls == []
    assert not (tmp_path / "data").exists()


def test_settings_come_from_config_yaml() -> None:
    cfg = config.load(REPO_ROOT / "config.yaml")
    assert cfg["data_acl"] == {"timeout_s": 30, "refuse_on_failure": False}
    assert data_acl.settings(cfg) == (30.0, False)
    assert data_acl.settings({}) == (data_acl.DEFAULT_TIMEOUT_S, False)
    assert data_acl.settings({"data_acl": {"refuse_on_failure": True}})[1] is True


# --- agent/main.py wiring --------------------------------------------------------------------


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Pretend to be the installed agent: frozen, data root in a temp %PROGRAMDATA%."""
    data_root = tmp_path / "PD" / "HomeSOC"
    monkeypatch.setattr(config, "FROZEN", True)
    monkeypatch.setattr(config, "REPO_ROOT", data_root)
    monkeypatch.setattr(config, "BUNDLE_ROOT", tmp_path / "MEI")
    return data_root


def test_agent_locks_the_installed_data_root_with_the_evidence_dir_from_config(
        installed: Path) -> None:
    import agent.main as agent_main
    cfg = config.load(REPO_ROOT / "config.yaml")
    run = FakeRun()
    assert agent_main.secure_data_folder(cfg, run=run) is True
    evidence = installed / "data" / "evidence"  # evidence.evidence_dir, under the data root
    assert evidence.is_dir()
    assert run.args == data_acl.acl_commands(installed, evidence,
                                             data_acl.icacls_path(os.environ))


def test_agent_from_source_leaves_the_repo_acl_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent.main as agent_main
    assert config.FROZEN is False and config.REPO_ROOT == config.BUNDLE_ROOT == REPO_ROOT
    run = FakeRun()
    assert agent_main.secure_data_folder(config.load(REPO_ROOT / "config.yaml"), run=run) is None
    assert run.calls == []


def test_agent_runs_on_after_an_acl_failure_by_default(
        installed: Path, caplog: pytest.LogCaptureFixture) -> None:
    import agent.main as agent_main
    cfg = config.load(REPO_ROOT / "config.yaml")
    with caplog.at_level(logging.ERROR):
        assert agent_main.secure_data_folder(cfg, run=FakeRun(codes=[5, 5, 5, 5])) is False
    assert "Could not fully lock the data folder" in caplog.text


def test_agent_refuses_to_start_when_configured_and_the_acl_fails(installed: Path) -> None:
    import agent.main as agent_main
    cfg = config.load(REPO_ROOT / "config.yaml")
    cfg["data_acl"]["refuse_on_failure"] = True
    with pytest.raises(SystemExit) as excinfo:
        agent_main.secure_data_folder(cfg, run=FakeRun(codes=[5]))
    assert excinfo.value.code == 1
    # a successful lock starts normally even with refuse_on_failure
    assert agent_main.secure_data_folder(cfg, run=FakeRun()) is True


def test_main_locks_the_data_root_after_loading_and_before_running(
        installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import agent.main as agent_main
    order: list[str] = []
    cfg = config.load(REPO_ROOT / "config.yaml")
    run = FakeRun()

    def fake_run(args: list[str], **kwargs: Any) -> SimpleNamespace:
        order.append("icacls")
        return run(args, **kwargs)

    async def fake_agent(*args: Any, **kwargs: Any) -> None:
        order.append("run_agent")

    def fake_seed() -> list[Path]:
        order.append("seed")
        installed.mkdir(parents=True)  # the real seed creates the data root
        return []

    monkeypatch.setattr(config, "seed_data_root", fake_seed)
    monkeypatch.setattr(config, "load", lambda: order.append("load") or cfg)
    monkeypatch.setattr(data_acl.subprocess, "run", fake_run)
    monkeypatch.setattr(agent_main, "run_agent", fake_agent)
    handlers = list(logging.getLogger().handlers)
    try:
        agent_main.main()
    finally:
        for h in logging.getLogger().handlers[:]:
            if h not in handlers:  # main() adds agent.log when frozen
                logging.getLogger().removeHandler(h)
                h.close()
    assert order == ["seed", "load", "icacls", "icacls", "icacls", "icacls", "run_agent"]
    assert run.args[0][1] == str(installed) and run.args[0][2] == "/inheritance:r"


# --- the real icacls on a temp folder (Windows) ----------------------------------------------


def _is_admin() -> bool:
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]


def _sddl(icacls: str, path: Path, out_dir: Path) -> str:
    """The path's DACL as SDDL (``icacls /save``: SIDs, not localised names)."""
    out = out_dir / f"acl{len(list(out_dir.iterdir()))}.txt"
    subprocess.run([icacls, str(path), "/save", str(out), "/Q"], check=True,
                   capture_output=True)
    return out.read_bytes().decode("utf-16-le").splitlines()[1]


def _current_user_sid() -> str:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], check=True,
                         capture_output=True, text=True).stdout
    return out.strip().split(",")[-1].strip('"')


@pytest.mark.skipif(sys.platform != "win32", reason="needs Windows icacls")
def test_real_icacls_locks_a_folder_like_the_installed_data_root(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real commands on a temp copy of the data root's layout. Elevated, they run as is. Not
    # elevated (a dev shell, CI), the test user stands in for Administrators (the agent runs as
    # SYSTEM): only an admin may take ownership for Administrators or lock itself out and keep
    # working. Users, Authenticated Users, Everyone and CREATOR OWNER are checked either way.
    icacls = data_acl.icacls_path(os.environ)
    admin_alias = "BA"
    if not _is_admin():
        me = _current_user_sid()
        monkeypatch.setattr(data_acl, "SID_ADMINISTRATORS", "*" + me)
        admin_alias = me
    root = tmp_path / "HomeSOC"
    (root / "data" / "evidence").mkdir(parents=True)
    locked = ("agent.log", "data/homesoc.db", "data/ring_00001_20260101000000.pcapng")
    files = {rel: root / rel for rel in (*locked, "data/evidence/alert1.pcap")}
    for path in files.values():
        path.write_bytes(b"secret packets")  # exists before the lock, like an upgrade
    acls = tmp_path / "acls"
    acls.mkdir()
    try:
        assert data_acl.secure_data_root(root, root / "data" / "evidence", icacls=icacls) is True

        root_sddl = _sddl(icacls, root, acls)
        assert "D:P" in root_sddl  # protected: nothing inherited from C:\ProgramData
        owner = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Acl -LiteralPath $env:HOMESOC_ACL_TEST).GetOwner("
             "[System.Security.Principal.SecurityIdentifier]).Value"],
            env=dict(os.environ, HOMESOC_ACL_TEST=str(files["agent.log"])),
            check=True, capture_output=True, text=True).stdout.strip()
        assert owner == data_acl.SID_ADMINISTRATORS.lstrip("*")  # /setowner reached the files
        assert "(A;OICI;FA;;;SY)" in root_sddl and f"(A;OICI;FA;;;{admin_alias})" in root_sddl
        for sid in ("BU", "AU", "WD", "CO"):  # Users, Authenticated Users, Everyone, CREATOR OWNER
            assert f";;;{sid})" not in root_sddl
            for rel in locked:
                assert f";;;{sid})" not in _sddl(icacls, files[rel], acls), (rel, sid)
        for rel in locked:  # existing files now inherit only SYSTEM + Administrators
            sddl = _sddl(icacls, files[rel], acls)
            assert "(A;ID;FA;;;SY)" in sddl and f"(A;ID;FA;;;{admin_alias})" in sddl
        ev_sddl = _sddl(icacls, root / "data" / "evidence", acls)
        assert "(A;OICI;0x1200a9;;;BU)" in ev_sddl  # Users read + execute (no write), inherited
        # an evidence pcap inherits Users RX, and so does one written after the lock (SYSTEM's)
        assert "(A;ID;0x1200a9;;;BU)" in _sddl(icacls, files["data/evidence/alert1.pcap"], acls)
        new_pcap = root / "data" / "evidence" / "alert2.pcap"
        new_pcap.write_bytes(b"later export")
        assert "(A;ID;0x1200a9;;;BU)" in _sddl(icacls, new_pcap, acls)
        # running it again (every agent start) gives the same result
        assert data_acl.secure_data_root(root, root / "data" / "evidence", icacls=icacls) is True
        assert _sddl(icacls, root, acls) == root_sddl
    finally:  # put inheritance back so pytest can delete the folder
        subprocess.run([icacls, str(root), "/reset", "/T", "/C", "/Q"], capture_output=True)
