"""Tests for agent.procinfo. No real PowerShell or processes: subprocess.run and
psutil.Process are patched at the module boundary."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

import psutil
import pytest

from agent import procinfo
from agent.procinfo import KillError, ProcInfo, UnsafePathError

PROGRAM_FILES_EXE = r"C:\Program Files\Vendor\app.exe"
DOWNLOADS_EXE = r"C:\Users\bob\Downloads\FreeGameCheats.exe"
TEMP_DIR = r"C:\Users\bob\AppData\Local\Temp"


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch) -> None:
    procinfo.clear_signature_cache()
    for var in procinfo.TEMP_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@dataclass
class FakeRun:
    """Stands in for subprocess.run; records every call."""

    stdout: str = "Valid\r\n"
    returncode: int = 0
    stderr: str = ""
    raises: BaseException | None = None
    calls: list[list[str]] = field(default_factory=list)
    kwargs: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        self.kwargs.append(kwargs)
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> FakeRun:
    fake = FakeRun()
    monkeypatch.setattr(procinfo.subprocess, "run", fake)
    return fake


class FakeProcess:
    """Stands in for psutil.Process."""

    def __init__(
        self,
        pid: int,
        name: str = "app.exe",
        exe: str | None = PROGRAM_FILES_EXE,
        name_error: Exception | None = None,
        exe_error: Exception | None = None,
        terminate_error: Exception | None = None,
        wait_results: list[Exception | None] | None = None,
    ) -> None:
        self.pid = pid
        self._name = name
        self._exe = exe
        self._name_error = name_error
        self._exe_error = exe_error
        self._terminate_error = terminate_error
        self._wait_results = list(wait_results or [None])
        self.terminated = False
        self.killed = False
        self.wait_timeouts: list[float] = []

    def name(self) -> str:
        if self._name_error:
            raise self._name_error
        return self._name

    def exe(self) -> str:
        if self._exe_error:
            raise self._exe_error
        return self._exe or ""

    def terminate(self) -> None:
        if self._terminate_error:
            raise self._terminate_error
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float) -> None:
        self.wait_timeouts.append(timeout)
        result = self._wait_results.pop(0) if self._wait_results else None
        if result is not None:
            raise result


def _patch_process(monkeypatch: pytest.MonkeyPatch, factory: Any) -> None:
    monkeypatch.setattr(procinfo.psutil, "Process", factory)


# --- in_risky_dir ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        DOWNLOADS_EXE,
        r"C:\USERS\BOB\DOWNLOADS\x.exe",
        r"c:\users\bob\downloads\sub\dir\x.exe",
        r"C:\Users\bob\AppData\Local\Temp\x.exe",
        r"C:\Users\bob\appdata\LOCAL\tEmP\nested\x.exe",
        "C:/Users/bob/Downloads/x.exe",
    ],
)
def test_risky_paths_are_detected_case_insensitively(path: str) -> None:
    assert procinfo.is_in_risky_dir(path) is True


@pytest.mark.parametrize(
    "path",
    [
        PROGRAM_FILES_EXE,
        r"C:\PROGRAM FILES\Vendor\app.exe",
        r"C:\Program Files\DownloadsHelper\x.exe",
        r"C:\Users\bob\MyDownloads\x.exe",
        r"C:\Users\bob\AppData\Local\Temporary\x.exe",
        r"C:\Users\bob\AppData\Roaming\Temp\x.exe",
        r"C:\Users\bob\Desktop\Downloads.exe",
        r"C:\Windows\System32\svchost.exe",
    ],
)
def test_non_risky_paths_and_substring_traps(path: str) -> None:
    assert procinfo.is_in_risky_dir(path) is False


def test_temp_env_var_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    path = r"D:\Scratch\Tmp\dropper.exe"
    assert procinfo.is_in_risky_dir(path) is False
    monkeypatch.setenv("TEMP", r"d:\scratch\tmp")
    assert procinfo.is_in_risky_dir(path) is True


def test_tmp_env_var_also_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TMP", r"E:\T")
    assert procinfo.is_in_risky_dir(r"e:\t\x.exe") is True


def test_injected_temp_dirs_match_on_components_only() -> None:
    temp = [r"D:\Scratch\Tmp"]
    assert procinfo.is_in_risky_dir(r"D:\SCRATCH\TMP\a\x.exe", temp_dirs=temp) is True
    assert procinfo.is_in_risky_dir(r"D:\Scratch\TmpOther\x.exe", temp_dirs=temp) is False
    assert procinfo.is_in_risky_dir(r"D:\Other\Scratch\Tmp\x.exe", temp_dirs=temp) is False


# --- signed: parsing PowerShell output -------------------------------------------------------


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ("Valid\r\n", True),
        ("Valid", True),
        ("NotSigned\r\n", False),
        ("HashMismatch\r\n", False),
        ("UnknownError\r\n", False),
    ],
)
def test_signature_status_is_parsed(fake_run: FakeRun, stdout: str, expected: bool) -> None:
    fake_run.stdout = stdout
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is expected
    assert len(fake_run.calls) == 1


def test_powershell_is_invoked_with_expected_argv(fake_run: FakeRun) -> None:
    procinfo.is_signed(PROGRAM_FILES_EXE)
    assert fake_run.calls == [
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-AuthenticodeSignature -LiteralPath 'C:\\Program Files\\Vendor\\app.exe'"
            " | Select-Object -ExpandProperty Status",
        ]
    ]
    kwargs = fake_run.kwargs[0]
    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["errors"] == "replace"
    assert kwargs["timeout"] == procinfo.SIGNATURE_TIMEOUT_S


def _real_run_printing(stdout: bytes, stderr: bytes, code: int) -> Any:
    """A subprocess.run stand-in that runs a REAL child process (this Python) which writes the
    given raw bytes, passing through the exact kwargs procinfo uses. This exercises the real
    decoding path instead of handing back already-decoded strings."""
    real_run = subprocess.run
    script = (
        "import sys;"
        f"sys.stdout.buffer.write({stdout!r});"
        f"sys.stderr.buffer.write({stderr!r});"
        f"sys.exit({code})"
    )

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return real_run([sys.executable, "-c", script], **kwargs)

    return run


def test_undecodable_powershell_error_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    # "Cannot find path 'C:\Users\Jürgen\...'" in cp437/cp850: ü is byte 0x81, which is
    # invalid in both cp1252 and UTF-8.
    stderr = b"Cannot find path 'C:\\Users\\J\x81rgen\\Downloads\\x.exe'\r\n"
    monkeypatch.setattr(procinfo.subprocess, "run", _real_run_printing(b"", stderr, 1))
    assert procinfo.is_signed(r"C:\Users\Jurgen\Downloads\x.exe") is False


def test_undecodable_status_output_is_not_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(procinfo.subprocess, "run", _real_run_printing(b"Val\x81d\r\n", b"", 0))
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False


def test_info_survives_exe_vanishing_with_non_ascii_error(monkeypatch: pytest.MonkeyPatch) -> None:
    exe = r"C:\Users\Jürgen\Downloads\dropper.exe"
    stderr = b"Cannot find path 'C:\\Users\\J\x81rgen\\Downloads\\dropper.exe'\r\n"
    monkeypatch.setattr(procinfo.subprocess, "run", _real_run_printing(b"", stderr, 1))
    _patch_process(monkeypatch, lambda pid: FakeProcess(pid, name="dropper.exe", exe=exe))
    result = procinfo.info(4321)
    assert result == ProcInfo(
        pid=4321, name="dropper.exe", exe_path=exe, in_risky_dir=True, signed=False
    )


def test_decode_error_is_treated_as_failed_check_and_not_cached(fake_run: FakeRun) -> None:
    fake_run.raises = UnicodeDecodeError("cp1252", b"\x81", 0, 1, "undefined")
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False
    fake_run.raises = None
    fake_run.stdout = "Valid"
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is True  # retried, not cached as unsigned
    assert len(fake_run.calls) == 2


def test_nonzero_exit_is_unsigned_and_not_cached(fake_run: FakeRun) -> None:
    fake_run.returncode = 1
    fake_run.stdout = "Valid"
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False
    assert len(fake_run.calls) == 2  # failure is retried, not cached


def test_empty_output_is_unsigned(fake_run: FakeRun) -> None:
    fake_run.stdout = "   \r\n"
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False


@pytest.mark.parametrize(
    "error",
    [FileNotFoundError("powershell"), subprocess.TimeoutExpired("powershell", 15.0)],
)
def test_missing_or_hung_powershell_is_unsigned(fake_run: FakeRun, error: Exception) -> None:
    fake_run.raises = error
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False


def test_transient_failure_then_success_is_rechecked(fake_run: FakeRun) -> None:
    fake_run.returncode = 1
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is False
    fake_run.returncode = 0
    fake_run.stdout = "Valid"
    assert procinfo.is_signed(PROGRAM_FILES_EXE) is True
    assert len(fake_run.calls) == 2


# --- cache -----------------------------------------------------------------------------------


def test_second_info_for_same_exe_does_not_rerun_powershell(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_process(monkeypatch, lambda pid: FakeProcess(pid))
    first = procinfo.info(100)
    second = procinfo.info(200)  # different PID, same exe
    assert first.signed is True and second.signed is True
    assert len(fake_run.calls) == 1


def test_cache_is_case_insensitive(fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = iter([PROGRAM_FILES_EXE, PROGRAM_FILES_EXE.upper(), "c:/program files/vendor/APP.exe"])
    _patch_process(monkeypatch, lambda pid: FakeProcess(pid, exe=next(paths)))
    results = [procinfo.info(pid).signed for pid in (1, 2, 3)]
    assert results == [True, True, True]
    assert len(fake_run.calls) == 1


def test_negative_result_is_cached_too(fake_run: FakeRun) -> None:
    fake_run.stdout = "NotSigned"
    assert procinfo.is_signed(DOWNLOADS_EXE) is False
    assert procinfo.is_signed(DOWNLOADS_EXE) is False
    assert len(fake_run.calls) == 1


def test_different_exes_are_checked_separately(fake_run: FakeRun) -> None:
    procinfo.is_signed(PROGRAM_FILES_EXE)
    procinfo.is_signed(DOWNLOADS_EXE)
    assert len(fake_run.calls) == 2


# --- safe quoting ----------------------------------------------------------------------------


INJECTION_PATH = r"C:\Users\x\Downloads\it's; Remove-Item C:\ -Recurse.exe"


def test_injection_path_becomes_one_literal() -> None:
    cmd = procinfo.build_signature_command(INJECTION_PATH)
    assert cmd == (
        "Get-AuthenticodeSignature -LiteralPath "
        "'C:\\Users\\x\\Downloads\\it''s; Remove-Item C:\\ -Recurse.exe'"
        " | Select-Object -ExpandProperty Status"
    )


def test_quoted_literal_has_only_doubled_inner_quotes() -> None:
    quoted = procinfo.ps_quote(INJECTION_PATH)
    assert quoted.startswith("'") and quoted.endswith("'")
    inner = quoted[1:-1]
    # Every quote inside is part of a doubled pair, so the literal never closes early and
    # the `;` stays inside the string instead of starting a second command.
    assert inner.replace("''", "").count("'") == 0
    assert inner.replace("''", "'") == INJECTION_PATH


def test_injection_path_reaches_powershell_as_single_literal(fake_run: FakeRun) -> None:
    procinfo.is_signed(INJECTION_PATH)
    cmd = fake_run.calls[0][-1]
    assert cmd == procinfo.build_signature_command(INJECTION_PATH)
    assert len(fake_run.calls[0]) == 5  # the path did not leak into extra argv entries


@pytest.mark.parametrize("quote", ["\u2018", "\u2019", "\u201a", "\u201b"])
def test_unicode_single_quotes_are_doubled(quote: str) -> None:
    assert procinfo.ps_quote(f"a{quote}b") == f"'a{quote}{quote}b'"


def test_dollar_and_backtick_are_left_literal() -> None:
    assert procinfo.ps_quote("C:\\$env:x`n\\a.exe") == "'C:\\$env:x`n\\a.exe'"


@pytest.mark.parametrize("bad", ["C:\\a\nb.exe", "C:\\a\rb.exe", "C:\\a\x00b.exe"])
def test_control_characters_are_rejected(bad: str) -> None:
    with pytest.raises(UnsafePathError):
        procinfo.ps_quote(bad)


def test_unsafe_path_never_reaches_powershell(fake_run: FakeRun) -> None:
    assert procinfo.is_signed("C:\\a\n Remove-Item C:\\.exe") is False
    assert fake_run.calls == []


# --- info() ----------------------------------------------------------------------------------


def test_info_returns_full_result(fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_run.stdout = "NotSigned"
    _patch_process(
        monkeypatch, lambda pid: FakeProcess(pid, name="FreeGameCheats.exe", exe=DOWNLOADS_EXE)
    )
    result = procinfo.info(1234)
    assert result == ProcInfo(
        pid=1234,
        name="FreeGameCheats.exe",
        exe_path=DOWNLOADS_EXE,
        in_risky_dir=True,
        signed=False,
    )
    assert result.as_dict() == {
        "pid": 1234,
        "name": "FreeGameCheats.exe",
        "exe_path": DOWNLOADS_EXE,
        "in_risky_dir": True,
        "signed": False,
    }


def test_info_uses_injected_temp_dirs(fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_process(monkeypatch, lambda pid: FakeProcess(pid, exe=r"D:\T\x.exe"))
    assert procinfo.info(1, temp_dirs=[r"D:\T"]).in_risky_dir is True
    assert procinfo.info(1, temp_dirs=[]).in_risky_dir is False


def test_info_on_vanished_pid_returns_none_path(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    def gone(pid: int) -> FakeProcess:
        raise psutil.NoSuchProcess(pid)

    _patch_process(monkeypatch, gone)
    result = procinfo.info(999)
    assert result == ProcInfo(
        pid=999, name="unknown", exe_path=None, in_risky_dir=None, signed=None
    )
    assert fake_run.calls == []


def test_info_when_process_exits_between_calls(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_process(monkeypatch, lambda pid: FakeProcess(pid, exe_error=psutil.NoSuchProcess(pid)))
    result = procinfo.info(5)
    assert result.exe_path is None and result.signed is None and result.in_risky_dir is None
    assert result.name == "app.exe"
    assert fake_run.calls == []


def test_info_on_access_denied_exe_keeps_name(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_process(
        monkeypatch,
        lambda pid: FakeProcess(pid, name="lsass.exe", exe_error=psutil.AccessDenied(pid)),
    )
    result = procinfo.info(700)
    assert result == ProcInfo(
        pid=700, name="lsass.exe", exe_path=None, in_risky_dir=None, signed=None
    )
    assert fake_run.calls == []


def test_info_on_access_denied_everything(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_process(
        monkeypatch,
        lambda pid: FakeProcess(
            pid, name_error=psutil.AccessDenied(pid), exe_error=psutil.AccessDenied(pid)
        ),
    )
    result = procinfo.info(8)
    assert result.name == "unknown" and result.exe_path is None


def test_info_with_empty_exe_string_is_unknown(
    fake_run: FakeRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_process(monkeypatch, lambda pid: FakeProcess(pid, name="Registry", exe=""))
    assert procinfo.info(120).exe_path is None
    assert fake_run.calls == []


# --- kill() ----------------------------------------------------------------------------------


def test_kill_terminates_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProcess(42)
    _patch_process(monkeypatch, lambda pid: proc)
    assert procinfo.kill(42) is True
    assert proc.terminated and not proc.killed
    assert proc.wait_timeouts == [procinfo.KILL_TIMEOUT_S]


def test_kill_escalates_after_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProcess(42, wait_results=[psutil.TimeoutExpired(3.0), None])
    _patch_process(monkeypatch, lambda pid: proc)
    assert procinfo.kill(42, timeout_s=0.5) is True
    assert proc.terminated and proc.killed
    assert proc.wait_timeouts == [0.5, 0.5]


def test_kill_raises_if_process_survives(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProcess(42, wait_results=[psutil.TimeoutExpired(3.0), psutil.TimeoutExpired(3.0)])
    _patch_process(monkeypatch, lambda pid: proc)
    with pytest.raises(KillError):
        procinfo.kill(42)


def test_kill_on_vanished_pid_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    def gone(pid: int) -> FakeProcess:
        raise psutil.NoSuchProcess(pid)

    _patch_process(monkeypatch, gone)
    assert procinfo.kill(31337) is False


def test_kill_when_process_exits_before_terminate(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProcess(42, terminate_error=psutil.NoSuchProcess(42))
    _patch_process(monkeypatch, lambda pid: proc)
    assert procinfo.kill(42) is False


def test_kill_access_denied_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = FakeProcess(42, terminate_error=psutil.AccessDenied(42))
    _patch_process(monkeypatch, lambda pid: proc)
    with pytest.raises(KillError):
        procinfo.kill(42)


@pytest.mark.parametrize("pid", [0, 4])
def test_kill_refuses_protected_pids(monkeypatch: pytest.MonkeyPatch, pid: int) -> None:
    def must_not_open(pid: int) -> FakeProcess:
        raise AssertionError("psutil.Process must not be opened for a protected pid")

    _patch_process(monkeypatch, must_not_open)
    with pytest.raises(KillError):
        procinfo.kill(pid)


def test_kill_refuses_own_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(procinfo.os, "getpid", lambda: 5150)
    with pytest.raises(KillError):
        procinfo.kill(5150)
