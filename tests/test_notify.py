"""Tests for the Windows toasts (app/notify.py, CLAUDE.md §6.7, ticket #43).

``winotify`` is replaced by a fake module in ``sys.modules`` and the platform check
(:func:`app.notify.is_windows`) is patched, so these run on any OS.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from agent import config as config_module
from agent.events import Alert, to_json
from app import main as app_main
from app import notify
from app.notify import Notifier, NotifySettings, listen, notify_settings, truncate

LONG_ADVICE = ("Delete FreeGameCheats.exe from your Downloads folder, then run a full scan with "
               "Microsoft Defender and change any passwords you typed while it was running. "
               "If you did not install this app yourself, ask for help before restoring it.")


def alert(alert_id: str, severity: str, title: str = "FreeGameCheats.exe talks to a C2 server",
          advice: str = LONG_ADVICE) -> dict[str, Any]:
    return to_json(Alert(id=alert_id, ts_ms=1, severity=severity,  # type: ignore[arg-type]
                         process="FreeGameCheats.exe", risk=0.95, title=title,
                         what_you_should_do=advice))


class FakeWinotify:
    """Stands in for the ``winotify`` module: records every Notification and its show()."""

    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.shown: list[dict[str, Any]] = []
        outer = self

        class Notification:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                outer.created.append(kwargs)

            def show(self) -> None:
                outer.shown.append(self.kwargs)

        self.Notification = Notification


@pytest.fixture
def fake_winotify(monkeypatch: pytest.MonkeyPatch) -> FakeWinotify:
    fake = FakeWinotify()
    monkeypatch.setitem(sys.modules, "winotify", fake)  # type: ignore[arg-type]
    monkeypatch.setattr(notify, "is_windows", lambda: True)
    return fake


# --- acceptance 1: high + critical toast once each, low + medium never -------------------------


def test_high_and_critical_each_toast_once_low_and_medium_never(
        fake_winotify: FakeWinotify) -> None:
    n = Notifier(settings=NotifySettings(text_chars=60))
    results = [n.handle_message(alert(f"a-{sev}", sev))
               for sev in ("low", "medium", "high", "critical")]
    assert results == [False, False, True, True]
    assert len(fake_winotify.created) == 2
    assert len(fake_winotify.shown) == 2
    expected_text = truncate(LONG_ADVICE, 60)
    assert len(expected_text) <= 60 and expected_text.endswith("…")
    assert LONG_ADVICE.startswith(expected_text[:-1].rstrip())
    for kwargs in fake_winotify.shown:
        assert kwargs["title"] == "FreeGameCheats.exe talks to a C2 server"
        assert kwargs["msg"] == expected_text
        assert kwargs["app_id"] == "HomeSOC"


def test_non_alert_messages_never_toast(fake_winotify: FakeWinotify) -> None:
    n = Notifier()
    flow = {"type": "flow", "id": "x", "severity": "critical", "title": "t"}
    action = {"type": "action", "id": "y", "kind": "quarantine_app"}
    assert not n.handle_message(flow)
    assert not n.handle_message(action)
    assert not n.handle_raw("not json")
    assert fake_winotify.shown == []


def test_raw_ws_frame_of_a_critical_alert_toasts(fake_winotify: FakeWinotify) -> None:
    n = Notifier()
    assert n.handle_raw(json.dumps(alert("raw-1", "critical", advice="Short advice.")))
    assert fake_winotify.shown[0]["msg"] == "Short advice."


def test_text_length_comes_from_config_yaml() -> None:
    cfg = config_module.load()
    settings = notify_settings(cfg)
    assert settings.text_chars == cfg["app"]["toast_text_chars"]
    seen: list[tuple[str, str]] = []
    Notifier(lambda t, m: seen.append((t, m)), settings).handle_message(alert("c1", "high"))
    assert len(seen[0][1]) <= settings.text_chars


def test_bad_settings_are_refused() -> None:
    with pytest.raises(ValueError):
        notify_settings({"app": {"toast_text_chars": 0}})


# --- acceptance 2: the same alert id never toasts twice ---------------------------------------


def test_same_alert_id_toasts_only_once(fake_winotify: FakeWinotify) -> None:
    n = Notifier()
    assert n.handle_message(alert("dup", "critical"))
    assert not n.handle_message(alert("dup", "critical"))
    assert not n.handle_raw(json.dumps(alert("dup", "high")))
    assert n.handle_message(alert("other", "high"))
    assert len(fake_winotify.shown) == 2


def test_dedupe_memory_is_bounded() -> None:
    seen: list[str] = []
    n = Notifier(lambda t, m: seen.append(t), NotifySettings(dedupe_max=2))
    for i in range(3):
        n.handle_message(alert(f"id{i}", "high", title=f"t{i}"))
    assert not n.handle_message(alert("id2", "high"))  # still remembered
    assert len(n._seen) == 2
    assert n.handle_message(alert("id0", "high", title="t0"))  # oldest was forgotten
    assert seen == ["t0", "t1", "t2", "t0"]


def test_a_failing_toast_is_logged_not_raised_and_not_retried() -> None:
    calls: list[str] = []

    def broken(title: str, text: str) -> None:
        calls.append(title)
        raise RuntimeError("toast backend down")

    n = Notifier(broken)
    assert n.handle_message(alert("boom", "critical")) is False
    assert n.handle_message(alert("boom", "critical")) is False
    assert len(calls) == 1


# --- acceptance 3: imports on non-Windows, toasts are a no-op there ---------------------------


def test_reload_without_winotify_on_non_windows_is_a_noop(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "winotify", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    module = importlib.reload(notify)
    try:
        assert "winotify" not in sys.modules
        assert module.is_windows() is False
        n = module.Notifier()  # default toast_fn = windows_toast
        assert n.handle_message(alert("crit", "critical")) is True  # handled, nothing shown
        assert "winotify" not in sys.modules  # never even tried to import it
        assert module.start_notifier(cfg={}) is None  # no listener off Windows
    finally:
        monkeypatch.undo()
        importlib.reload(notify)


def test_non_windows_does_not_touch_an_installed_winotify(
        monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeWinotify()
    monkeypatch.setitem(sys.modules, "winotify", fake)  # type: ignore[arg-type]
    monkeypatch.setattr(notify, "is_windows", lambda: False)
    Notifier().handle_message(alert("crit", "critical"))
    assert fake.created == []


def test_windows_without_winotify_installed_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notify, "is_windows", lambda: True)
    monkeypatch.setitem(sys.modules, "winotify", None)  # makes `import winotify` raise
    notify.windows_toast("title", "text")  # no exception


def test_importing_notify_does_not_import_winotify_or_websockets() -> None:
    code = ("import sys, app.notify; "
            "bad = [m for m in ('winotify', 'websockets', 'webview') if m in sys.modules]; "
            "sys.exit(1 if bad else 0)")
    repo = Path(__file__).resolve().parent.parent
    assert subprocess.run([sys.executable, "-c", code], cwd=repo).returncode == 0


# --- the WebSocket listener and the wiring in app.main ----------------------------------------


class FakeConn:
    def __init__(self, frames: list[str]) -> None:
        self.frames = frames

    def __enter__(self) -> list[str]:
        return self.frames

    def __exit__(self, *exc: Any) -> None:
        return None


def test_listen_feeds_frames_and_reconnects_after_a_failure() -> None:
    stop = threading.Event()
    toasts: list[str] = []
    urls: list[str] = []
    attempts = {"n": 0}

    def connect(url: str) -> FakeConn:
        urls.append(url)
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ConnectionRefusedError("agent offline")
        if attempts["n"] == 2:
            return FakeConn([json.dumps(alert("w1", "critical", title="first")),
                             json.dumps({"type": "flow"}),
                             json.dumps(alert("w1", "critical", title="first"))])
        stop.set()
        return FakeConn([json.dumps(alert("w2", "high", title="ignored after stop"))])

    listen(Notifier(lambda t, m: toasts.append(t)), stop, connect=connect, reconnect_s=0.001)
    assert urls == ["ws://127.0.0.1:8765/ws"] * 3
    assert toasts == ["first"]


def test_listen_refuses_a_non_local_url() -> None:
    with pytest.raises(ValueError):
        listen(Notifier(lambda t, m: None), threading.Event(), url="ws://10.0.0.5:8765/ws",
               connect=lambda url: pytest.fail("must not connect"))


def test_start_notifier_runs_the_listener_in_a_daemon_thread() -> None:
    got = threading.Event()
    toasts: list[str] = []

    def connect(url: str) -> FakeConn:
        return FakeConn([json.dumps(alert("t1", "critical", title="threaded"))])

    def toast(title: str, text: str) -> None:
        toasts.append(title)
        got.set()

    stop = notify.start_notifier(cfg={"app": {"ws_reconnect_s": 0.01}}, connect=connect,
                                 toast_fn=toast)
    try:
        assert stop is not None
        assert got.wait(2)
        threads = [t for t in threading.enumerate() if t.name == "homesoc-notify"]
        assert threads and all(t.daemon for t in threads)
    finally:
        assert stop is not None
        stop.set()
    assert toasts == ["threaded"]


def test_main_starts_the_notifier(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[bool] = []
    monkeypatch.setattr(notify, "start_notifier", lambda: started.append(True))
    monkeypatch.setattr(app_main, "run", lambda **kw: None)
    monkeypatch.setattr(app_main.logging, "basicConfig", lambda **kw: None)
    app_main.main()
    assert started == [True]
