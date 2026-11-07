"""SQLite persistence for alerts, actions and anomaly baselines (CLAUDE.md §3, §6.5).

Pure Python (stdlib :mod:`sqlite3`), no Windows-only imports, so it is tested on any OS (§10).

Tables
    ``alerts``     one row per :class:`~agent.events.Alert` (``id`` is the key). A few columns
                   (``ts_ms``, ``severity``, ``process``) are kept for ordering/filtering; the
                   whole alert, nested :class:`~agent.events.Signal`\\ s included, is stored as
                   JSON in ``data`` (the same shape :func:`agent.events.to_json` produces).
    ``actions``    one row per :class:`~agent.events.Action`, every field as a column
                   (``rule_names`` as a JSON list). The stored rule names are what lets
                   ``agent.response.firewall.undo`` remove the rules after an agent restart.
    ``baselines``  one row per process name: the anomaly detector's calibration data.

Baseline payload
    Whatever JSON-serialisable ``dict`` the anomaly detector chooses (e.g.
    ``{"windows": [[bytes_out, flows, unique_dst_ips], ...], "calibrated_at_ms": 0}``). It is
    stored with :func:`json.dumps` and read back with :func:`json.loads`, so tuples come back as
    lists and dict keys as strings. A non-serialisable payload raises ``TypeError``.

Semantics
    * Every ``save_*`` is an upsert: saving an object with an existing id/process replaces it.
      An alert keeps its original insertion position when it is re-saved (e.g. after
      ``finalize_alert`` fills ``action_ids``), so list order stays stable.
    * ``list_alerts`` / ``list_actions`` return newest first: ``ts_ms`` descending, then most
      recently inserted first for equal timestamps.
    * ``mark_undone(action_id)`` returns ``False`` for an unknown id (nothing changes) so the API
      can answer 404 without catching exceptions.
    * Alerts and actions need a non-empty ``id``; an empty one raises ``ValueError``.

Threading
    The agent is asyncio plus capture threads. One connection is opened with
    ``check_same_thread=False`` and every call holds a :class:`threading.Lock`, so a single
    ``Store`` can be shared between threads. Each write commits immediately.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields
from pathlib import Path
from types import TracebackType
from typing import Any

from agent import config as config_module
from agent.events import Action, Alert, Signal, to_json

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        TEXT PRIMARY KEY,
    ts_ms     INTEGER NOT NULL,
    severity  TEXT NOT NULL,
    process   TEXT NOT NULL,
    data      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts_ms);

CREATE TABLE IF NOT EXISTS actions (
    id          TEXT PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    target      TEXT NOT NULL,
    rule_names  TEXT NOT NULL,
    undone      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS actions_ts ON actions (ts_ms);

CREATE TABLE IF NOT EXISTS baselines (
    process     TEXT PRIMARY KEY,
    updated_ms  INTEGER NOT NULL,
    data        TEXT NOT NULL
);
"""

_ALERT_FIELDS = frozenset(f.name for f in fields(Alert))
_SIGNAL_FIELDS = frozenset(f.name for f in fields(Signal))


def _now_ms() -> int:
    return int(time.time() * 1000)


def _signal_from_dict(data: dict[str, Any]) -> Signal:
    return Signal(**{k: v for k, v in data.items() if k in _SIGNAL_FIELDS})


def _alert_from_json(text: str) -> Alert:
    data = json.loads(text)
    kwargs = {k: v for k, v in data.items() if k in _ALERT_FIELDS}
    kwargs["signals"] = [_signal_from_dict(s) for s in data.get("signals", [])]
    kwargs["action_ids"] = list(data.get("action_ids", []))
    return Alert(**kwargs)


def _action_from_row(row: sqlite3.Row) -> Action:
    return Action(
        id=row["id"],
        ts_ms=row["ts_ms"],
        kind=row["kind"],
        target=row["target"],
        rule_names=list(json.loads(row["rule_names"])),
        undone=bool(row["undone"]),
    )


def _require_id(obj: Alert | Action) -> None:
    if not obj.id:
        raise ValueError(f"cannot store a {type(obj).__name__} with an empty id")


class Store:
    """SQLite store for alerts, actions and baselines. Use as a context manager or call close()."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        logger.debug("Opened store %s", self._path)

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> Store:
        """Open the store at ``store.path`` from a loaded ``config.yaml``."""
        return cls(config_module.store_path(cfg))

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Hold the lock and run one transaction (commit on success, rollback on error)."""
        with self._lock, self._conn:
            yield self._conn

    # --- alerts -------------------------------------------------------------------------------

    def save_alert(self, alert: Alert) -> None:
        """Insert or replace an alert (nested signals included)."""
        _require_id(alert)
        data = json.dumps(to_json(alert))
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO alerts (id, ts_ms, severity, process, data) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET ts_ms = excluded.ts_ms, "
                "severity = excluded.severity, process = excluded.process, data = excluded.data",
                (alert.id, alert.ts_ms, alert.severity, alert.process, data),
            )

    def get_alert(self, alert_id: str) -> Alert | None:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _alert_from_json(row["data"]) if row else None

    def list_alerts(self, limit: int | None = None) -> list[Alert]:
        """Alerts newest first (``ts_ms`` desc, then latest inserted). ``limit=None`` = all."""
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT data FROM alerts ORDER BY ts_ms DESC, rowid DESC LIMIT ?",
                (-1 if limit is None else limit,),
            ).fetchall()
        return [_alert_from_json(r["data"]) for r in rows]

    # --- actions ------------------------------------------------------------------------------

    def save_action(self, action: Action) -> None:
        """Insert or replace an action, keeping its firewall ``rule_names`` for later undo."""
        _require_id(action)
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO actions (id, ts_ms, kind, target, rule_names, undone) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET ts_ms = excluded.ts_ms, kind = excluded.kind, "
                "target = excluded.target, rule_names = excluded.rule_names, "
                "undone = excluded.undone",
                (
                    action.id,
                    action.ts_ms,
                    action.kind,
                    action.target,
                    json.dumps(list(action.rule_names)),
                    int(action.undone),
                ),
            )

    def get_action(self, action_id: str) -> Action | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
        return _action_from_row(row) if row else None

    def list_actions(self, limit: int | None = None, undone: bool | None = None) -> list[Action]:
        """Actions newest first. ``undone=False`` gives only the ones still in force."""
        query = "SELECT * FROM actions"
        params: list[Any] = []
        if undone is not None:
            query += " WHERE undone = ?"
            params.append(int(undone))
        query += " ORDER BY ts_ms DESC, rowid DESC LIMIT ?"
        params.append(-1 if limit is None else limit)
        with self._tx() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_action_from_row(r) for r in rows]

    def mark_undone(self, action_id: str) -> bool:
        """Set ``undone=True`` on a stored action. Returns ``False`` if the id is unknown."""
        with self._tx() as conn:
            cur = conn.execute("UPDATE actions SET undone = 1 WHERE id = ?", (action_id,))
        if cur.rowcount == 0:
            logger.warning("mark_undone: no stored action with id %r", action_id)
            return False
        return True

    def mark_all_undone(self) -> int:
        """Mark every action as undone (after ``firewall.undo_all``). Returns rows changed."""
        with self._tx() as conn:
            cur = conn.execute("UPDATE actions SET undone = 1 WHERE undone = 0")
        return cur.rowcount

    # --- baselines ----------------------------------------------------------------------------

    def save_baseline(
        self, process: str, data: dict[str, Any], updated_ms: int | None = None
    ) -> None:
        """Insert or replace one process's baseline (a JSON-serialisable dict)."""
        if not isinstance(data, dict):
            raise TypeError(f"baseline data must be a dict, got {type(data).__name__}")
        payload = json.dumps(data)
        ts = _now_ms() if updated_ms is None else updated_ms
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO baselines (process, updated_ms, data) VALUES (?, ?, ?) "
                "ON CONFLICT(process) DO UPDATE SET updated_ms = excluded.updated_ms, "
                "data = excluded.data",
                (process, ts, payload),
            )

    def load_baseline(self, process: str) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT data FROM baselines WHERE process = ?", (process,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def load_baselines(self) -> dict[str, dict[str, Any]]:
        """Every stored baseline, keyed by process name."""
        with self._tx() as conn:
            rows = conn.execute("SELECT process, data FROM baselines").fetchall()
        return {r["process"]: json.loads(r["data"]) for r in rows}
