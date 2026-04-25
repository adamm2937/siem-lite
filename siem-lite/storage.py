"""
SIEM-Lite — Event Store
SQLite-backed persistence for events and alerts.
Provides a simple query API consumed by the dashboard.
"""

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

log = logging.getLogger(__name__)

DB_PATH = Path(os.getenv("DB_PATH", "siem.db")) if (os := __import__("os")) else Path("siem.db")


class EventStore:
    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self._local  = threading.local()
        self._init_db()

    # ── connection management ──────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        conn = self._conn()
        cur  = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    # ── schema ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with self._cursor() as cur:
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp  TEXT    NOT NULL,
                    source     TEXT    NOT NULL,
                    event_type TEXT    NOT NULL,
                    severity   TEXT    NOT NULL,
                    raw        TEXT,
                    extra      TEXT    -- JSON blob for remaining fields
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp        TEXT NOT NULL,
                    rule_id          TEXT NOT NULL,
                    title            TEXT NOT NULL,
                    severity         TEXT NOT NULL,
                    mitre_tactic     TEXT,
                    mitre_technique  TEXT,
                    description      TEXT,
                    event_json       TEXT,
                    context_json     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts   ON events (timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_src  ON events (source);
                CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts (timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_sev  ON alerts (severity);
            """)
        log.info("EventStore initialised at %s", self.db_path)

    # ── write ──────────────────────────────────────────────────────────────

    def save_event(self, event: dict) -> None:
        extra = {k: v for k, v in event.items()
                 if k not in ("timestamp", "source", "event_type", "severity", "raw")}
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO events (timestamp, source, event_type, severity, raw, extra) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (event["timestamp"], event["source"], event["event_type"],
                 event["severity"], event.get("raw"), json.dumps(extra)),
            )

    def save_alert(self, alert) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO alerts "
                "(timestamp, rule_id, title, severity, mitre_tactic, "
                " mitre_technique, description, event_json, context_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (alert.timestamp, alert.rule_id, alert.title, alert.severity,
                 alert.mitre_tactic, alert.mitre_technique, alert.description,
                 json.dumps(alert.event), json.dumps(alert.context)),
            )

    # ── read ───────────────────────────────────────────────────────────────

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]

    def recent_events(self, limit: int = 200) -> list[dict]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]

    def event_counts_by_type(self, hours: int = 24) -> list[dict]:
        cutoff = datetime.now(timezone.utc).isoformat()[:13]  # hour precision
        with self._cursor() as cur:
            cur.execute(
                "SELECT event_type, COUNT(*) as count FROM events "
                "WHERE timestamp >= ? GROUP BY event_type ORDER BY count DESC",
                (cutoff,),
            )
            return [dict(r) for r in cur.fetchall()]

    def alert_counts_by_severity(self) -> dict:
        with self._cursor() as cur:
            cur.execute(
                "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
            )
            return {r["severity"]: r["count"] for r in cur.fetchall()}

    def stats(self) -> dict:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) as n FROM events")
            total_events = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) as n FROM alerts")
            total_alerts = cur.fetchone()["n"]
            cur.execute(
                "SELECT COUNT(*) as n FROM alerts WHERE severity IN ('high','critical')"
            )
            critical = cur.fetchone()["n"]
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical,
        }
