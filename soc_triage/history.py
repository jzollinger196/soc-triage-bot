"""SQLite store of recent alerts, used to correlate events from the same source.

Correlation uses the alert's own timestamp rather than wall-clock time, so replaying
old sample alerts gives the same results as live traffic.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import Alert

FAILURE_CATEGORIES = ("brute_force", "auth_failure")


class History:
    def __init__(self, path: str = ":memory:"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS events (
                   alert_id TEXT PRIMARY KEY,
                   ts REAL NOT NULL,
                   src_ip TEXT,
                   agent TEXT,
                   rule_id TEXT,
                   category TEXT,
                   user TEXT
               )"""
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ts ON events (src_ip, ts)")
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS tickets (
                   incident_id TEXT PRIMARY KEY,
                   system TEXT NOT NULL,
                   ticket_id TEXT NOT NULL,
                   url TEXT,
                   created_at TEXT NOT NULL
               )"""
        )
        self.conn.commit()

    # ------------------------------------------------------------------ tickets
    def add_ticket(self, incident_id: str, ticket: dict, created_at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO tickets (incident_id, system, ticket_id, url, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (incident_id, ticket["system"], ticket["id"], ticket.get("url"), created_at))
        self.conn.commit()

    def get_ticket(self, incident_id: str):
        row = self.conn.execute("SELECT system, ticket_id, url FROM tickets WHERE incident_id = ?",
                                (incident_id,)).fetchone()
        return {"system": row[0], "id": row[1], "url": row[2]} if row else None

    def lookback(self, alert: Alert, window_minutes: int) -> dict:
        """Summarise earlier alerts from the same source IP inside the window."""
        empty = {"related": 0, "users": [], "agents": [], "failures_same_agent": 0, "first_seen": None}
        if not alert.src_ip:
            return empty
        end = alert.timestamp.timestamp()
        start = end - window_minutes * 60
        rows = self.conn.execute(
            "SELECT ts, agent, category, user FROM events "
            "WHERE src_ip = ? AND ts >= ? AND ts <= ? AND alert_id != ? ORDER BY ts",
            (alert.src_ip, start, end, alert.alert_id),
        ).fetchall()
        if not rows:
            return empty
        return {
            "related": len(rows),
            "users": sorted({r[3].lower() for r in rows if r[3]}),
            "agents": sorted({r[1] for r in rows if r[1]}),
            "failures_same_agent": sum(
                1 for r in rows if r[2] in FAILURE_CATEGORIES and r[1] == alert.agent_name
            ),
            "first_seen": rows[0][0],
        }

    def record(self, alert: Alert) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO events (alert_id, ts, src_ip, agent, rule_id, category, user) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (alert.alert_id, alert.timestamp.timestamp(), alert.src_ip, alert.agent_name,
             alert.rule_id, alert.category, alert.user),
        )
        self.conn.commit()

    def prune(self, older_than_days: int = 30) -> None:
        self.conn.execute(
            "DELETE FROM events WHERE ts < (SELECT MAX(ts) FROM events) - ?",
            (older_than_days * 86400,),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
