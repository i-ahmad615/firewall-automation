"""SQLite persistence for alerts, firewall actions, structured logs, and statistics.

Design notes
------------
* This module is intentionally decoupled from :class:`~core.config.AppConfig`.
  Callers pass a plain path string to :func:`init_db`; recording functions
  (``record_alert``, ``record_firewall_action``, ``record_log``) are safe
  no-ops until ``init_db`` has been called. This keeps existing unit tests
  (which build ``AppConfig``/mocks without a database) working unchanged.
* Short-lived connections are opened per call with WAL journaling enabled,
  which is safe for concurrent access from the monitor thread and the web
  server thread/process without a shared connection object.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

_lock = threading.Lock()
_db_path: Optional[str] = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    subject TEXT,
    sender TEXT,
    origin_ip TEXT,
    classification TEXT,
    status TEXT,          -- processed | ignored
    action_taken TEXT,     -- blocked | duplicate | allowed | failed | ignored
    reason TEXT,
    notification_sent INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at);
CREATE INDEX IF NOT EXISTS idx_alerts_origin_ip ON alerts(origin_ip);

CREATE TABLE IF NOT EXISTS firewall_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    ip TEXT,
    rule_name TEXT,
    result TEXT,           -- blocked | duplicate | allowed | failed
    duplicate INTEGER DEFAULT 0,
    allowed_list INTEGER DEFAULT 0,
    notification_sent INTEGER DEFAULT 0,
    status TEXT,           -- success | failure
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_fw_occurred_at ON firewall_actions(occurred_at);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT,
    module TEXT,
    action TEXT,
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_module ON logs(module);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at TEXT NOT NULL,
    subject TEXT,
    recipient TEXT,
    status TEXT
);

-- IPs that failed to block are "reserved" here and retried on every
-- subsequent polling cycle until the firewall accepts them.
CREATE TABLE IF NOT EXISTS pending_blocks (
    ip TEXT PRIMARY KEY,
    first_failed_at TEXT NOT NULL,
    last_attempt_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_error TEXT
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(path: str) -> None:
    """Create the database file/schema and register *path* as the active DB."""
    global _db_path
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()
    _db_path = path


def is_initialized() -> bool:
    return _db_path is not None


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    if _db_path is None:
        raise RuntimeError("database not initialized -- call init_db() first")
    conn = sqlite3.connect(_db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Recording (safe no-ops when uninitialized)
# ──────────────────────────────────────────────────────────────────────────────

def record_alert(
    *,
    subject: str = "",
    sender: str = "",
    origin_ip: str = "",
    classification: str = "",
    status: str = "processed",
    action_taken: str = "",
    reason: str = "",
    notification_sent: bool = False,
    received_at: Optional[str] = None,
) -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO alerts (received_at, subject, sender, origin_ip, "
            "classification, status, action_taken, reason, notification_sent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                received_at or _utcnow(),
                subject,
                sender,
                origin_ip,
                classification,
                status,
                action_taken,
                reason,
                int(notification_sent),
            ),
        )
        conn.commit()


def record_firewall_action(
    *,
    ip: str = "",
    rule_name: str = "",
    result: str = "",
    duplicate: bool = False,
    allowed_list: bool = False,
    notification_sent: bool = False,
    status: str = "success",
    detail: str = "",
    occurred_at: Optional[str] = None,
) -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO firewall_actions (occurred_at, ip, rule_name, result, "
            "duplicate, allowed_list, notification_sent, status, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                occurred_at or _utcnow(),
                ip,
                rule_name,
                result,
                int(duplicate),
                int(allowed_list),
                int(notification_sent),
                status,
                detail,
            ),
        )
        conn.commit()


def record_log(
    *,
    severity: str,
    module: str,
    action: str = "",
    message: str = "",
    timestamp: Optional[str] = None,
) -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO logs (timestamp, severity, module, action, message) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp or _utcnow(), severity, module, action, message),
        )
        conn.commit()


def record_notification(*, subject: str, recipient: str, status: str) -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO notifications (sent_at, subject, recipient, status) "
            "VALUES (?, ?, ?, ?)",
            (_utcnow(), subject, recipient, status),
        )
        conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Pending blocks (retry queue for IPs that failed to block)
# ──────────────────────────────────────────────────────────────────────────────

def reserve_pending_block(ip: str, error: str) -> None:
    """Reserve *ip* for retry on the next polling cycle.

    Safe to call repeatedly for the same IP (first failure, and every
    subsequent failed retry) -- the attempt counter and last error are kept
    up to date rather than duplicating rows.
    """
    if _db_path is None:
        return
    now = _utcnow()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO pending_blocks (ip, first_failed_at, last_attempt_at, attempts, last_error) "
            "VALUES (?, ?, ?, 1, ?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "attempts = attempts + 1, last_attempt_at = excluded.last_attempt_at, "
            "last_error = excluded.last_error",
            (ip, now, now, error),
        )
        conn.commit()


def list_pending_blocks() -> list[dict[str, Any]]:
    """Return all IPs currently reserved for retry, oldest failure first."""
    if _db_path is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM pending_blocks ORDER BY first_failed_at ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def resolve_pending_block(ip: str, new_result: str, notified: bool = False) -> None:
    """Mark *ip* as resolved after a successful retry.

    Updates every alert previously recorded as ``failed`` for this IP to
    *new_result* (so Alert History, the Action Breakdown chart, and the
    Alert Volume chart all reflect the resolved outcome), clears the stale
    failure rows from ``firewall_actions`` (so the Failed Blocks KPI drops
    accordingly), and removes the retry reservation.
    """
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE alerts SET action_taken = ?, reason = ?, "
            "notification_sent = CASE WHEN ? THEN 1 ELSE notification_sent END "
            "WHERE origin_ip = ? AND action_taken = 'failed'",
            (
                new_result,
                f"Resolved on retry -- origin IP now {new_result}",
                int(notified),
                ip,
            ),
        )
        conn.execute(
            "DELETE FROM firewall_actions WHERE ip = ? AND status = 'failure'", (ip,)
        )
        conn.execute("DELETE FROM pending_blocks WHERE ip = ?", (ip,))
        conn.commit()


def sync_pending_blocks_from_alerts() -> int:
    """Reserve any ``failed`` alert whose IP isn't already queued for retry.

    Self-heals two situations: alerts that failed before the retry queue
    existed (e.g. recorded by an older version of this app), and any other
    reason an IP marked ``failed`` fell out of sync with ``pending_blocks``.
    Returns the number of IPs newly reserved.
    """
    if _db_path is None:
        return 0
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT origin_ip FROM alerts "
            "WHERE action_taken = 'failed' AND origin_ip != '' "
            "AND origin_ip NOT IN (SELECT ip FROM pending_blocks)"
        ).fetchall()
        now = _utcnow()
        for row in rows:
            conn.execute(
                "INSERT INTO pending_blocks "
                "(ip, first_failed_at, last_attempt_at, attempts, last_error) "
                "VALUES (?, ?, ?, 0, 'Recovered from historical failure') "
                "ON CONFLICT(ip) DO NOTHING",
                (row["origin_ip"], now, now),
            )
        conn.commit()
        return len(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Querying
# ──────────────────────────────────────────────────────────────────────────────

def get_stats() -> dict[str, int]:
    if _db_path is None:
        return {
            "total_emails_processed": 0,
            "attack_emails_detected": 0,
            "successful_blocks": 0,
            "failed_blocks": 0,
            "duplicate_ips": 0,
            "allowed_ips_ignored": 0,
            "firewall_rule_updates": 0,
            "total_notifications_sent": 0,
        }
    with _connect() as conn:
        total_emails = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        attacks = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE status='processed'"
        ).fetchone()["c"]
        successful_blocks = conn.execute(
            "SELECT COUNT(*) c FROM firewall_actions WHERE result='blocked' AND status='success'"
        ).fetchone()["c"]
        failed_blocks = conn.execute(
            "SELECT COUNT(*) c FROM firewall_actions WHERE status='failure'"
        ).fetchone()["c"]
        duplicates = conn.execute(
            "SELECT COUNT(*) c FROM firewall_actions WHERE result='duplicate'"
        ).fetchone()["c"]
        allowed_ignored = conn.execute(
            "SELECT COUNT(*) c FROM firewall_actions WHERE result='allowed'"
        ).fetchone()["c"]
        rule_updates = successful_blocks
        # Derived from alerts.notification_sent (not the separate `notifications`
        # audit table) so this KPI can never drift out of sync with what the
        # Alert History page actually shows -- e.g. after "Clear All" on alerts.
        notifications = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE notification_sent = 1"
        ).fetchone()["c"]
    return {
        "total_emails_processed": total_emails,
        "attack_emails_detected": attacks,
        "successful_blocks": successful_blocks,
        "failed_blocks": failed_blocks,
        "duplicate_ips": duplicates,
        "allowed_ips_ignored": allowed_ignored,
        "firewall_rule_updates": rule_updates,
        "total_notifications_sent": notifications,
    }


_ALERT_SORT_COLUMNS = {
    "received_at", "subject", "sender", "origin_ip", "classification",
    "status", "action_taken",
}
_FW_SORT_COLUMNS = {"occurred_at", "ip", "rule_name", "result", "status"}
_LOG_SORT_COLUMNS = {"timestamp", "severity", "module", "action"}


def query_alerts(
    *,
    search: str = "",
    classification: str = "",
    status: str = "",
    action_taken: str = "",
    notification_sent: Optional[bool] = None,
    sort_by: str = "received_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    if _db_path is None:
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}

    sort_by = sort_by if sort_by in _ALERT_SORT_COLUMNS else "received_at"
    sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    where = []
    params: list[Any] = []
    if search:
        where.append(
            "(subject LIKE ? OR sender LIKE ? OR origin_ip LIKE ? OR classification LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if classification:
        where.append("classification = ?")
        params.append(classification)
    if status:
        where.append("status = ?")
        params.append(status)
    if action_taken:
        where.append("action_taken = ?")
        params.append(action_taken)
    if notification_sent is not None:
        where.append("notification_sent = ?")
        params.append(int(notification_sent))

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    with _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM alerts {where_sql}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM alerts {where_sql} ORDER BY {sort_by} {sort_dir} "
            f"LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def query_firewall_actions(
    *,
    search: str = "",
    result: str = "",
    status: str = "",
    sort_by: str = "occurred_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    if _db_path is None:
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}

    sort_by = sort_by if sort_by in _FW_SORT_COLUMNS else "occurred_at"
    sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    where = []
    params: list[Any] = []
    if search:
        where.append("(ip LIKE ? OR rule_name LIKE ? OR detail LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if result:
        where.append("result = ?")
        params.append(result)
    if status:
        where.append("status = ?")
        params.append(status)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    with _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM firewall_actions {where_sql}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM firewall_actions {where_sql} ORDER BY {sort_by} {sort_dir} "
            f"LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def query_logs(
    *,
    search: str = "",
    severity: str = "",
    module: str = "",
    date_from: str = "",
    date_to: str = "",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    if _db_path is None:
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}

    sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    where = []
    params: list[Any] = []
    if search:
        where.append("(message LIKE ? OR module LIKE ? OR action LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if module:
        where.append("module = ?")
        params.append(module)
    if date_from:
        where.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        where.append("timestamp <= ?")
        params.append(date_to)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    page = max(1, page)
    page_size = max(1, min(page_size, 1000))
    offset = (page - 1) * page_size

    with _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM logs {where_sql}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM logs {where_sql} ORDER BY timestamp {sort_dir} "
            f"LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def all_rows(table: str) -> list[dict[str, Any]]:
    """Return every row from *table* (for export). *table* must be whitelisted."""
    if table not in {"alerts", "firewall_actions", "logs"}:
        raise ValueError(f"unknown export table: {table}")
    if _db_path is None:
        return []
    order_col = {"alerts": "received_at", "firewall_actions": "occurred_at", "logs": "timestamp"}[table]
    with _connect() as conn:
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY {order_col} DESC").fetchall()
    return [dict(r) for r in rows]


def clear_table(table: str) -> int:
    """Delete every row from *table*. *table* must be whitelisted.

    Clearing ``alerts`` also clears the ``notifications`` audit table, since
    every notification row is tied to an alert -- leaving it behind would
    strand orphaned records with nothing left to reference them.

    Returns the number of rows deleted. Safe no-op (returns 0) if the
    database has not been initialized.
    """
    if table not in {"alerts", "firewall_actions", "logs"}:
        raise ValueError(f"unknown table: {table}")
    if _db_path is None:
        return 0
    with _lock, _connect() as conn:
        cursor = conn.execute(f"DELETE FROM {table}")
        if table == "alerts":
            conn.execute("DELETE FROM notifications")
        conn.commit()
        return cursor.rowcount


def alerts_timeseries(days: int = 14) -> list[dict[str, Any]]:
    """Return per-day counts of alerts processed / blocked over the last *days* days."""
    if _db_path is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT substr(received_at, 1, 10) AS day, "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN action_taken='blocked' THEN 1 ELSE 0 END) AS blocked "
            "FROM alerts "
            "WHERE received_at >= datetime('now', ?) "
            "GROUP BY day ORDER BY day ASC",
            (f"-{days} days",),
        ).fetchall()
    return [dict(r) for r in rows]


def action_breakdown() -> list[dict[str, Any]]:
    if _db_path is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT action_taken AS label, COUNT(*) AS value FROM alerts "
            "WHERE action_taken != '' GROUP BY action_taken ORDER BY value DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def distinct_modules() -> list[str]:
    if _db_path is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT module FROM logs WHERE module != '' ORDER BY module"
        ).fetchall()
    return [r["module"] for r in rows]
