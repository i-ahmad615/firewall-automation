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
    action_taken TEXT,     -- blocked | duplicate | allowed | failed | ignored | removed
    reason TEXT,
    notification_sent INTEGER DEFAULT 0,
    alarm_id TEXT DEFAULT '',
    email_body TEXT DEFAULT '',          -- raw extracted HTML (or <pre>-wrapped plain text) body, unmodified
    parsed_data TEXT DEFAULT '',         -- JSON dict of every key/value row found in the alert email's table(s)
    validation_results TEXT DEFAULT '',  -- JSON list of {check, result, message}
    validation_decision TEXT DEFAULT '', -- approved | ignored | rejected | failed_validation
    message_id TEXT DEFAULT '',           -- RFC Message-ID; preferred catch-up identity
    imap_uid TEXT DEFAULT '',             -- IMAP UID fallback when Message-ID is absent
    imap_account TEXT DEFAULT '',
    imap_folder TEXT DEFAULT '',
    imap_uidvalidity TEXT DEFAULT '',
    processing_status TEXT DEFAULT 'not_processed',
    processing_source TEXT DEFAULT 'live_monitor', -- live_monitor | startup_catchup
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at);
CREATE INDEX IF NOT EXISTS idx_alerts_origin_ip ON alerts(origin_ip);

CREATE TABLE IF NOT EXISTS firewall_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    ip TEXT,
    rule_name TEXT,
    result TEXT,           -- blocked | duplicate | allowed | failed | unblocked | not_blocked
    duplicate INTEGER DEFAULT 0,
    allowed_list INTEGER DEFAULT 0,
    notification_sent INTEGER DEFAULT 0,
    status TEXT,           -- success | failure
    detail TEXT,
    source TEXT DEFAULT 'automatic',  -- automatic | manual
    reason TEXT DEFAULT '',
    alert_id INTEGER,                    -- links back to the originating alerts.id, when known
    request_started_at TEXT DEFAULT '',  -- when the firewall call began (occurred_at is when it concluded)
    status_code TEXT DEFAULT '',         -- SFOS status code, e.g. "200", "502" (when available)
    response_snippet TEXT DEFAULT ''     -- redacted, truncated SFOS response (never contains credentials)
);
CREATE INDEX IF NOT EXISTS idx_fw_occurred_at ON firewall_actions(occurred_at);

-- Currently-blocked IPs -- the single source of truth for the Manual IP
-- Unblock page. Populated by BOTH the automatic (email-driven) and manual
-- block paths (rule_updater.block_ip calls record_blocked_ip on every
-- successful block), so it reflects every IP actually blocked on the
-- firewall right now, regardless of how it got there.
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    host_name TEXT NOT NULL,
    reason TEXT DEFAULT '',
    source TEXT NOT NULL DEFAULT 'automatic',  -- automatic | manual
    blocked_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'blocked',    -- blocked | unblocked
    protected INTEGER NOT NULL DEFAULT 0,
    unblocked_at TEXT,
    unblock_source TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_status ON blocked_ips(status);

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
-- subsequent polling cycle until the firewall accepts them. This table is
-- the single source of truth for the retry queue -- the worker
-- (EmailMonitor._retry_pending_blocks) reads only from here, and an IP is
-- retried if and only if a row for it exists in this table.
CREATE TABLE IF NOT EXISTS pending_blocks (
    ip TEXT PRIMARY KEY,
    first_failed_at TEXT NOT NULL,
    last_attempt_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    alarm_id TEXT,
    alert_id INTEGER,
    active INTEGER NOT NULL DEFAULT 1
);

-- Append-only per-attempt retry log -- the audit-history counterpart to
-- pending_blocks' current-state row (which only keeps a running counter and
-- the most recent error). Populated alongside every reserve_pending_block/
-- record_retry_attempt/resolve_pending_block call so the Alert Details page
-- can show a full attempt-by-attempt table, not just the latest state.
CREATE TABLE IF NOT EXISTS retry_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    alert_id INTEGER,
    attempt_number INTEGER NOT NULL,
    attempted_at TEXT NOT NULL,
    status TEXT NOT NULL,       -- success | failure
    error TEXT DEFAULT '',
    source TEXT DEFAULT 'automatic'  -- automatic | manual
);
CREATE INDEX IF NOT EXISTS idx_retry_history_ip ON retry_history(ip);

-- Raw-message ingestion is separate from alert processing so a parsing or
-- firewall failure can never discard the original fetched email.
CREATE TABLE IF NOT EXISTS stored_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_identifier TEXT NOT NULL,
    folder_name TEXT NOT NULL,
    uidvalidity TEXT NOT NULL,
    imap_uid TEXT NOT NULL,
    raw_message BLOB NOT NULL,
    stored_at TEXT NOT NULL,
    processing_status TEXT NOT NULL DEFAULT 'stored',
    alert_id INTEGER,
    UNIQUE(account_identifier, folder_name, uidvalidity, imap_uid)
);
CREATE INDEX IF NOT EXISTS idx_stored_emails_alert_id ON stored_emails(alert_id);

CREATE TABLE IF NOT EXISTS imap_uid_checkpoints (
    account_identifier TEXT NOT NULL,
    folder_name TEXT NOT NULL,
    uidvalidity TEXT NOT NULL,
    last_fetched_uid INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(account_identifier, folder_name)
);
"""

# Indexes that reference columns introduced by an ALTER TABLE migration must
# be created only after those migrations have run. Keeping them in _SCHEMA
# breaks startup for an existing database because CREATE TABLE IF NOT EXISTS
# leaves the legacy table unchanged before CREATE INDEX is evaluated.
_POST_MIGRATION_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_fw_alert_id ON firewall_actions(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_message_id ON alerts(message_id);
CREATE INDEX IF NOT EXISTS idx_alerts_imap_uid ON alerts(imap_uid);
CREATE INDEX IF NOT EXISTS idx_alerts_processing_status ON alerts(processing_status);
CREATE INDEX IF NOT EXISTS idx_alerts_folder_uid ON alerts(imap_account, imap_folder, imap_uidvalidity, imap_uid);
"""

# Columns added after the initial release of each table. Applied with
# ALTER TABLE ... ADD COLUMN (idempotent, checked against PRAGMA
# table_info) so existing databases upgrade in place without losing data.
_COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "alerts": [
        ("alarm_id", "TEXT DEFAULT ''"),
        ("email_body", "TEXT DEFAULT ''"),
        ("parsed_data", "TEXT DEFAULT ''"),
        ("validation_results", "TEXT DEFAULT ''"),
        ("validation_decision", "TEXT DEFAULT ''"),
        ("message_id", "TEXT DEFAULT ''"),
        ("imap_uid", "TEXT DEFAULT ''"),
        ("imap_account", "TEXT DEFAULT ''"),
        ("imap_folder", "TEXT DEFAULT ''"),
        ("imap_uidvalidity", "TEXT DEFAULT ''"),
        ("processing_status", "TEXT DEFAULT 'not_processed'"),
        ("processing_source", "TEXT DEFAULT 'live_monitor'"),
        ("updated_at", "TEXT DEFAULT ''"),
    ],
    "pending_blocks": [
        ("alarm_id", "TEXT"),
        ("alert_id", "INTEGER"),
        ("active", "INTEGER NOT NULL DEFAULT 1"),
    ],
    "firewall_actions": [
        ("source", "TEXT DEFAULT 'automatic'"),
        ("reason", "TEXT DEFAULT ''"),
        ("alert_id", "INTEGER"),
        ("request_started_at", "TEXT DEFAULT ''"),
        ("status_code", "TEXT DEFAULT ''"),
        ("response_snippet", "TEXT DEFAULT ''"),
    ],
}


def _apply_column_migrations(conn: sqlite3.Connection) -> None:
    for table, columns in _COLUMN_MIGRATIONS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, coltype in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")


def _backfill_alert_processing_statuses(conn: sqlite3.Connection) -> None:
    """Translate pre-catch-up alert outcomes into explicit final statuses.

    Older databases only recorded broad ``status``/``action_taken`` values.
    The reason text distinguishes the important ignored cases, allowing the
    startup scan to re-evaluate old keyword misses without reopening alerts
    which already reached a safe final result.
    """
    conn.execute(
        "UPDATE alerts SET processing_status = CASE "
        "WHEN action_taken = 'blocked' THEN 'blocked_successfully' "
        "WHEN action_taken = 'duplicate' THEN 'already_blocked' "
        "WHEN action_taken = 'allowed' THEN 'allowlisted' "
        "WHEN action_taken = 'removed' THEN 'manually_resolved' "
        "WHEN action_taken = 'ignored' AND reason LIKE '%not trusted%' THEN 'untrusted_sender' "
        "WHEN action_taken = 'ignored' AND reason LIKE '%does not match%keyword%' THEN 'no_keyword_match' "
        "WHEN action_taken = 'ignored' AND reason LIKE '%No readable%body%' THEN 'partial_parse' "
        "WHEN action_taken = 'failed' AND reason LIKE '%extract%IP%' THEN 'partial_parse' "
        "WHEN action_taken = 'failed' THEN 'processing_failed' "
        "WHEN COALESCE(action_taken, '') = '' THEN 'not_processed' "
        "ELSE COALESCE(NULLIF(processing_status, ''), 'not_processed') END "
        "WHERE processing_status IS NULL OR processing_status = '' "
        "OR (processing_status = 'not_processed' AND COALESCE(action_taken, '') != '')"
    )


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
        _apply_column_migrations(conn)
        _backfill_alert_processing_statuses(conn)
        conn.executescript(_POST_MIGRATION_SCHEMA)
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
    alarm_id: str = "",
    email_body: str = "",
    parsed_data: str = "",
    validation_results: str = "",
    validation_decision: str = "",
    message_id: str = "",
    imap_uid: str = "",
    imap_account: str = "",
    imap_folder: str = "",
    imap_uidvalidity: str = "",
    processing_status: str = "not_processed",
    processing_source: str = "live_monitor",
) -> Optional[int]:
    """Insert a new alert row. Returns its id, or None if uninitialized."""
    if _db_path is None:
        return None
    now = received_at or _utcnow()
    with _lock, _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO alerts (received_at, subject, sender, origin_ip, "
            "classification, status, action_taken, reason, notification_sent, "
            "alarm_id, email_body, parsed_data, validation_results, "
            "validation_decision, message_id, imap_uid, imap_account, imap_folder, "
            "imap_uidvalidity, processing_status, processing_source, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                now,
                subject,
                sender,
                origin_ip,
                classification,
                status,
                action_taken,
                reason,
                int(notification_sent),
                alarm_id,
                email_body,
                parsed_data,
                validation_results,
                validation_decision,
                message_id,
                imap_uid,
                imap_account,
                imap_folder,
                imap_uidvalidity,
                processing_status,
                processing_source,
                now,
            ),
        )
        conn.commit()
        return cursor.lastrowid


_ALERT_UPDATE_FIELDS = frozenset({
    "subject", "sender", "origin_ip", "classification", "status",
    "action_taken", "reason", "notification_sent", "alarm_id",
    "email_body", "parsed_data", "validation_results",
    "validation_decision", "message_id", "imap_uid",
    "imap_account", "imap_folder", "imap_uidvalidity",
    "processing_status", "processing_source",
})


def update_alert(alert_id: int, **values: Any) -> bool:
    """Update mutable processing fields while preserving ``received_at``."""
    if _db_path is None:
        return False
    fields = {key: value for key, value in values.items() if key in _ALERT_UPDATE_FIELDS}
    if not fields:
        return False
    if "notification_sent" in fields:
        fields["notification_sent"] = int(bool(fields["notification_sent"]))
    fields["updated_at"] = _utcnow()
    assignments = ", ".join(f"{name} = ?" for name in fields)
    with _lock, _connect() as conn:
        cursor = conn.execute(
            f"UPDATE alerts SET {assignments} WHERE id = ?",
            (*fields.values(), alert_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def find_alert_by_message_identity(
    message_id: str,
    imap_uid: str,
    imap_folder: str = "",
    imap_account: str = "",
    imap_uidvalidity: str = "",
) -> Optional[dict[str, Any]]:
    """Find one alert using Message-ID first and UID only as its fallback."""
    if _db_path is None:
        return None
    with _connect() as conn:
        if message_id:
            row = conn.execute(
                "SELECT * FROM alerts WHERE message_id = ? ORDER BY id DESC LIMIT 1",
                (message_id,),
            ).fetchone()
        elif imap_uid and imap_folder:
            clauses = ["imap_uid = ?", "imap_folder = ?"]
            values: list[Any] = [imap_uid, imap_folder]
            if imap_account:
                clauses.append("imap_account = ?")
                values.append(imap_account)
            if imap_uidvalidity:
                clauses.append("imap_uidvalidity = ?")
                values.append(imap_uidvalidity)
            row = conn.execute(
                "SELECT * FROM alerts WHERE " + " AND ".join(clauses)
                + " ORDER BY id DESC LIMIT 1",
                values,
            ).fetchone()
        elif imap_uid:
            row = conn.execute(
                "SELECT * FROM alerts WHERE imap_uid = ? ORDER BY id DESC LIMIT 1",
                (imap_uid,),
            ).fetchone()
        else:
            row = None
    return dict(row) if row else None


def get_uid_checkpoint(account_identifier: str, folder_name: str) -> Optional[dict[str, Any]]:
    if _db_path is None:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM imap_uid_checkpoints "
            "WHERE account_identifier = ? AND folder_name = ?",
            (account_identifier, folder_name),
        ).fetchone()
    return dict(row) if row else None


def reset_uid_checkpoint(
    account_identifier: str, folder_name: str, uidvalidity: str
) -> None:
    if _db_path is None:
        return
    now = _utcnow()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO imap_uid_checkpoints "
            "(account_identifier, folder_name, uidvalidity, last_fetched_uid, updated_at) "
            "VALUES (?, ?, ?, 0, ?) "
            "ON CONFLICT(account_identifier, folder_name) DO UPDATE SET "
            "uidvalidity = excluded.uidvalidity, last_fetched_uid = 0, "
            "updated_at = excluded.updated_at",
            (account_identifier, folder_name, uidvalidity, now),
        )
        conn.commit()


def advance_uid_checkpoint(
    account_identifier: str,
    folder_name: str,
    uidvalidity: str,
    uid: int,
) -> None:
    """Advance only within the current UIDVALIDITY generation."""
    if _db_path is None:
        return
    now = _utcnow()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO imap_uid_checkpoints "
            "(account_identifier, folder_name, uidvalidity, last_fetched_uid, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(account_identifier, folder_name) DO UPDATE SET "
            "last_fetched_uid = CASE "
            "WHEN imap_uid_checkpoints.uidvalidity = excluded.uidvalidity "
            "THEN MAX(imap_uid_checkpoints.last_fetched_uid, excluded.last_fetched_uid) "
            "ELSE excluded.last_fetched_uid END, "
            "uidvalidity = excluded.uidvalidity, updated_at = excluded.updated_at",
            (account_identifier, folder_name, uidvalidity, uid, now),
        )
        conn.commit()


def store_fetched_email(
    account_identifier: str,
    folder_name: str,
    uidvalidity: str,
    imap_uid: str,
    raw_message: bytes,
) -> tuple[Optional[int], bool]:
    """Durably store raw mail before processing; return ``(id, inserted)``."""
    if _db_path is None:
        return None, True
    now = _utcnow()
    with _lock, _connect() as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO stored_emails "
            "(account_identifier, folder_name, uidvalidity, imap_uid, raw_message, stored_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (account_identifier, folder_name, uidvalidity, imap_uid, raw_message, now),
        )
        inserted = cursor.rowcount > 0
        row = conn.execute(
            "SELECT id FROM stored_emails WHERE account_identifier = ? "
            "AND folder_name = ? AND uidvalidity = ? AND imap_uid = ?",
            (account_identifier, folder_name, uidvalidity, imap_uid),
        ).fetchone()
        conn.commit()
    return (int(row["id"]) if row else None), inserted


def update_stored_email(
    stored_email_id: Optional[int], *, processing_status: str, alert_id: Optional[int] = None
) -> None:
    if _db_path is None or stored_email_id is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE stored_emails SET processing_status = ?, "
            "alert_id = COALESCE(?, alert_id) WHERE id = ?",
            (processing_status, alert_id, stored_email_id),
        )
        conn.commit()


def get_stored_email(stored_email_id: int) -> Optional[dict[str, Any]]:
    if _db_path is None:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM stored_emails WHERE id = ?", (stored_email_id,)
        ).fetchone()
    return dict(row) if row else None


def find_legacy_alert(
    *,
    subject: str,
    sender: str,
    alarm_id: str = "",
    email_body: str = "",
) -> Optional[dict[str, Any]]:
    """Best-effort match for rows created before Message-ID/UID were stored."""
    if _db_path is None:
        return None
    with _connect() as conn:
        if email_body:
            row = conn.execute(
                "SELECT * FROM alerts WHERE COALESCE(message_id, '') = '' "
                "AND COALESCE(imap_uid, '') = '' AND email_body = ? "
                "AND lower(sender) = lower(?) ORDER BY id DESC LIMIT 1",
                (email_body, sender),
            ).fetchone()
        else:
            row = None
        if row is None and alarm_id:
            row = conn.execute(
                "SELECT * FROM alerts WHERE COALESCE(message_id, '') = '' "
                "AND COALESCE(imap_uid, '') = '' AND alarm_id = ? "
                "AND lower(sender) = lower(?) ORDER BY id DESC LIMIT 1",
                (alarm_id, sender),
            ).fetchone()
        elif row is None:
            row = conn.execute(
                "SELECT * FROM alerts WHERE COALESCE(message_id, '') = '' "
                "AND COALESCE(imap_uid, '') = '' AND subject = ? "
                "AND lower(sender) = lower(?) ORDER BY id DESC LIMIT 1",
                (subject, sender),
            ).fetchone()
    return dict(row) if row else None


def get_alert(alert_id: int) -> Optional[dict[str, Any]]:
    """Return the alert row for *alert_id*, or None if it doesn't exist."""
    if _db_path is None:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def get_ip_alert_stats(ip: str) -> dict[str, Any]:
    """Return {first_seen, last_seen, count} across every alert for *ip*."""
    if _db_path is None or not ip:
        return {"first_seen": None, "last_seen": None, "count": 0}
    with _connect() as conn:
        row = conn.execute(
            "SELECT MIN(received_at) AS first_seen, MAX(received_at) AS last_seen, "
            "COUNT(*) AS count FROM alerts WHERE origin_ip = ?",
            (ip,),
        ).fetchone()
    return dict(row) if row else {"first_seen": None, "last_seen": None, "count": 0}


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
    source: str = "automatic",
    reason: str = "",
    alert_id: Optional[int] = None,
    request_started_at: str = "",
    status_code: str = "",
    response_snippet: str = "",
) -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO firewall_actions (occurred_at, ip, rule_name, result, "
            "duplicate, allowed_list, notification_sent, status, detail, source, "
            "reason, alert_id, request_started_at, status_code, response_snippet) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                source,
                reason,
                alert_id,
                request_started_at,
                status_code,
                response_snippet,
            ),
        )
        conn.commit()


def list_firewall_actions_for_ip(ip: str) -> list[dict[str, Any]]:
    """Return every firewall_actions row for *ip*, oldest first."""
    if _db_path is None or not ip:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM firewall_actions WHERE ip = ? ORDER BY occurred_at ASC", (ip,)
        ).fetchall()
    return [dict(r) for r in rows]


def list_firewall_actions_for_alert(alert_id: int, ip: str = "") -> list[dict[str, Any]]:
    """Return actions linked to an alert plus legacy unlinked actions for its IP."""
    if _db_path is None:
        return []
    with _connect() as conn:
        if ip:
            rows = conn.execute(
                "SELECT * FROM firewall_actions WHERE alert_id = ? "
                "OR (alert_id IS NULL AND ip = ?) ORDER BY occurred_at ASC, id ASC",
                (alert_id, ip),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM firewall_actions WHERE alert_id = ? "
                "ORDER BY occurred_at ASC, id ASC",
                (alert_id,),
            ).fetchall()
    return [dict(r) for r in rows]


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
# Currently-blocked IPs -- single source of truth for the Manual IP Unblock
# page. `record_blocked_ip` is called from rule_updater.block_ip() on every
# successful block (both automatic and manual), so this reflects every IP
# actually blocked on the firewall, not just manually-blocked ones.
# ──────────────────────────────────────────────────────────────────────────────

def record_blocked_ip(
    ip: str, host_name: str, *, reason: str = "", source: str = "automatic"
) -> None:
    """Upsert *ip* as currently blocked. Safe to call repeatedly (e.g. a
    duplicate-detected re-block just refreshes the row)."""
    if _db_path is None:
        return
    now = _utcnow()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO blocked_ips (ip, host_name, reason, source, blocked_at, status) "
            "VALUES (?, ?, ?, ?, ?, 'blocked') "
            "ON CONFLICT(ip) DO UPDATE SET "
            "host_name = excluded.host_name, status = 'blocked', "
            "blocked_at = excluded.blocked_at, source = excluded.source, "
            "reason = CASE WHEN excluded.reason != '' THEN excluded.reason "
            "ELSE blocked_ips.reason END, "
            "unblocked_at = NULL, unblock_source = NULL",
            (ip, host_name, reason, source, now),
        )
        conn.commit()


def get_blocked_ip(ip: str) -> Optional[dict[str, Any]]:
    """Return the blocked_ips row for *ip*, or None if it has no row at all."""
    if _db_path is None:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT * FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def mark_ip_unblocked(ip: str, *, source: str = "manual") -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE blocked_ips SET status = 'unblocked', unblocked_at = ?, "
            "unblock_source = ? WHERE ip = ?",
            (_utcnow(), source, ip),
        )
        conn.commit()


def set_ip_protected(ip: str, protected: bool) -> bool:
    """Set/clear the protected flag for a tracked IP. Returns True if a row
    was updated, False if *ip* has no blocked_ips row."""
    if _db_path is None:
        return False
    with _lock, _connect() as conn:
        cursor = conn.execute(
            "UPDATE blocked_ips SET protected = ? WHERE ip = ?", (int(protected), ip)
        )
        conn.commit()
        return cursor.rowcount > 0


def find_blocked_ips_missing_from_table() -> list[str]:
    """Return distinct IPs with a successful 'blocked' firewall_actions row
    but no corresponding blocked_ips row -- used once at startup to backfill
    IPs that were already blocked before this table existed."""
    if _db_path is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT ip FROM firewall_actions "
            "WHERE result = 'blocked' AND status = 'success' AND ip != '' "
            "AND ip NOT IN (SELECT ip FROM blocked_ips)"
        ).fetchall()
    return [r["ip"] for r in rows]


_BLOCKED_IPS_SORT_COLUMNS = {
    "ip", "host_name", "reason", "source", "blocked_at", "status",
}


def query_blocked_ips(
    *,
    search: str = "",
    status: str = "blocked",
    sort_by: str = "blocked_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    if _db_path is None:
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}

    sort_by = sort_by if sort_by in _BLOCKED_IPS_SORT_COLUMNS else "blocked_at"
    sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    where = []
    params: list[Any] = []
    if search:
        where.append("(ip LIKE ? OR host_name LIKE ? OR reason LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if status:
        where.append("status = ?")
        params.append(status)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    with _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM blocked_ips {where_sql}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM blocked_ips {where_sql} ORDER BY {sort_by} {sort_dir} "
            f"LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Pending blocks (retry queue for IPs that failed to block)
#
# `pending_blocks` is the ONLY place retry jobs live. The worker
# (EmailMonitor._retry_pending_blocks) reads exclusively from
# list_pending_blocks()/query_pending_blocks(); an IP is retried if and only
# if a row for it exists here. Cancelling a job (cancel_pending_block) also
# flips its originating `alerts` row away from action_taken='failed' so
# sync_pending_blocks_from_alerts() can never resurrect it -- the worker will
# only reserve that IP again for a genuinely new alert.
# ──────────────────────────────────────────────────────────────────────────────

# In-memory only -- tracks which IPs are mid-retry *right now* so the UI can
# show "Retrying" vs "Pending". This is transient worker status, not retry
# job data: it holds no attempts/errors/schedule and is safe to lose on
# restart (rows simply show "Pending" again, which is correct).
_retrying_ips: set[str] = set()


def mark_retrying(ip: str) -> None:
    with _lock:
        _retrying_ips.add(ip)


def clear_retrying(ip: str) -> None:
    with _lock:
        _retrying_ips.discard(ip)


def _pending_status(ip: str) -> str:
    return "retrying" if ip in _retrying_ips else "pending"


def reserve_pending_block(
    ip: str, error: str, alarm_id: Optional[str] = None, alert_id: Optional[int] = None
) -> None:
    """Reserve *ip* for retry on the next polling cycle.

    Used only for a *new* failure (first attempt on a fresh alert, or the
    historical self-heal path) -- it inserts a row if one doesn't already
    exist. Existing `alarm_id`/`alert_id` are preserved unless a new
    non-null value is supplied.
    """
    if _db_path is None:
        return
    now = _utcnow()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO pending_blocks (ip, first_failed_at, last_attempt_at, attempts, last_error, alarm_id, alert_id) "
            "VALUES (?, ?, ?, 1, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "attempts = attempts + 1, last_attempt_at = excluded.last_attempt_at, "
            "last_error = excluded.last_error, active = 1, "
            "alarm_id = CASE WHEN excluded.alarm_id IS NOT NULL AND excluded.alarm_id != '' "
            "THEN excluded.alarm_id ELSE pending_blocks.alarm_id END, "
            "alert_id = CASE WHEN excluded.alert_id IS NOT NULL "
            "THEN excluded.alert_id ELSE pending_blocks.alert_id END",
            (ip, now, now, error, alarm_id, alert_id),
        )
        conn.commit()


def get_pending_block(ip: str) -> Optional[dict[str, Any]]:
    """Return the pending_blocks row for *ip*, or None if not queued."""
    if _db_path is None:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT * FROM pending_blocks WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return None
    entry = dict(row)
    entry["active"] = bool(entry.get("active", 1))
    entry["status"] = _pending_status(entry["ip"]) if entry["active"] else "paused"
    return entry


def record_retry_attempt(ip: str, error: str) -> None:
    """Record a failed retry for *ip* that is already in the queue.

    Unlike reserve_pending_block, this NEVER inserts a new row. If *ip* was
    removed from the queue (e.g. an administrator cancelled it) while this
    retry was in flight, the UPDATE simply affects 0 rows instead of
    resurrecting the cancelled entry -- closing the race between the
    background worker and a manual removal.
    """
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE pending_blocks SET attempts = attempts + 1, "
            "last_attempt_at = ?, last_error = ? WHERE ip = ?",
            (_utcnow(), error, ip),
        )
        conn.commit()


def cancel_pending_block(ip: str) -> bool:
    """Permanently cancel the retry job for *ip*.

    Removes it from the retry queue and marks any 'failed' alert rows for
    this IP as 'removed' so sync_pending_blocks_from_alerts() cannot
    resurrect it. A brand new alert for the same IP that later fails will
    reserve it again through the normal first-failure path, independent of
    this cancellation.

    Returns True if a queued entry was removed, False if the IP wasn't queued.
    """
    if _db_path is None:
        return False
    with _lock, _connect() as conn:
        cursor = conn.execute("DELETE FROM pending_blocks WHERE ip = ?", (ip,))
        removed = cursor.rowcount > 0
        conn.execute(
            "UPDATE alerts SET action_taken = 'removed', "
            "processing_status = 'manually_resolved', "
            "reason = 'Retry cancelled by administrator', updated_at = ? "
            "WHERE origin_ip = ? AND action_taken = 'failed'",
            (_utcnow(), ip),
        )
        conn.commit()
    clear_retrying(ip)
    return removed


def stop_pending_block(ip: str) -> bool:
    """Stop automatic retries while retaining the failed-queue audit record."""
    if _db_path is None:
        return False
    with _lock, _connect() as conn:
        cursor = conn.execute(
            "UPDATE pending_blocks SET active = 0 WHERE ip = ? AND active != 0", (ip,)
        )
        conn.commit()
    clear_retrying(ip)
    return cursor.rowcount > 0


def resume_pending_block(ip: str) -> bool:
    """Resume automatic retries for a paused failed-queue entry."""
    if _db_path is None:
        return False
    with _lock, _connect() as conn:
        cursor = conn.execute(
            "UPDATE pending_blocks SET active = 1 WHERE ip = ? AND active = 0", (ip,)
        )
        conn.commit()
    return cursor.rowcount > 0


def list_pending_blocks() -> list[dict[str, Any]]:
    """Return all IPs currently reserved for retry, oldest failure first."""
    if _db_path is None:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM pending_blocks WHERE active != 0 ORDER BY first_failed_at ASC"
        ).fetchall()
    entries = [dict(r) for r in rows]
    for entry in entries:
        entry["active"] = True
        entry["status"] = _pending_status(entry["ip"])
    return entries


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
            "processing_status = CASE ? "
            "WHEN 'blocked' THEN 'blocked_successfully' "
            "WHEN 'duplicate' THEN 'already_blocked' "
            "WHEN 'allowed' THEN 'allowlisted' "
            "ELSE processing_status END, "
            "notification_sent = CASE WHEN ? THEN 1 ELSE notification_sent END, "
            "updated_at = ? "
            "WHERE origin_ip = ? AND action_taken = 'failed'",
            (
                new_result,
                f"Resolved on retry -- origin IP now {new_result}",
                new_result,
                int(notified),
                _utcnow(),
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
            "SELECT a.id AS alert_id, a.origin_ip AS origin_ip, a.alarm_id AS alarm_id FROM alerts a "
            "INNER JOIN ("
            "  SELECT origin_ip, MAX(id) AS max_id FROM alerts "
            "  WHERE action_taken = 'failed' AND processing_status = 'processing_failed' "
            "  AND origin_ip != '' GROUP BY origin_ip"
            ") latest ON a.id = latest.max_id "
            "WHERE a.origin_ip NOT IN (SELECT ip FROM pending_blocks)"
        ).fetchall()
        now = _utcnow()
        for row in rows:
            conn.execute(
                "INSERT INTO pending_blocks "
                "(ip, first_failed_at, last_attempt_at, attempts, last_error, alarm_id, alert_id) "
                "VALUES (?, ?, ?, 0, 'Recovered from historical failure', ?, ?) "
                "ON CONFLICT(ip) DO NOTHING",
                (row["origin_ip"], now, now, row["alarm_id"], row["alert_id"]),
            )
        conn.commit()
        return len(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Retry history (append-only per-attempt audit log)
# ──────────────────────────────────────────────────────────────────────────────

def record_retry_history(
    ip: str,
    attempt_number: int,
    status: str,
    *,
    error: str = "",
    alert_id: Optional[int] = None,
    source: str = "automatic",
) -> None:
    if _db_path is None:
        return
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO retry_history (ip, alert_id, attempt_number, attempted_at, "
            "status, error, source) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ip, alert_id, attempt_number, _utcnow(), status, error, source),
        )
        conn.commit()


def list_retry_history(ip: str) -> list[dict[str, Any]]:
    """Return every retry attempt for *ip*, oldest first."""
    if _db_path is None or not ip:
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM retry_history WHERE ip = ? ORDER BY attempt_number ASC, id ASC",
            (ip,),
        ).fetchall()
    return [dict(r) for r in rows]


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
        # Unique IPs currently in the retry queue -- NOT every failed attempt.
        # `ip` is the pending_blocks primary key, so this is inherently a
        # distinct count (one IP retried 10 times still counts as 1).
        failed_blocks = conn.execute(
            "SELECT COUNT(*) c FROM pending_blocks"
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


_PENDING_SORT_COLUMNS = {
    "ip", "alarm_id", "attempts", "first_failed_at", "last_attempt_at",
}


def query_pending_blocks(
    *,
    search: str = "",
    sort_by: str = "last_attempt_at",
    sort_dir: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    if _db_path is None:
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}

    sort_by = sort_by if sort_by in _PENDING_SORT_COLUMNS else "last_attempt_at"
    sort_dir = "ASC" if sort_dir.lower() == "asc" else "DESC"

    where = []
    params: list[Any] = []
    if search:
        where.append("(ip LIKE ? OR alarm_id LIKE ? OR last_error LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    with _connect() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) c FROM pending_blocks {where_sql}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM pending_blocks {where_sql} ORDER BY {sort_by} {sort_dir} "
            f"LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()

    entries = [dict(r) for r in rows]
    for entry in entries:
        entry["active"] = bool(entry.get("active", 1))
        entry["status"] = _pending_status(entry["ip"]) if entry["active"] else "paused"

    return {
        "rows": entries,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


_ALERT_SORT_COLUMNS = {
    "received_at", "subject", "sender", "origin_ip", "classification",
    "status", "action_taken",
}
_FW_SORT_COLUMNS = {"occurred_at", "ip", "rule_name", "result", "status"}
_LOG_SORT_COLUMNS = {"timestamp", "severity", "module", "action"}

_LOG_CATEGORY_MAP = {
    "core.email_client": "Email Service",
    "core.email_monitor": "Alert Processing",
    "core.email_connectivity_monitor": "Connectivity",
    "core.firewall_client": "Firewall Action",
    "core.firewall_monitor": "Connectivity",
    "core.rule_updater": "Firewall Action",
    "core.xml_handler": "Firewall Action",
    "core.manual_actions": "Firewall Action",
    "Email": "Email Service",
    "Firewall API": "Firewall Action",
    "Firewall Rule": "Firewall Action",
    "Firewall Connectivity": "Connectivity",
    "Manual Action": "Firewall Action",
    "Configuration": "Application",
    "Dashboard": "Application",
}

_LEGACY_LOG_NOISE_SQL = (
    "severity != 'DEBUG'",
    "message NOT LIKE '%SFOS >>%'",
    "message NOT LIKE '%SFOS <<%'",
    "message NOT LIKE '%<Request %'",
    "message NOT LIKE '%<Response%'",
    "message NOT LIKE '%IMAP SEARCH%'",
    "message NOT LIKE '%EXISTS=%'",
    "message NOT LIKE '%no unread messages%'",
    "message NOT LIKE '%Cycle complete%'",
    "message NOT LIKE '%SourceNetworks%'",
    "message NOT LIKE '%XML being uploaded%'",
)


def _clean_dashboard_log_row(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    old_category = result.get("action") or result.get("module") or "Application"
    result["module"] = _LOG_CATEGORY_MAP.get(old_category, old_category)
    if "." in result["module"]:
        result["module"] = _LOG_CATEGORY_MAP.get(result["module"], "Application")
    result["action"] = ""
    return result


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

    where = list(_LEGACY_LOG_NOISE_SQL)
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
        "rows": [_clean_dashboard_log_row(r) for r in rows],
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


def delete_rows_by_ids(table: str, ids: list[int]) -> int:
    """Delete selected rows from a supported history table by primary key."""
    if table not in {"alerts", "firewall_actions"}:
        raise ValueError(f"unknown table: {table}")
    if _db_path is None:
        return 0

    normalized_ids = sorted({row_id for row_id in ids if isinstance(row_id, int) and row_id > 0})
    if not normalized_ids:
        return 0

    deleted = 0
    with _lock, _connect() as conn:
        for start in range(0, len(normalized_ids), 500):
            batch = normalized_ids[start:start + 500]
            placeholders = ",".join("?" for _ in batch)
            cursor = conn.execute(
                f"DELETE FROM {table} WHERE id IN ({placeholders})", batch
            )
            deleted += cursor.rowcount
        conn.commit()
    return deleted


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
    return sorted({
        _LOG_CATEGORY_MAP.get(r["module"], "Application" if "." in r["module"] else r["module"])
        for r in rows
    })
