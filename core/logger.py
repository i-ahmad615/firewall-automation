"""Logging configuration for SecurityAlertAutomation.

Sets up a rotating file handler (UTF-8) and a console handler.
Call configure_logging() exactly once at startup.
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from . import database, event_bus
from .event_translator import translate

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_MAX_BYTES = 5_000_000
_BACKUP_COUNT = 5


class SQLiteEventHandler(logging.Handler):
    """Writes structured log rows to SQLite and publishes them for SSE."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            raw_message = record.getMessage()
            event = translate(
                level_name=record.levelname,
                module_name=record.name,
                raw_message=raw_message,
            )
            timestamp = datetime.now(timezone.utc).isoformat()
            database.record_log(
                severity=event.severity,
                module=record.name,
                action=event.category,
                message=event.message,
                timestamp=timestamp,
            )
            event_bus.publish(
                {
                    "timestamp": timestamp,
                    "severity": event.severity,
                    "category": event.category,
                    "message": event.message,
                    "success": event.success,
                }
            )
        except Exception:
            pass  # logging must never raise


def configure_logging(log_dir: str = "logs", level: str = "INFO", enable_db: bool = False) -> None:
    """Configure the root logger with console and rotating file handlers.

    Safe to call multiple times — subsequent calls are no-ops once handlers
    are already attached.

    Parameters
    ----------
    log_dir:
        Directory for app.log (created if absent).
    level:
        Logging level string, e.g. ``"INFO"``, ``"DEBUG"``.
    """
    root = logging.getLogger()
    already_configured = any(
        isinstance(h, (logging.StreamHandler, RotatingFileHandler)) for h in root.handlers
    )

    if not already_configured:
        numeric_level = getattr(logging, level, logging.INFO)
        root.setLevel(numeric_level)
        fmt = logging.Formatter(_LOG_FORMAT)

        # ── Console handler ────────────────────────────────────────────────
        # Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError).
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except AttributeError:
            pass  # Python < 3.7 or non-standard stdout

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(sh)

        # ── Rotating file handler ──────────────────────────────────────────
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "app.log")
        fh = RotatingFileHandler(
            log_file,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)

    numeric_level = getattr(logging, level, logging.INFO)
    root.setLevel(numeric_level)

    # ── SQLite + live event-stream handler ─────────────────────────────
    has_db_handler = any(isinstance(h, SQLiteEventHandler) for h in root.handlers)
    if enable_db and not has_db_handler:
        root.addHandler(SQLiteEventHandler())
