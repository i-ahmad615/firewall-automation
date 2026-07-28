"""Production-safe logging configuration for SecurityAlertAutomation."""
from __future__ import annotations

import copy
import logging
import os
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any

from . import database, event_bus
from .event_translator import translate

SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")


def _success(self: logging.Logger, message: object, *args: Any, **kwargs: Any) -> None:
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)


if not hasattr(logging.Logger, "success"):
    setattr(logging.Logger, "success", _success)

_PRODUCTION_FORMAT = "%(asctime)s  %(levelname)-8s %(category)-20s %(message)s"
_DEBUG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s %(message)s"
_MAX_BYTES = 5_000_000
_BACKUP_COUNT = 5
_CREDENTIAL_XML_RE = re.compile(
    r"(<(?:Username|Password|Token|APIKey)>).*?(</(?:Username|Password|Token|APIKey)>)",
    re.IGNORECASE | re.DOTALL,
)
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|username|user|login)\b"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_AUTH_IDENTITY_RE = re.compile(
    r"(?i)\b(authentication failed for|authenticated as)\s+[^\s,:;]+"
)


def redact_sensitive(value: object) -> str:
    """Return text with common credential representations redacted."""
    text = str(value)
    text = _CREDENTIAL_XML_RE.sub(r"\1***REDACTED***\2", text)
    text = _SECRET_PAIR_RE.sub(r"\1\2***REDACTED***", text)
    text = _AUTH_IDENTITY_RE.sub(r"\1 ***REDACTED***", text)
    return _BEARER_RE.sub("Bearer ***REDACTED***", text)


def truncate_debug(value: object, max_chars: int) -> str:
    """Redact and bound a technical message for safe debug-file storage."""
    text = redact_sensitive(value)
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]} … [truncated; {omitted} characters omitted]"


class ProductionFilter(logging.Filter):
    """Allow clean INFO+ business events and exclude technical internals."""

    def __init__(self, minimum_level: int = logging.INFO) -> None:
        super().__init__()
        self.minimum_level = minimum_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.minimum_level and not getattr(
            record, "technical", False
        )


class ExactLevelFilter(logging.Filter):
    def __init__(self, minimum: int, maximum: int | None = None) -> None:
        super().__init__()
        self.minimum = minimum
        self.maximum = maximum

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.minimum and (
            self.maximum is None or record.levelno <= self.maximum
        )


class SafeFormatter(logging.Formatter):
    """Formatter which redacts messages and can suppress stack traces."""

    def __init__(
        self,
        fmt: str,
        *,
        datefmt: str,
        max_chars: int,
        include_exception: bool,
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.max_chars = max_chars
        self.include_exception = include_exception

    def format(self, record: logging.LogRecord) -> str:
        safe = copy.copy(record)
        safe.category = getattr(record, "category", "Application")
        safe.msg = truncate_debug(record.getMessage(), self.max_chars)
        safe.args = ()
        if not self.include_exception:
            safe.exc_info = None
            safe.exc_text = None
            safe.stack_info = None
        rendered = super().format(safe)
        return redact_sensitive(rendered)


class SQLiteEventHandler(logging.Handler):
    """Store only production-safe business events for dashboard/SSE use."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            event = translate(
                level_name=record.levelname,
                module_name=record.name,
                raw_message=redact_sensitive(record.getMessage()),
                category_name=getattr(record, "category", ""),
            )
            timestamp = datetime.now(timezone.utc).isoformat()
            database.record_log(
                severity=event.severity,
                module=event.category,
                action="",
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
            pass


def _managed(handler: logging.Handler) -> logging.Handler:
    setattr(handler, "_security_automation_handler", True)
    return handler


def configure_logging(
    log_dir: str = "logs",
    level: str = "INFO",
    enable_db: bool = False,
    *,
    debug_logging: bool = False,
    debug_max_chars: int = 2000,
) -> None:
    """Configure clean production logs and optional isolated debug logs.

    Reconfiguration is deliberate: startup first installs a safe console,
    then calls this again after loading ``.env``. Managed handlers are
    replaced so the second call never duplicates an event.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_security_automation_handler", False):
            root.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except AttributeError:
        pass

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    production_level = max(logging.INFO, numeric_level)
    root.setLevel(logging.DEBUG if debug_logging else production_level)
    os.makedirs(log_dir, exist_ok=True)

    production_formatter = SafeFormatter(
        _PRODUCTION_FORMAT,
        datefmt="%b %d, %H:%M:%S",
        max_chars=debug_max_chars,
        include_exception=False,
    )
    detailed_formatter = SafeFormatter(
        _DEBUG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
        max_chars=debug_max_chars,
        include_exception=True,
    )
    production_filter = ProductionFilter(production_level)

    console = _managed(logging.StreamHandler(sys.stdout))
    console.setLevel(production_level)
    console.addFilter(production_filter)
    console.setFormatter(production_formatter)
    root.addHandler(console)

    application = _managed(RotatingFileHandler(
        os.path.join(log_dir, "application.log"),
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    ))
    application.setLevel(production_level)
    application.addFilter(production_filter)
    application.setFormatter(production_formatter)
    root.addHandler(application)

    errors = _managed(RotatingFileHandler(
        os.path.join(log_dir, "error.log"),
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    ))
    errors.setLevel(logging.ERROR)
    errors.addFilter(ExactLevelFilter(logging.ERROR))
    errors.addFilter(production_filter)
    errors.setFormatter(detailed_formatter)
    root.addHandler(errors)

    if debug_logging:
        debug_file = _managed(RotatingFileHandler(
            os.path.join(log_dir, "debug.log"),
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        ))
        debug_file.setLevel(logging.DEBUG)
        debug_file.setFormatter(detailed_formatter)
        root.addHandler(debug_file)

    if enable_db:
        dashboard = _managed(SQLiteEventHandler())
        dashboard.setLevel(production_level)
        dashboard.addFilter(production_filter)
        root.addHandler(dashboard)
