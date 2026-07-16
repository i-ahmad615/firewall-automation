"""Logging configuration for SecurityAlertAutomation.

Sets up a rotating file handler (UTF-8) and a console handler.
Call configure_logging() exactly once at startup.
"""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_MAX_BYTES = 5_000_000
_BACKUP_COUNT = 5


def configure_logging(log_dir: str = "logs", level: str = "INFO") -> None:
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
    if root.handlers:
        return  # already configured

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
