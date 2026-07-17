"""Thread-safe cache of the most recent firewall connectivity check.

Updated by the email monitor once per polling cycle, and on demand when an
admin clicks the status indicator in the dashboard topbar. Both the monitor
thread and the web server read/write this from different threads, hence the
lock.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Optional

_lock = threading.Lock()
_status: dict[str, Any] = {"online": None, "checked_at": None, "detail": ""}


def set_status(online: bool, detail: str = "") -> None:
    with _lock:
        _status["online"] = online
        _status["checked_at"] = datetime.now(timezone.utc).isoformat()
        _status["detail"] = detail


def get_status() -> dict[str, Any]:
    with _lock:
        return dict(_status)
