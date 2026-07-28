"""Thread-safe cached connectivity state for IMAP and SMTP services."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Literal

ServiceName = Literal["imap", "smtp"]

_lock = threading.Lock()
_statuses: dict[ServiceName, dict[str, Any]] = {
    "imap": {"online": None, "checked_at": None, "detail": ""},
    "smtp": {"online": None, "checked_at": None, "detail": ""},
}


def set_status(service: ServiceName, online: bool, detail: str = "") -> None:
    with _lock:
        _statuses[service] = {
            "online": online,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "detail": detail,
        }


def get_status(service: ServiceName) -> dict[str, Any]:
    with _lock:
        return dict(_statuses[service])


def reset_statuses() -> None:
    """Reset cached state; intended for isolated tests."""
    with _lock:
        for service in _statuses:
            _statuses[service] = {"online": None, "checked_at": None, "detail": ""}
