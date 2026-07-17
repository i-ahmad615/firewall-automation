"""In-process pub/sub used to stream live events to the dashboard (SSE).

Thread-safe: the monitor thread publishes events; each SSE connection in the
web server subscribes with its own queue so slow/disconnected clients never
block the publisher.
"""
from __future__ import annotations

import queue
import threading
from typing import Any, Iterator

_lock = threading.Lock()
_subscribers: list["queue.Queue[dict[str, Any]]"] = []


def publish(event: dict[str, Any]) -> None:
    with _lock:
        subscribers = list(_subscribers)
    for q in subscribers:
        try:
            q.put_nowait(event)
        except queue.Full:
            pass


def subscribe() -> "queue.Queue[dict[str, Any]]":
    q: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=500)
    with _lock:
        _subscribers.append(q)
    return q


def unsubscribe(q: "queue.Queue[dict[str, Any]]") -> None:
    with _lock:
        if q in _subscribers:
            _subscribers.remove(q)


def stream(q: "queue.Queue[dict[str, Any]]", timeout: float = 15.0) -> Iterator[dict[str, Any] | None]:
    """Yield events from *q*, yielding ``None`` on idle timeout (for SSE keep-alive)."""
    while True:
        try:
            yield q.get(timeout=timeout)
        except queue.Empty:
            yield None
