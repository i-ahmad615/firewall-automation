"""Safe, reusable production messages for firewall failures."""
from __future__ import annotations

from typing import Iterator, Optional

import requests


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    current: Optional[BaseException] = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def firewall_exception_message(exc: BaseException, timeout: int = 30) -> str:
    """Translate a technical firewall exception into a safe production message."""
    chain = tuple(_exception_chain(exc))

    if any(isinstance(item, requests.exceptions.ConnectTimeout) for item in chain):
        return f"Firewall connection timed out after {timeout} seconds"
    if any(isinstance(item, requests.exceptions.ReadTimeout) for item in chain):
        return f"Firewall did not respond within {timeout} seconds"
    if any(isinstance(item, requests.exceptions.SSLError) for item in chain):
        return "Secure connection to the firewall failed"
    if any(isinstance(item, requests.exceptions.ConnectionError) for item in chain):
        return "Firewall is currently unreachable"

    status_code: Optional[int] = None
    for item in chain:
        response = getattr(item, "response", None)
        candidate = getattr(response, "status_code", None)
        if candidate is None:
            candidate = getattr(item, "code", None)
        try:
            if candidate not in (None, ""):
                status_code = int(candidate)
                break
        except (TypeError, ValueError):
            continue
    if status_code in (401, 403):
        return "Firewall authentication failed"
    if status_code is not None:
        return f"Firewall API returned HTTP {status_code}"
    return "Firewall request failed unexpectedly"
