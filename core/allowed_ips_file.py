"""Read/write access to the allowed-IP allow list (``config/allowed_ips.txt``).

The file format is unchanged from :func:`core.config.load_allowed_ips`:
one IP per line, ``#``-prefixed comment lines and blank lines are ignored.
Comments and ordering are preserved on write -- only IP entries are
added/removed.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path


class InvalidIPError(Exception):
    """Raised when a supplied value is not a valid IPv4/IPv6 address."""


def _validate_ip(ip: str) -> str:
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise InvalidIPError(f"{ip!r} is not a valid IP address") from exc
    return ip


def list_ips(path: str) -> list[str]:
    """Return the ordered list of active (non-comment) IP entries."""
    p = Path(path)
    if not p.exists():
        return []
    ips = []
    for line in p.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            ips.append(stripped)
    return ips


def add_ip(path: str, ip: str) -> bool:
    """Append *ip* to the file. Returns False if it was already present.

    Raises
    ------
    InvalidIPError
        If *ip* is not a valid IPv4/IPv6 address.
    """
    ip = _validate_ip(ip)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    existing_lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    if ip in list_ips(path):
        return False

    lines = list(existing_lines)
    if lines and lines[-1].strip() != "":
        lines.append(ip)
    else:
        # Replace a single trailing blank line (if any) rather than stacking blanks
        while lines and lines[-1].strip() == "":
            lines.pop()
        lines.append(ip)

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def remove_ip(path: str, ip: str) -> bool:
    """Remove *ip* from the file. Returns False if it wasn't present."""
    ip = ip.strip()
    p = Path(path)
    if not p.exists():
        return False

    lines = p.read_text(encoding="utf-8").splitlines()
    new_lines = [line for line in lines if line.strip() != ip]
    if len(new_lines) == len(lines):
        return False

    p.write_text("\n".join(new_lines) + ("\n" if new_lines else ""), encoding="utf-8")
    return True
