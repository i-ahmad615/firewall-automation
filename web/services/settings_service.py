"""Settings page service: load/save `.env` values through structured forms.

Passwords are masked when rendered to the browser; a masked value submitted
back unchanged is not overwritten, so credentials are never round-tripped
through the client in plaintext.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.config import parse_trusted_senders
from core.env_file import read_env_pairs, write_env_pairs

_ENV_PATH = str(Path(__file__).resolve().parents[2] / ".env")
MASK = "********"
# Legacy singular env var, still read for display/migration -- see
# core.config.load_config() for the matching backward-compat fallback.
_LEGACY_TRUSTED_SENDER_KEY = "TRUSTED_SENDER"

# (section, key, field_type, is_secret)
_FIELDS: list[tuple[str, str, str, bool]] = [
    # IMAP
    ("imap", "IMAP_HOST", "text", False),
    ("imap", "IMAP_PORT", "number", False),
    ("imap", "IMAP_USE_SSL", "bool", False),
    ("imap", "IMAP_USE_STARTTLS", "bool", False),
    ("imap", "IMAP_MAILBOX", "text", False),
    ("imap", "IMAP_TIMEOUT", "number", False),
    ("imap", "EMAIL_USERNAME", "text", False),
    ("imap", "EMAIL_PASSWORD", "password", True),
    ("imap", "IMAP_POLL_INTERVAL", "number", False),
    ("imap", "IMAP_STARTUP_EMAIL_LIMIT", "number", False),
    ("imap", "TRUSTED_SENDERS", "text", False),
    ("imap", "ALERT_KEYWORDS", "text", False),
    # SMTP
    ("smtp", "SMTP_HOST", "text", False),
    ("smtp", "SMTP_PORT", "number", False),
    ("smtp", "SMTP_USE_SSL", "bool", False),
    ("smtp", "SMTP_USE_TLS", "bool", False),
    ("smtp", "SMTP_USERNAME", "text", False),
    ("smtp", "SMTP_PASSWORD", "password", True),
    ("smtp", "SMTP_FROM", "text", False),
    ("smtp", "NOTIFICATION_EMAIL", "text", False),
    # Firewall
    ("firewall", "FIREWALL_HOST", "text", False),
    ("firewall", "FIREWALL_PORT", "number", False),
    ("firewall", "FIREWALL_USERNAME", "text", False),
    ("firewall", "FIREWALL_PASSWORD", "password", True),
    ("firewall", "FIREWALL_RULE_NAME", "text", False),
    ("firewall", "FIREWALL_PING_INTERVAL", "number", False),
    # Application
    ("application", "DASHBOARD_HOST", "text", False),
    ("application", "DASHBOARD_PORT", "number", False),
    ("application", "DASHBOARD_AUTO_OPEN_BROWSER", "bool", False),
    ("application", "DASHBOARD_ADMIN_USERNAME", "text", False),
    ("application", "DASHBOARD_ADMIN_PASSWORD", "password", True),
]

# Effective defaults applied by core.config.load_config() when a key is
# absent from .env. Shown in the form (instead of a blank field) so an
# administrator can see the value actually in effect, and so an accidental
# blank submission never overwrites a working default with an empty string.
_DEFAULTS: dict[str, str] = {
    "IMAP_MAILBOX": "INBOX",
    "IMAP_TIMEOUT": "30",
    "IMAP_POLL_INTERVAL": "60",
    "IMAP_STARTUP_EMAIL_LIMIT": "10",
    "FIREWALL_PING_INTERVAL": "60",
    "SMTP_TIMEOUT": "30",
    "DASHBOARD_HOST": "0.0.0.0",
    "DASHBOARD_PORT": "5000",
    "DASHBOARD_ADMIN_USERNAME": "admin",
}

# Extra guidance shown under specific fields in the form.
_HINTS: dict[str, str] = {
    "IMAP_STARTUP_EMAIL_LIMIT": (
        "Latest emails checked in each configured folder when the application starts."
    ),
    "TRUSTED_SENDERS": (
        "Comma-separated list of trusted sender email addresses, e.g. "
        "soc@company.com, alerts@company.com"
    ),
    "DASHBOARD_HOST": (
        "Use 0.0.0.0 to make the dashboard available to other devices on "
        "the same network."
    ),
}

_LABELS: dict[str, str] = {
    "IMAP_STARTUP_EMAIL_LIMIT": "Startup Email Limit",
}


def load_settings() -> dict[str, dict[str, Any]]:
    """Return settings grouped by section, with secrets masked."""
    current = read_env_pairs(_ENV_PATH)
    sections: dict[str, dict[str, Any]] = {
        "imap": {}, "smtp": {}, "firewall": {}, "application": {},
    }
    for section, key, field_type, is_secret in _FIELDS:
        if key == "TRUSTED_SENDERS":
            # Fall back to the legacy singular var for display so an
            # existing .env that only has TRUSTED_SENDER still shows its
            # current value here instead of an empty field.
            raw_value = (
                current.get("TRUSTED_SENDERS", "")
                or current.get(_LEGACY_TRUSTED_SENDER_KEY, "")
                or _DEFAULTS.get(key, "")
            )
        else:
            raw_value = current.get(key, "") or _DEFAULTS.get(key, "")
        display_value = MASK if (is_secret and raw_value) else raw_value
        sections[section][key] = {
            "value": display_value,
            "type": field_type,
            "is_secret": is_secret,
            "choices": None,
            "hint": _HINTS.get(key),
            "label": _LABELS.get(key, key.replace("_", " ").title()),
        }
    return sections


def save_settings(form: dict[str, str]) -> list[str]:
    """Persist submitted *form* values back to .env.

    Fields left as the mask placeholder are skipped (secret unchanged).
    Returns a list of human-readable validation errors (empty if none).
    """
    errors: list[str] = []
    updates: dict[str, str] = {}

    for section, key, field_type, is_secret in _FIELDS:
        if key not in form:
            if field_type == "bool":
                updates[key] = "false"
            continue
        value = form[key].strip()
        if is_secret and value == MASK:
            continue
        if field_type == "bool":
            updates[key] = "true" if value.lower() in ("true", "on", "1", "yes") else "false"
            continue
        if not value:
            # Blank submission: leave the existing .env value (or built-in
            # default) untouched rather than writing an empty override that
            # would defeat core.config's fallback defaults. Secret fields are
            # the one exception -- an explicit blank (not the mask) clears
            # a credential on purpose, e.g. to disable dashboard auth.
            if is_secret:
                updates[key] = value
            continue
        if key == "TRUSTED_SENDERS":
            try:
                parse_trusted_senders(value, required=False)
            except EnvironmentError as exc:
                errors.append(str(exc))
                continue
            updates[key] = value
            continue
        if field_type == "number":
            try:
                numeric_value = int(value)
            except ValueError:
                errors.append(f"{key} must be a whole number, got {value!r}")
                continue
            if key == "IMAP_STARTUP_EMAIL_LIMIT" and numeric_value <= 0:
                errors.append("Startup Email Limit must be a positive integer")
                continue
        updates[key] = value

    if errors:
        return errors

    write_env_pairs(_ENV_PATH, updates)
    return []
