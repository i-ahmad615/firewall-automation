"""Centralized configuration for SecurityAlertAutomation.

All settings are read from environment variables (loaded from .env).
No mode switching, no provider-specific defaults that hide missing configuration.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet

from dotenv import load_dotenv

# ──────────────────────────────────────────────────────────────────────────────
# Required env-var names (absence causes a hard startup failure)
# ──────────────────────────────────────────────────────────────────────────────
_REQUIRED: tuple[str, ...] = (
    "FIREWALL_HOST",
    "FIREWALL_PORT",
    "FIREWALL_USERNAME",
    "FIREWALL_PASSWORD",
    "FIREWALL_RULE_NAME",
    "IMAP_HOST",
    "IMAP_PORT",
    "EMAIL_USERNAME",
    "EMAIL_PASSWORD",
    "SMTP_HOST",
    "SMTP_PORT",
    "NOTIFICATION_EMAIL",
    "TRUSTED_SENDER",
    "ALERT_KEYWORDS",
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class AppConfig:
    """Immutable, validated application configuration."""

    # Firewall
    firewall_host: str
    firewall_port: int
    firewall_username: str
    firewall_password: str
    firewall_rule_name: str

    # IMAP (inbound alert polling)
    imap_host: str
    imap_port: int
    imap_use_ssl: bool
    imap_use_starttls: bool
    imap_mailbox: str
    imap_timeout: int
    email_username: str
    email_password: str

    # SMTP (outbound notifications)
    smtp_host: str
    smtp_port: int
    smtp_use_tls: bool
    smtp_use_ssl: bool
    smtp_timeout: int
    smtp_username: str
    smtp_password: str
    smtp_from_address: str
    notification_email: str

    # Alert filtering
    trusted_sender: str
    alert_keywords: FrozenSet[str]

    # Paths / behaviour
    allowed_ips_file: str
    log_directory: str
    log_level: str
    poll_interval: int
    run_loop: bool


def _env_bool(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _validate_port(name: str, raw: str) -> int:
    try:
        port = int(raw.strip())
    except ValueError as exc:
        raise EnvironmentError(
            f"{name} must be an integer port number, got {raw!r}"
        ) from exc
    if not 1 <= port <= 65535:
        raise EnvironmentError(f"{name} must be between 1 and 65535, got {port}")
    return port


def _validate_email(name: str, raw: str) -> str:
    value = raw.strip()
    if not value:
        raise EnvironmentError(f"{name} is required and cannot be empty")
    if not _EMAIL_RE.match(value):
        raise EnvironmentError(f"{name} must be a valid email address, got {value!r}")
    return value


def _validate_non_empty(name: str, raw: str) -> str:
    value = raw.strip()
    if not value:
        raise EnvironmentError(f"{name} is required and cannot be empty")
    return value


def load_config() -> AppConfig:
    """Load .env, validate required variables, and return an AppConfig.

    Raises
    ------
    EnvironmentError
        If any required variable is absent, empty, or invalid.
    """
    load_dotenv()

    missing = [k for k in _REQUIRED if not os.environ.get(k, "").strip()]
    if missing:
        raise EnvironmentError(
            "Missing required environment variables: "
            + ", ".join(sorted(missing))
        )

    imap_port = _validate_port("IMAP_PORT", os.environ["IMAP_PORT"])
    smtp_port = _validate_port("SMTP_PORT", os.environ["SMTP_PORT"])
    firewall_port = _validate_port("FIREWALL_PORT", os.environ["FIREWALL_PORT"])

    email_username = _validate_email("EMAIL_USERNAME", os.environ["EMAIL_USERNAME"])
    notification_email = _validate_email(
        "NOTIFICATION_EMAIL", os.environ["NOTIFICATION_EMAIL"]
    )
    trusted_sender = _validate_email("TRUSTED_SENDER", os.environ["TRUSTED_SENDER"]).lower()

    smtp_username = os.environ.get("SMTP_USERNAME", "").strip() or email_username
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip() or os.environ["EMAIL_PASSWORD"]
    smtp_from = os.environ.get("SMTP_FROM", "").strip() or email_username
    _validate_email("SMTP_FROM", smtp_from)

    imap_use_ssl = _env_bool("IMAP_USE_SSL", "true")
    imap_use_starttls = _env_bool("IMAP_USE_STARTTLS", "false")
    if imap_use_ssl and imap_use_starttls:
        raise EnvironmentError(
            "IMAP_USE_SSL and IMAP_USE_STARTTLS cannot both be true; "
            "use IMAP_USE_SSL=true for port 993 (Outlook/Gmail) or "
            "IMAP_USE_STARTTLS=true with IMAP_USE_SSL=false for STARTTLS on port 143"
        )

    smtp_use_ssl = _env_bool("SMTP_USE_SSL", "false")
    # When implicit SSL is enabled (port 465), STARTTLS must stay off.
    smtp_use_tls = (
        False if smtp_use_ssl else _env_bool("SMTP_USE_TLS", "true")
    )
    if smtp_use_tls and smtp_use_ssl:
        raise EnvironmentError(
            "SMTP_USE_TLS and SMTP_USE_SSL cannot both be true; "
            "use SMTP_USE_TLS=true for port 587 (Outlook) or "
            "SMTP_USE_SSL=true for port 465"
        )

    try:
        imap_timeout = int(os.environ.get("IMAP_TIMEOUT", "30"))
        smtp_timeout = int(os.environ.get("SMTP_TIMEOUT", "30"))
        poll_interval = int(os.environ.get("IMAP_POLL_INTERVAL", "60"))
    except ValueError as exc:
        raise EnvironmentError(
            "IMAP_TIMEOUT, SMTP_TIMEOUT, and IMAP_POLL_INTERVAL must be integers"
        ) from exc

    keywords_raw = os.environ.get("ALERT_KEYWORDS", "")
    keywords: FrozenSet[str] = frozenset(
        k.strip().lower() for k in keywords_raw.split(",") if k.strip()
    )
    if not keywords:
        raise EnvironmentError(
            "ALERT_KEYWORDS must contain at least one comma-separated keyword "
            f"(e.g. attack,threat,malicious); got {keywords_raw!r}"
        )

    return AppConfig(
        firewall_host=_validate_non_empty("FIREWALL_HOST", os.environ["FIREWALL_HOST"]),
        firewall_port=firewall_port,
        firewall_username=os.environ["FIREWALL_USERNAME"],
        firewall_password=os.environ["FIREWALL_PASSWORD"],
        firewall_rule_name=_validate_non_empty(
            "FIREWALL_RULE_NAME", os.environ["FIREWALL_RULE_NAME"]
        ),
        imap_host=_validate_non_empty("IMAP_HOST", os.environ["IMAP_HOST"]),
        imap_port=imap_port,
        imap_use_ssl=imap_use_ssl,
        imap_use_starttls=imap_use_starttls,
        imap_mailbox=os.environ.get("IMAP_MAILBOX", "INBOX").strip() or "INBOX",
        imap_timeout=imap_timeout,
        email_username=email_username,
        email_password=os.environ["EMAIL_PASSWORD"],
        smtp_host=_validate_non_empty("SMTP_HOST", os.environ["SMTP_HOST"]),
        smtp_port=smtp_port,
        smtp_use_tls=smtp_use_tls,
        smtp_use_ssl=smtp_use_ssl,
        smtp_timeout=smtp_timeout,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_from_address=smtp_from,
        notification_email=notification_email,
        trusted_sender=trusted_sender,
        alert_keywords=keywords,
        allowed_ips_file=os.environ.get(
            "ALLOWED_IPS_FILE", "config/allowed_ips.txt"
        ).strip(),
        log_directory=os.environ.get("LOG_DIRECTORY", "logs").strip(),
        log_level=os.environ.get("LOG_LEVEL", "INFO").strip().upper(),
        poll_interval=poll_interval,
        run_loop=_env_bool("IMAP_RUN_LOOP", "true"),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Allowed-IP helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_allowed_ips(path: str) -> FrozenSet[str]:
    """Return the set of IPs that must never be blocked."""
    p = Path(path)
    if not p.exists():
        return frozenset()
    allowed: set[str] = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            allowed.add(stripped)
    return frozenset(allowed)


def is_ip_allowed(ip: str, allowed: FrozenSet[str]) -> bool:
    """Return True if *ip* is whitelisted and must NOT be blocked."""
    return ip.strip() in allowed
