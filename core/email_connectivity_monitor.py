"""Background and on-demand IMAP/SMTP connectivity checks."""
from __future__ import annotations

import logging
import time

from . import email_status
from .config import AppConfig
from .email_client import EmailConnectionError, ImapMailbox, check_smtp_connection

logger = logging.getLogger(__name__)


def _log_state_change(service: str, previous: object, online: bool, detail: str = "") -> None:
    if previous == online:
        return
    label = service.upper()
    if online:
        message = (
            f"{label} service connected"
            if previous is None else f"{label} service connection restored"
        )
        logger.info(message, extra={"category": "Connectivity"})
    else:
        logger.warning(
            "%s service connection lost",
            label,
            extra={"category": "Connectivity"},
        )
        logger.debug(
            "%s connectivity failure detail: %s",
            label,
            detail,
            extra={"technical": True},
        )


def check_imap_once(config: AppConfig) -> bool:
    previous = email_status.get_status("imap").get("online")
    mailbox = ImapMailbox(config)
    try:
        mailbox.connect()
    except EmailConnectionError as exc:
        email_status.set_status("imap", False, str(exc))
        _log_state_change("imap", previous, False, str(exc))
        return False
    finally:
        mailbox.disconnect()
    email_status.set_status("imap", True, "Authentication and connection succeeded")
    _log_state_change("imap", previous, True)
    return True


def check_smtp_once(config: AppConfig) -> bool:
    previous = email_status.get_status("smtp").get("online")
    try:
        check_smtp_connection(config)
    except EmailConnectionError as exc:
        email_status.set_status("smtp", False, str(exc))
        transition = " | Connection lost" if previous is not False else ""
        logger.warning(
            "SMTP connectivity check completed | Status: disconnected%s",
            transition,
            extra={"category": "Connectivity"},
        )
        logger.debug(
            "SMTP connectivity failure detail: %s",
            exc,
            extra={"technical": True},
        )
        return False
    email_status.set_status("smtp", True, "Authentication and connection succeeded")
    transition = " | Connection restored" if previous is False else ""
    logger.info(
        "SMTP connectivity check completed | Status: connected%s",
        transition,
        extra={"category": "Connectivity"},
    )
    return True


def run_forever(config: AppConfig) -> None:
    """Check mail services on the firewall connectivity-monitor cadence."""
    interval = config.firewall_ping_interval
    logger.debug(
        "Email connectivity monitor started | interval=%ds",
        interval,
        extra={"technical": True},
    )
    while True:
        try:
            check_imap_once(config)
            check_smtp_once(config)
        except Exception:
            logger.exception(
                "Unexpected error during email connectivity check",
                extra={"technical": True},
            )
        time.sleep(interval)
