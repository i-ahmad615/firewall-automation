"""Background firewall connectivity monitor.

Runs on its own interval (``FIREWALL_PING_INTERVAL``), independent of the
email polling cadence -- connectivity health is a distinct, more time
sensitive concern than message processing throughput. Shared by both the
periodic background loop and the on-demand "test connectivity" click in the
dashboard, so both paths log and update status identically.
"""
from __future__ import annotations

import logging
import time

from . import firewall_status
from .config import AppConfig
from .firewall_client import ping as ping_firewall

logger = logging.getLogger(__name__)


def check_once(config: AppConfig) -> bool:
    """Ping the firewall once, log the result, and update the shared status."""
    previous = firewall_status.get_status().get("online")
    online, detail = ping_firewall(
        config.firewall_host, config.firewall_port,
        config.firewall_username, config.firewall_password,
    )
    firewall_status.set_status(online, detail)
    if online:
        transition = " | Connection restored" if previous is False else ""
        logger.info(
            "Firewall ping completed | Status: connected%s",
            transition,
            extra={"category": "Connectivity"},
        )
    else:
        transition = " | Connection lost" if previous is not False else ""
        logger.warning(
            "Firewall ping failed | Status: disconnected%s",
            transition,
            extra={"category": "Connectivity"},
        )
        logger.debug(
            "Firewall connectivity failure detail: %s",
            detail,
            extra={"technical": True},
        )
    return online


def run_forever(config: AppConfig) -> None:
    """Ping the firewall on a loop at ``config.firewall_ping_interval`` seconds."""
    logger.debug(
        "Firewall connectivity monitor started | firewall=%s:%s interval=%ds",
        config.firewall_host, config.firewall_port, config.firewall_ping_interval,
        extra={"technical": True},
    )
    while True:
        try:
            check_once(config)
        except Exception:
            logger.exception(
                "Unexpected error during firewall connectivity check",
                extra={"technical": True},
            )
        time.sleep(config.firewall_ping_interval)
