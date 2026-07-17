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
    online, detail = ping_firewall(
        config.firewall_host, config.firewall_port,
        config.firewall_username, config.firewall_password,
    )
    firewall_status.set_status(online, detail)
    if online:
        logger.info("Firewall connectivity check succeeded")
    else:
        logger.warning("Firewall connectivity check failed: %s", detail)
    return online


def run_forever(config: AppConfig) -> None:
    """Ping the firewall on a loop at ``config.firewall_ping_interval`` seconds."""
    logger.info(
        "Firewall connectivity monitor started | firewall=%s:%s interval=%ds",
        config.firewall_host, config.firewall_port, config.firewall_ping_interval,
    )
    while True:
        try:
            check_once(config)
        except Exception:
            logger.exception("Unexpected error during firewall connectivity check")
        time.sleep(config.firewall_ping_interval)
