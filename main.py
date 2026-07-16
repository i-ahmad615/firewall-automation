"""Entry point for SecurityAlertAutomation.

Run with:
    python main.py
"""
from __future__ import annotations

import logging
import sys

from core.logger import configure_logging
from core.config import load_config
from core.email_monitor import EmailMonitor


def main() -> None:
    # Bootstrap with defaults so startup errors are visible
    configure_logging()
    logger = logging.getLogger(__name__)
    logger.info("SecurityAlertAutomation starting")

    try:
        config = load_config()
    except EnvironmentError as exc:
        logger.critical("Configuration error: %s", exc)
        sys.exit(1)

    # Re-configure with final log level from .env
    configure_logging(log_dir=config.log_directory, level=config.log_level)
    logger.info(
        "Configuration loaded | firewall=%s:%s rule=%r | "
        "imap=%s:%s | smtp=%s:%s | notify=%s | trusted=%s",
        config.firewall_host,
        config.firewall_port,
        config.firewall_rule_name,
        config.imap_host,
        config.imap_port,
        config.smtp_host,
        config.smtp_port,
        config.notification_email,
        config.trusted_sender,
    )

    monitor = EmailMonitor(config)
    monitor.start()


if __name__ == "__main__":
    main()
