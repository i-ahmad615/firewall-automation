"""Entry point for SecurityAlertAutomation.

Run with:
    python main.py

Starts the email/firewall monitoring service in a background thread, then
starts the integrated web dashboard (FastAPI + uvicorn) in the foreground,
opening the user's default browser automatically. No separate frontend
process or build step is required.
"""
from __future__ import annotations

import logging
import sys
import threading
import time
import webbrowser

import uvicorn

from core import database
from core import firewall_monitor
from core.config import load_config
from core.email_monitor import EmailMonitor
from core.logger import configure_logging


def _run_monitor(config) -> None:
    logger = logging.getLogger(__name__)
    try:
        EmailMonitor(config).start()
    except Exception:
        logger.exception("Email monitor thread crashed")


def _run_firewall_monitor(config) -> None:
    logger = logging.getLogger(__name__)
    try:
        firewall_monitor.run_forever(config)
    except Exception:
        logger.exception("Firewall connectivity monitor thread crashed")


def _open_browser_when_ready(url: str, delay: float = 1.5) -> None:
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


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

    database.init_db(config.database_path)

    # Re-configure with final log level from .env and enable SQLite/live logging
    configure_logging(log_dir=config.log_directory, level=config.log_level, enable_db=True)
    logger.info(
        "Configuration loaded | firewall=%s:%s rule=%r | "
        "imap=%s:%s | smtp=%s:%s | notify=%s | trusted=%s | dashboard=%s:%s",
        config.firewall_host,
        config.firewall_port,
        config.firewall_rule_name,
        config.imap_host,
        config.imap_port,
        config.smtp_host,
        config.smtp_port,
        config.notification_email,
        config.trusted_sender,
        config.dashboard_host,
        config.dashboard_port,
    )

    monitor_thread = threading.Thread(
        target=_run_monitor, args=(config,), name="email-monitor", daemon=True
    )
    monitor_thread.start()
    logger.info("Email monitor started in background thread")

    firewall_thread = threading.Thread(
        target=_run_firewall_monitor, args=(config,), name="firewall-monitor", daemon=True
    )
    firewall_thread.start()
    logger.info(
        "Firewall connectivity monitor started in background thread (interval=%ds)",
        config.firewall_ping_interval,
    )

    dashboard_url = f"http://{config.dashboard_host}:{config.dashboard_port}"
    if config.auto_open_browser:
        threading.Thread(
            target=_open_browser_when_ready, args=(dashboard_url,), daemon=True
        ).start()

    logger.info("Starting web dashboard at %s", dashboard_url)

    from web.app import create_app

    app = create_app(config)
    uvicorn.run(app, host=config.dashboard_host, port=config.dashboard_port, log_level="warning")


if __name__ == "__main__":
    main()
