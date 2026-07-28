"""Entry point for SecurityAlertAutomation.

Run with:
    python main.py

Starts the email/firewall monitoring service in a background thread, then
starts the integrated web dashboard (FastAPI + uvicorn) in the foreground,
opening the user's default browser automatically. No separate frontend
process or build step is required.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import webbrowser

import uvicorn

from core import database
from core import email_connectivity_monitor
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


def _run_email_connectivity_monitor(config) -> None:
    logger = logging.getLogger(__name__)
    try:
        email_connectivity_monitor.run_forever(config)
    except Exception:
        logger.exception("Email connectivity monitor thread crashed")


def _open_browser_when_ready(url: str, delay: float = 1.5) -> None:
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _run_dashboard(app, host: str, port: int) -> None:
    """Run the uvicorn server, responsive to Ctrl+C.

    The dashboard's live activity feed (`/api/events`, an SSE stream) is
    opened automatically the moment the browser tab loads and never closes
    on its own -- it only ends when the *client* disconnects. uvicorn's
    graceful shutdown waits for every open connection to close before
    exiting, so with no bound that wait never completes and the process
    hangs silently forever (the "Waiting for connections to close" notice
    is INFO level, suppressed by our WARNING log level). Exposing `server`
    on app.state lets that endpoint (see
    web/routes/api.py:_server_shutting_down) notice should_exit and close
    itself within ~2s on its own; timeout_graceful_shutdown is kept as a
    backstop for any other connection that doesn't.
    """
    config = uvicorn.Config(
        app, host=host, port=port, log_level="warning",
        timeout_graceful_shutdown=3,
    )
    server = uvicorn.Server(config)
    app.state.server = server
    asyncio.run(server.serve())


def main() -> None:
    # Bootstrap with defaults so startup errors are visible
    configure_logging()
    logger = logging.getLogger(__name__)
    logger.info("Security automation service starting", extra={"category": "Application"})

    try:
        config = load_config()
    except EnvironmentError as exc:
        logger.critical("Configuration error: %s", exc)
        sys.exit(1)

    database.init_db(config.database_path)

    # One-time backfill: IPs blocked before the blocked_ips table existed
    # (i.e. by an older version of this app) still need to show up on the
    # Manual IP Unblock page.
    from core.rule_updater import sync_blocked_ips_from_history
    recovered = sync_blocked_ips_from_history()
    if recovered:
        logger.info(
            "Recovered %d historical blocked IP record(s)",
            recovered,
            extra={"category": "Firewall Action"},
        )

    # Re-configure with final log level from .env and enable SQLite/live logging
    configure_logging(
        log_dir=config.log_directory,
        level=config.log_level,
        enable_db=True,
        debug_logging=config.debug_logging,
        debug_max_chars=config.debug_log_max_chars,
    )
    logger.info("Configuration loaded", extra={"category": "Application"})
    logger.debug(
        "Runtime configuration | firewall=%s:%s rule=%r | imap=%s:%s | "
        "catchup=%dh/%d | smtp=%s:%s | dashboard=%s:%s",
        config.firewall_host,
        config.firewall_port,
        config.firewall_rule_name,
        config.imap_host,
        config.imap_port,
        config.email_lookback_hours,
        config.email_lookback_max_messages,
        config.smtp_host,
        config.smtp_port,
        config.dashboard_host,
        config.dashboard_port,
        extra={"technical": True},
    )

    # Bounded, synchronous startup recovery. Failure is intentionally
    # non-fatal: live monitoring and the dashboard still start when IMAP or
    # Sophos is temporarily unavailable.
    logger.info(
        "Starting bounded email catch-up scan",
        extra={"category": "Application"},
    )
    EmailMonitor(config).run_startup_catchup()

    monitor_thread = threading.Thread(
        target=_run_monitor, args=(config,), name="email-monitor", daemon=True
    )
    monitor_thread.start()
    logger.debug("Email monitor thread started", extra={"technical": True})

    firewall_thread = threading.Thread(
        target=_run_firewall_monitor, args=(config,), name="firewall-monitor", daemon=True
    )
    firewall_thread.start()
    logger.debug(
        "Firewall connectivity monitor started in background thread (interval=%ds)",
        config.firewall_ping_interval,
        extra={"technical": True},
    )

    email_connectivity_thread = threading.Thread(
        target=_run_email_connectivity_monitor,
        args=(config,),
        name="email-connectivity-monitor",
        daemon=True,
    )
    email_connectivity_thread.start()
    logger.debug(
        "IMAP/SMTP connectivity monitor started in background thread (interval=%ds)",
        config.firewall_ping_interval,
        extra={"technical": True},
    )

    dashboard_url = f"http://{config.dashboard_host}:{config.dashboard_port}"
    if config.auto_open_browser:
        threading.Thread(
            target=_open_browser_when_ready, args=(dashboard_url,), daemon=True
        ).start()

    logger.info("Application services started", extra={"category": "Application"})
    logger.debug("Web dashboard endpoint: %s", dashboard_url, extra={"technical": True})

    from web.app import create_app

    app = create_app(config)
    try:
        _run_dashboard(app, config.dashboard_host, config.dashboard_port)
    except KeyboardInterrupt:
        pass
    logger.info("Security automation service stopped", extra={"category": "Application"})


if __name__ == "__main__":
    main()
