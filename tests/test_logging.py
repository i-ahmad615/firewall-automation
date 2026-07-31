"""Production/debug logging separation and concise business-event tests."""
from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from core import database, email_status, firewall_status
from core.email_monitor import EmailMonitor
from core.firewall_monitor import check_once as check_firewall_once
from core.logger import SUCCESS, configure_logging
from core.rule_updater import RuleUpdateError
from tests.test_email_catchup import _config, _email, _run_with_messages


@pytest.fixture(autouse=True)
def _remove_managed_handlers_after_test():
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_security_automation_handler", False):
            root.removeHandler(handler)
            handler.close()
    root.setLevel(logging.WARNING)


def _configure(tmp_path: Path, *, debug: bool = False, max_chars: int = 2000, db=False):
    log_dir = tmp_path / "logs"
    configure_logging(
        str(log_dir),
        "INFO",
        enable_db=db,
        debug_logging=debug,
        debug_max_chars=max_chars,
    )
    return log_dir


def _flush() -> None:
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass


def _read(path: Path) -> str:
    _flush()
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_production_logs_exclude_xml_and_credentials(tmp_path):
    log_dir = _configure(tmp_path)
    technical = logging.LoggerAdapter(
        logging.getLogger("core.firewall_client"), {"technical": True}
    )
    technical.info(
        "<Request><Username>admin</Username><Password>topsecret</Password></Request>"
    )
    logging.getLogger("service").info(
        "Application ready", extra={"category": "Application"}
    )

    production = _read(log_dir / "application.log")
    assert "Application ready" in production
    assert "<Request>" not in production
    assert "admin" not in production
    assert "topsecret" not in production


def test_empty_email_polling_reports_each_result_without_protocol_noise(tmp_path):
    log_dir = _configure(tmp_path)
    config = _config(tmp_path)
    with patch("core.email_monitor.ImapMailbox") as mailbox_type:
        mailbox_type.return_value.select_folder.return_value.uidvalidity = "1"
        mailbox_type.return_value.search_uids_since.return_value = []
        monitor = EmailMonitor(config)
        with patch.object(monitor, "_retry_pending_blocks"):
            monitor.run_once()
            monitor.run_once()

    production = _read(log_dir / "application.log")
    assert production.count(
        "IMAP poll completed | Status: connected | No new emails"
    ) == 2
    assert "IMAP SEARCH" not in production
    assert "EXISTS=" not in production
    assert "UNSEEN=" not in production


def test_firewall_connectivity_logs_every_ping_and_marks_transitions(tmp_path):
    log_dir = _configure(tmp_path)
    firewall_status.set_status(None)  # type: ignore[arg-type]
    config = _config(tmp_path)
    with patch(
        "core.firewall_monitor.ping_firewall",
        side_effect=[
            (True, "ok"),
            (True, "ok"),
            (False, "timeout"),
            (False, "timeout"),
            (True, "ok"),
        ],
    ):
        for _ in range(5):
            check_firewall_once(config)

    production = _read(log_dir / "application.log")
    assert production.count("Firewall ping completed | Status: connected") == 3
    assert production.count("Firewall ping failed | Status: disconnected") == 2
    assert production.count("Connection lost") == 1
    assert production.count("Connection restored") == 1


def test_successful_block_has_concise_single_business_sequence(tmp_path):
    log_dir = _configure(tmp_path)
    config = _config(tmp_path)
    database.init_db(config.database_path)
    with patch("core.email_monitor.block_ip", return_value="blocked"):
        with patch("core.email_monitor.send_notification"):
            EmailMonitor(config)._process_message(
                "20", _email(message_id="<success@example.com>")
            )

    production = _read(log_dir / "application.log")
    assert "External source selected | Origin: 8.8.8.8 | Impacted: 192.168.20.50" in production
    assert "Blocking IP 8.8.8.8" in production
    assert production.count("IP 8.8.8.8 blocked successfully") == 1
    assert production.count("Confirmation email sent") == 1
    assert "<success@example.com>" not in production
    assert "core.email_monitor" not in production


def test_already_blocked_ip_has_one_concise_event(tmp_path):
    log_dir = _configure(tmp_path)
    config = _config(tmp_path)
    database.init_db(config.database_path)
    with patch("core.email_monitor.block_ip", return_value="duplicate"):
        EmailMonitor(config)._process_message(
            "21", _email(message_id="<duplicate-log@example.com>")
        )

    production = _read(log_dir / "application.log")
    assert production.count("IP 8.8.8.8 is already blocked") == 1
    assert "Blocking IP 8.8.8.8" not in production


def test_failed_block_logs_error_and_retry_once(tmp_path):
    log_dir = _configure(tmp_path)
    config = _config(tmp_path)
    database.init_db(config.database_path)
    with patch(
        "core.email_monitor.block_ip",
        side_effect=RuleUpdateError("Firewall timeout"),
    ):
        with patch("core.email_monitor.send_notification"):
            EmailMonitor(config)._process_message(
                "22", _email(message_id="<failure-log@example.com>")
            )

    production = _read(log_dir / "application.log")
    assert production.count(
        "Failed to block 8.8.8.8 | Reason: Firewall request failed unexpectedly"
    ) == 1
    assert production.count("Retry scheduled | IP: 8.8.8.8 | Attempt: 1") == 1


def test_startup_catchup_has_one_summary_and_no_skip_noise(tmp_path):
    log_dir = _configure(tmp_path)
    config = _config(tmp_path)
    database.init_db(config.database_path)
    for number in range(3):
        database.record_alert(
            message_id=f"<done-{number}@example.com>",
            imap_uid=str(30 + number),
            processing_status="blocked_successfully",
            action_taken="blocked",
        )
    messages = [
        (str(30 + number), _email(message_id=f"<done-{number}@example.com>"))
        for number in range(3)
    ]
    _run_with_messages(config, messages)

    production = _read(log_dir / "application.log")
    assert production.count("Startup catch-up completed") == 1
    assert "Checked: 3 | Processed: 0 | Skipped: 3 | Failed: 0" in production
    assert "skipped final status" not in production
    assert "Message-ID" not in production


def test_debug_mode_isolated_redacted_and_truncated(tmp_path):
    log_dir = _configure(tmp_path, debug=True, max_chars=120)
    technical = logging.LoggerAdapter(
        logging.getLogger("core.firewall_client"), {"technical": True}
    )
    payload = (
        "<Request><Username>admin</Username><Password>topsecret</Password>"
        + ("<FirewallRule>blocked-host</FirewallRule>" * 20)
        + "</Request>"
    )
    technical.debug("SFOS request payload: %s", payload)

    production = _read(log_dir / "application.log")
    debug = _read(log_dir / "debug.log")
    assert "SFOS request payload" not in production
    assert "SFOS request payload" in debug
    assert "topsecret" not in debug
    assert "***REDACTED***" in debug
    assert "[truncated;" in debug


def test_dashboard_stores_only_clean_category_events(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    _configure(tmp_path, debug=True, db=True)
    technical = logging.LoggerAdapter(
        logging.getLogger("core.firewall_client"), {"technical": True}
    )
    technical.info("SFOS response: <Response>secret internals</Response>")
    logging.getLogger("core.email_monitor").log(
        SUCCESS,
        "IP 8.8.8.8 blocked successfully",
        extra={"category": "Firewall Action"},
    )

    rows = database.query_logs()["rows"]
    assert len(rows) == 1
    assert rows[0]["severity"] == "SUCCESS"
    assert rows[0]["module"] == "Firewall Action"
    assert "core." not in rows[0]["module"]
