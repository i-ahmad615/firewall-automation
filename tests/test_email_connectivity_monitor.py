"""IMAP/SMTP status cache, monitor checks, and API endpoint tests."""
from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core import email_connectivity_monitor, email_status
from core.email_client import EmailConnectionError
from web.routes import api


def _request():
    config = SimpleNamespace(admin_password="", firewall_ping_interval=60)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=config)))


def setup_function():
    email_status.reset_statuses()


def test_imap_check_success_updates_status():
    mailbox = MagicMock()
    with patch(
        "core.email_connectivity_monitor.ImapMailbox", return_value=mailbox
    ):
        assert email_connectivity_monitor.check_imap_once(MagicMock()) is True
    mailbox.connect.assert_called_once_with()
    mailbox.disconnect.assert_called_once_with()
    assert email_status.get_status("imap")["online"] is True


def test_imap_check_failure_updates_status():
    mailbox = MagicMock()
    mailbox.connect.side_effect = EmailConnectionError("login rejected")
    with patch(
        "core.email_connectivity_monitor.ImapMailbox", return_value=mailbox
    ):
        assert email_connectivity_monitor.check_imap_once(MagicMock()) is False
    assert email_status.get_status("imap")["online"] is False
    assert "login rejected" in email_status.get_status("imap")["detail"]


def test_imap_click_check_endpoint_returns_fresh_status():
    with patch(
        "web.routes.api.email_connectivity_monitor.check_imap_once",
        side_effect=lambda config: email_status.set_status("imap", True, "ok"),
    ):
        result = api.check_imap_status(_request())
    assert result["online"] is True


def test_smtp_click_check_endpoint_returns_fresh_status():
    with patch(
        "web.routes.api.email_connectivity_monitor.check_smtp_once",
        side_effect=lambda config: email_status.set_status("smtp", False, "down"),
    ):
        result = api.check_smtp_status(_request())
    assert result["online"] is False


def test_smtp_check_logs_every_success(caplog):
    caplog.set_level(logging.INFO)
    with patch("core.email_connectivity_monitor.check_smtp_connection"):
        assert email_connectivity_monitor.check_smtp_once(MagicMock()) is True
        assert email_connectivity_monitor.check_smtp_once(MagicMock()) is True
    assert caplog.text.count(
        "SMTP connectivity check completed | Status: connected"
    ) == 2
