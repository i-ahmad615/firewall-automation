"""Tests for core/email_client.py

Covers provider-agnostic IMAP connection and SMTP notification sending.
"""
from __future__ import annotations

from email.message import EmailMessage
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from core.config import AppConfig
from core import email_status
from core.email_client import (
    EmailConnectionError, ImapMailbox, check_smtp_connection, send_notification,
)


def _make_config() -> AppConfig:
    return AppConfig(
        firewall_host="192.168.1.1",
        firewall_port=4444,
        firewall_username="admin",
        firewall_password="pass",
        firewall_rule_name="Block IP",
        imap_host="outlook.office365.com",
        imap_port=993,
        imap_use_ssl=True,
        imap_use_starttls=False,
        imap_mailbox="INBOX",
        imap_timeout=30,
        email_username="monitor@company.com",
        email_password="secret",
        smtp_host="smtp.office365.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        smtp_timeout=30,
        smtp_username="monitor@company.com",
        smtp_password="secret",
        smtp_from_address="monitor@company.com",
        notification_email="security-alerts@company.com",
        trusted_senders=frozenset({"alerts@company.com"}),
        alert_keywords=frozenset({"attack"}),
        allowed_ips_file="config/allowed_ips.txt",
        log_directory="logs",
        log_level="INFO",
        poll_interval=60,
        run_loop=True,
    )


class TestImapMailbox:
    def test_connect_uses_ssl_and_logs_in(self) -> None:
        config = _make_config()
        mock_conn = MagicMock()
        with patch("core.email_client.imaplib.IMAP4_SSL", return_value=mock_conn) as mock_ssl:
            mailbox = ImapMailbox(config)
            mailbox.connect()
        mock_ssl.assert_called_once_with("outlook.office365.com", 993, timeout=30)
        mock_conn.login.assert_called_once_with("monitor@company.com", "secret")

    def test_connect_auth_failure_raises(self) -> None:
        import imaplib

        config = _make_config()
        mock_conn = MagicMock()
        mock_conn.login.side_effect = imaplib.IMAP4.error("AUTHENTICATE failed")
        with patch("core.email_client.imaplib.IMAP4_SSL", return_value=mock_conn):
            mailbox = ImapMailbox(config)
            with pytest.raises(EmailConnectionError, match="authentication failed"):
                mailbox.connect()

    def test_fetch_unread_returns_messages(self) -> None:
        config = _make_config()
        mailbox = ImapMailbox(config)
        mock_conn = MagicMock()
        mock_conn.select.return_value = ("OK", None)
        mock_conn.uid.side_effect = [
            ("OK", [b"1 2"]),
            ("OK", [(b"1 (RFC822 {10}", b"raw-email-1")]),
            ("OK", [(b"2 (RFC822 {10}", b"raw-email-2")]),
        ]
        mailbox._conn = mock_conn

        results = mailbox.fetch_unread()

        assert results == [("1", b"raw-email-1"), ("2", b"raw-email-2")]
        mock_conn.select.assert_called_once_with("INBOX", readonly=False)


class TestSendNotification:
    def test_tls_mode_uses_smtp_and_starttls(self) -> None:
        config = _make_config()
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)

        with patch("core.email_client.smtplib.SMTP", return_value=mock_smtp) as mock_ctor:
            with patch("core.email_client.smtplib.SMTP_SSL") as mock_ssl_ctor:
                send_notification(config, "Test Subject", "Test body")

        mock_ctor.assert_called_once_with("smtp.office365.com", 587, timeout=30)
        mock_ssl_ctor.assert_not_called()
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("monitor@company.com", "secret")
        mock_smtp.send_message.assert_called_once()
        sent_msg: EmailMessage = mock_smtp.send_message.call_args[0][0]
        assert sent_msg["To"] == "security-alerts@company.com"
        assert sent_msg["From"] == "monitor@company.com"
        assert sent_msg["Subject"] == "Test Subject"

    def test_ssl_mode_uses_smtp_ssl_without_starttls(self) -> None:
        config = _make_config()
        ssl_config = replace(
            config,
            smtp_host="webmail.centurypaper.com.pk",
            smtp_use_ssl=True,
            smtp_use_tls=False,
            smtp_port=465,
        )
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)

        with patch("core.email_client.smtplib.SMTP_SSL", return_value=mock_smtp) as mock_ssl:
            with patch("core.email_client.smtplib.SMTP") as mock_plain:
                send_notification(ssl_config, "Subject", "Body")

        mock_ssl.assert_called_once()
        call_args = mock_ssl.call_args
        assert call_args.args == ("webmail.centurypaper.com.pk", 465)
        assert call_args.kwargs["timeout"] == 30
        assert "context" in call_args.kwargs
        mock_plain.assert_not_called()
        mock_smtp.starttls.assert_not_called()
        mock_smtp.login.assert_called_once_with("monitor@company.com", "secret")
        mock_smtp.send_message.assert_called_once()

    def test_smtp_auth_failure_raises(self) -> None:
        import smtplib

        config = _make_config()
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")

        with patch("core.email_client.smtplib.SMTP", return_value=mock_smtp):
            with pytest.raises(EmailConnectionError, match="authentication failed"):
                send_notification(config, "Subject", "Body")


class TestSmtpConnectivityCheck:
    def test_authenticates_and_uses_noop_without_sending(self) -> None:
        config = _make_config()
        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)

        with patch("core.email_client._open_smtp_connection", return_value=mock_smtp):
            check_smtp_connection(config)

        mock_smtp.login.assert_called_once_with("monitor@company.com", "secret")
        mock_smtp.noop.assert_called_once_with()
        mock_smtp.send_message.assert_not_called()
        assert email_status.get_status("smtp")["online"] is True

    def test_connection_failure_sets_offline(self) -> None:
        config = _make_config()
        with patch(
            "core.email_client._open_smtp_connection",
            side_effect=OSError("connection refused"),
        ):
            with pytest.raises(EmailConnectionError, match="connection failed"):
                check_smtp_connection(config)
        assert email_status.get_status("smtp")["online"] is False
