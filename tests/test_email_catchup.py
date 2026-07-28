"""Bounded startup email catch-up and status-aware idempotency tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from core import database
from core.config import AppConfig
from core.email_client import ImapMailbox
from core.email_monitor import EmailMonitor


def _config(tmp_path, *, keywords=frozenset({"new-threat"}), allowed=()) -> AppConfig:
    allowed_file = tmp_path / "allowed.txt"
    allowed_file.write_text("\n".join(allowed), encoding="utf-8")
    return AppConfig(
        firewall_host="192.0.2.1",
        firewall_port=4444,
        firewall_username="admin",
        firewall_password="secret",
        firewall_rule_name="Block IP",
        imap_host="imap.example.com",
        imap_port=993,
        imap_use_ssl=True,
        imap_use_starttls=False,
        imap_mailbox="INBOX",
        imap_timeout=30,
        email_username="monitor@example.com",
        email_password="secret",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        smtp_timeout=30,
        smtp_username="monitor@example.com",
        smtp_password="secret",
        smtp_from_address="monitor@example.com",
        notification_email="notify@example.com",
        trusted_senders=frozenset({"soc@example.com"}),
        alert_keywords=keywords,
        allowed_ips_file=str(allowed_file),
        log_directory=str(tmp_path / "logs"),
        log_level="INFO",
        poll_interval=60,
        run_loop=True,
        database_path=str(tmp_path / "catchup.db"),
        email_lookback_hours=24,
        email_lookback_max_messages=200,
    )


def _email(
    *,
    message_id: str,
    ip: str = "8.8.8.8",
    classification: str = "New-Threat",
    sender: str = "soc@example.com",
    received: datetime | None = None,
) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "SOC security alert"
    msg["From"] = sender
    msg["To"] = "monitor@example.com"
    msg["Message-ID"] = message_id
    msg["Date"] = format_datetime(received or datetime.now(timezone.utc))
    msg.set_content("SOC alert")
    msg.add_alternative(
        "<html><table>"
        "<tr><th>Alarm ID</th><td>A-100</td></tr>"
        f"<tr><th>Classification</th><td>{classification}</td></tr>"
        f"<tr><th>Origin IP</th><td>{ip}</td></tr>"
        "</table></html>",
        subtype="html",
    )
    return msg.as_bytes()


def _run_with_messages(config: AppConfig, messages):
    mailbox = MagicMock()
    mailbox.fetch_recent.return_value = messages
    with patch("core.email_monitor.ImapMailbox", return_value=mailbox):
        with patch("core.email_monitor._notify", return_value=False):
            summary = EmailMonitor(config).run_startup_catchup()
    mailbox.connect.assert_called_once_with()
    mailbox.disconnect.assert_called_once_with()
    return summary


def test_fetch_recent_includes_read_mail_without_changing_seen_flag(tmp_path):
    config = _config(tmp_path)
    mailbox = ImapMailbox(config)
    conn = MagicMock()
    conn.select.return_value = ("OK", [b"1"])
    conn.uid.side_effect = [
        ("OK", [b"41"]),
        ("OK", [(b"41 (BODY[] {3})", b"raw")]),
    ]
    mailbox._conn = conn

    result = mailbox.fetch_recent(
        datetime.now(timezone.utc) - timedelta(hours=24),
        config.trusted_senders,
        200,
    )

    assert result == [("41", b"raw", None)]
    conn.select.assert_called_once_with("INBOX", readonly=True)
    assert conn.uid.call_args_list[0].args[0] == "SEARCH"
    assert "UNSEEN" not in conn.uid.call_args_list[0].args
    assert conn.uid.call_args_list[1].args == (
        "FETCH", "41", "(BODY.PEEK[] INTERNALDATE)"
    )
    assert not any(call.args and call.args[0] == "STORE" for call in conn.uid.call_args_list)


def test_fetch_recent_enforces_newest_message_limit(tmp_path):
    config = _config(tmp_path)
    mailbox = ImapMailbox(config)
    conn = MagicMock()
    conn.select.return_value = ("OK", [b"4"])
    conn.uid.side_effect = [
        ("OK", [b"1 2 3 4"]),
        ("OK", [(b"3", b"raw-3")]),
        ("OK", [(b"4", b"raw-4")]),
    ]
    mailbox._conn = conn

    result = mailbox.fetch_recent(
        datetime.now(timezone.utc) - timedelta(hours=24),
        config.trusted_senders,
        2,
    )

    assert result == [("3", b"raw-3", None), ("4", b"raw-4", None)]
    search_args = conn.uid.call_args_list[0].args
    assert search_args[-2:] == ("FROM", "soc@example.com")


def test_old_keyword_miss_is_updated_in_place_and_blocked(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    original_received = "2026-07-27T08:15:00+00:00"
    alert_id = database.record_alert(
        received_at=original_received,
        subject="SOC security alert",
        sender="soc@example.com",
        alarm_id="A-100",
        status="ignored",
        action_taken="ignored",
        reason="Classification does not match configured alert keywords",
        processing_status="no_keyword_match",
    )

    with patch("core.email_monitor.block_ip", return_value="blocked") as block:
        summary = _run_with_messages(
            config, [("7", _email(message_id="<missed@example.com>"))]
        )

    row = database.get_alert(alert_id)
    assert summary == {"fetched": 1, "processed": 1, "skipped": 0, "failed": 0}
    assert row["processing_status"] == "blocked_successfully"
    assert row["action_taken"] == "blocked"
    assert row["processing_source"] == "startup_catchup"
    assert row["message_id"] == "<missed@example.com>"
    assert row["imap_uid"] == "7"
    assert row["received_at"] == original_received
    block.assert_called_once()


@pytest.mark.parametrize(
    ("block_result", "expected_status"),
    [("duplicate", "already_blocked"), ("allowed", "allowlisted")],
)
def test_catchup_records_non_write_final_results(
    tmp_path, block_result, expected_status
):
    config = _config(tmp_path, allowed=("8.8.8.8",) if block_result == "allowed" else ())
    database.init_db(config.database_path)
    with patch("core.email_monitor.block_ip", return_value=block_result):
        _run_with_messages(config, [("8", _email(message_id=f"<{block_result}@example.com>"))])
    row = database.find_alert_by_message_identity(f"<{block_result}@example.com>", "8")
    assert row["processing_status"] == expected_status


def test_duplicate_message_id_is_processed_only_once(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    raw = _email(message_id="<duplicate@example.com>")
    with patch("core.email_monitor.block_ip", return_value="blocked") as block:
        summary = _run_with_messages(config, [("10", raw), ("11", raw)])
    assert block.call_count == 1
    assert summary["processed"] == 1
    assert summary["skipped"] == 1


def test_message_outside_exact_lookback_is_skipped(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    raw = _email(
        message_id="<old@example.com>",
        received=datetime.now(timezone.utc) - timedelta(hours=25),
    )
    with patch("core.email_monitor.block_ip") as block:
        summary = _run_with_messages(config, [("12", raw)])
    block.assert_not_called()
    assert summary["skipped"] == 1


def test_untrusted_sender_is_rejected_even_if_server_returns_it(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    raw = _email(message_id="<evil@example.com>", sender="evil@example.com")
    with patch("core.email_monitor.block_ip") as block:
        summary = _run_with_messages(config, [("13", raw)])
    block.assert_not_called()
    row = database.find_alert_by_message_identity("<evil@example.com>", "13")
    assert row["processing_status"] == "untrusted_sender"
    assert summary["processed"] == 1


def test_failure_on_one_message_does_not_stop_remaining_scan(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    messages = [
        ("14", _email(message_id="<fails@example.com>", ip="8.8.8.8")),
        ("15", _email(message_id="<works@example.com>", ip="9.9.9.9")),
    ]
    with patch(
        "core.email_monitor.block_ip",
        side_effect=[RuntimeError("unexpected parser dependency failure"), "blocked"],
    ) as block:
        summary = _run_with_messages(config, messages)
    assert block.call_count == 2
    assert summary["failed"] == 1
    assert summary["processed"] == 1
    assert database.find_alert_by_message_identity(
        "<works@example.com>", "15"
    )["processing_status"] == "blocked_successfully"
    assert database.find_alert_by_message_identity(
        "<fails@example.com>", "14"
    )["processing_status"] == "processing_failed"


def test_final_status_message_is_idempotently_skipped(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    database.record_alert(
        message_id="<done@example.com>",
        imap_uid="16",
        processing_status="blocked_successfully",
        action_taken="blocked",
    )
    with patch("core.email_monitor.block_ip") as block:
        summary = _run_with_messages(
            config, [("16", _email(message_id="<done@example.com>"))]
        )
    block.assert_not_called()
    assert summary["skipped"] == 1


def test_catchup_writes_required_processing_log(tmp_path, caplog):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    with caplog.at_level("INFO"):
        with patch("core.email_monitor.block_ip", return_value="blocked"):
            _run_with_messages(config, [("17", _email(message_id="<logged@example.com>"))])
    matching = [
        record.getMessage() for record in caplog.records
        if "processed through startup catch-up scan" in record.getMessage()
    ]
    assert len(matching) == 1


def test_legacy_database_keyword_miss_is_backfilled_as_reprocessable(tmp_path):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE alerts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, "
            "subject TEXT, sender TEXT, origin_ip TEXT, classification TEXT, "
            "status TEXT, action_taken TEXT, reason TEXT, "
            "notification_sent INTEGER DEFAULT 0)"
        )
        conn.execute(
            "INSERT INTO alerts (received_at, subject, sender, status, action_taken, reason) "
            "VALUES ('2026-07-27T08:15:00+00:00', 'SOC security alert', "
            "'soc@example.com', 'ignored', 'ignored', "
            "'Classification does not match configured alert keywords')"
        )
        conn.commit()

    database.init_db(str(db_path))

    assert database.get_alert(1)["processing_status"] == "no_keyword_match"
