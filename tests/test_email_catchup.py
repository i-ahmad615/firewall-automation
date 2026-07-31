"""Bounded startup email catch-up and status-aware idempotency tests."""
from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from core import database
from core.config import AppConfig
from core.email_client import ImapFolderState, ImapMailbox
from core.email_monitor import EmailMonitor


def _config(tmp_path, *, keywords=frozenset({"new-threat"}), allowed=()) -> AppConfig:
    allowed_file = tmp_path / "allowed.txt"
    allowed_file.write_text("\n".join(allowed), encoding="utf-8")
    config = AppConfig(
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
        log_directory=str(tmp_path / "logs"),
        log_level="INFO",
        poll_interval=60,
        run_loop=True,
        database_path=str(tmp_path / "catchup.db"),
        imap_startup_email_limit=10,
    )
    database.init_db(config.database_path)
    database.add_protected_endpoint(
        "192.168.20.0/24", "192.168.20.0/24", "CIDR", "CENTURY_OWNED"
    )
    for value in allowed:
        database.add_protected_endpoint(value, value, "IP", "EXTERNAL_ALLOWLIST")
    return config


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
        "<tr><th>Impacted IP</th><td>192.168.20.50</td></tr>"
        "</table></html>",
        subtype="html",
    )
    return msg.as_bytes()


def _run_with_messages(config: AppConfig, messages):
    mailbox = MagicMock()
    mailbox.select_folder.return_value = ImapFolderState("INBOX", "1")
    mailbox.search_uids_since.return_value = [str(message[0]) for message in messages]
    raw_by_uid = {str(message[0]): message[1] for message in messages}
    mailbox.fetch_message_peek.side_effect = lambda uid: raw_by_uid[str(uid)]
    with patch("core.email_monitor.ImapMailbox", return_value=mailbox):
        with patch("core.email_monitor._notify", return_value=False):
            summary = EmailMonitor(config).run_startup_scan()
    mailbox.connect.assert_called_once_with()
    mailbox.disconnect.assert_called_once_with()
    return summary


def test_startup_fetch_uses_body_peek_without_changing_seen_flag(tmp_path):
    config = _config(tmp_path)
    mailbox = ImapMailbox(config)
    conn = MagicMock()
    conn.uid.return_value = ("OK", [(b"41 (BODY[] {3})", b"raw")])
    mailbox._conn = conn

    result = mailbox.fetch_message_peek("41")

    assert result == b"raw"
    conn.uid.assert_called_once_with("FETCH", "41", "(BODY.PEEK[])")
    assert not any(call.args and call.args[0] == "STORE" for call in conn.uid.call_args_list)


def test_startup_scan_enforces_latest_n_and_processes_oldest_to_newest(tmp_path):
    config = __import__("dataclasses").replace(
        _config(tmp_path), imap_startup_email_limit=2
    )
    messages = [
        (str(uid), _email(message_id=f"<{uid}@example.com>", ip=f"8.8.8.{uid}"))
        for uid in range(1, 5)
    ]
    mailbox = MagicMock()
    mailbox.select_folder.return_value = ImapFolderState("INBOX", "9")
    mailbox.search_uids_since.return_value = ["4", "2", "1", "3"]
    raw_by_uid = {uid: raw for uid, raw in messages}
    mailbox.fetch_message_peek.side_effect = lambda uid: raw_by_uid[uid]
    monitor = EmailMonitor(config)
    with patch("core.email_monitor.ImapMailbox", return_value=mailbox):
        with patch.object(monitor, "_process_message", return_value="processed") as process:
            summary = monitor.run_startup_scan()

    assert [call.args[0] for call in process.call_args_list] == ["3", "4"]
    assert summary["fetched"] == 2
    checkpoint = database.get_uid_checkpoint(monitor._imap_account, "INBOX")
    assert checkpoint["last_fetched_uid"] == 4


def test_startup_limit_is_applied_to_each_configured_folder(tmp_path):
    config = __import__("dataclasses").replace(
        _config(tmp_path),
        imap_folders=("INBOX", "SOC"),
        imap_startup_email_limit=1,
    )
    mailbox = MagicMock()
    mailbox.select_folder.side_effect = [
        ImapFolderState("INBOX", "11"),
        ImapFolderState("SOC", "22"),
    ]
    mailbox.search_uids_since.side_effect = [["1", "2"], ["8", "9"]]
    mailbox.fetch_message_peek.side_effect = [
        _email(message_id="<inbox-2@example.com>"),
        _email(message_id="<soc-9@example.com>"),
    ]
    monitor = EmailMonitor(config)
    with patch("core.email_monitor.ImapMailbox", return_value=mailbox):
        with patch.object(monitor, "_process_message", return_value="processed") as process:
            monitor.run_startup_scan()

    assert [call.args[0] for call in process.call_args_list] == ["2", "9"]
    assert database.get_uid_checkpoint(monitor._imap_account, "INBOX")["last_fetched_uid"] == 2
    assert database.get_uid_checkpoint(monitor._imap_account, "SOC")["last_fetched_uid"] == 9


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
    assert row["processing_source"] == "startup_scan"
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
    # Origin (8.8.8.8) stays untrusted and Impacted (192.168.20.50, added by
    # _config) is trusted, so the decision reaches "approved_for_blocking"
    # and block_ip is actually invoked -- exercising the mocked "allowed"
    # result as the final guard catching a candidate that became trusted
    # between the decision and the firewall call.
    config = _config(tmp_path)
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


def test_latest_message_is_processed_regardless_of_received_date(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    raw = _email(
        message_id="<old@example.com>",
        received=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    with patch("core.email_monitor.block_ip", return_value="blocked") as block:
        summary = _run_with_messages(config, [("12", raw)])
    block.assert_called_once()
    assert summary["processed"] == 1


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


def test_startup_scan_writes_one_summary_log(tmp_path, caplog):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    with caplog.at_level("INFO"):
        with patch("core.email_monitor.block_ip", return_value="blocked"):
            _run_with_messages(config, [("17", _email(message_id="<logged@example.com>"))])
    matching = [
        record.getMessage() for record in caplog.records
        if "Startup email scan completed" in record.getMessage()
    ]
    assert len(matching) == 1


def test_active_retry_job_owns_processing_during_startup(tmp_path):
    config = _config(tmp_path)
    alert_id = database.record_alert(
        message_id="<retry-owned@example.com>",
        origin_ip="8.8.8.8",
        processing_status="processing_failed",
        action_taken="failed",
    )
    database.reserve_pending_block(
        "8.8.8.8", "Firewall unavailable", alert_id=alert_id
    )

    with patch("core.email_monitor.block_ip") as block:
        summary = _run_with_messages(
            config,
            [("18", _email(message_id="<retry-owned@example.com>"))],
        )

    block.assert_not_called()
    assert summary["skipped"] == 1
    assert database.get_alert(alert_id)["processing_status"] == "processing_failed"


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
