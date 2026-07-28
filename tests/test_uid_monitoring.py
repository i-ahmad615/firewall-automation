"""Folder-aware UID polling and raw-message durability tests."""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from core import database
from core.email_client import ImapFolderState, ImapMailbox
from core.email_monitor import EmailMonitor, _is_from_trusted_sender
from tests.test_email_catchup import _config, _email


def _mailbox(uidvalidity: str = "7", uids: list[str] | None = None) -> MagicMock:
    mailbox = MagicMock()
    mailbox.select_folder.side_effect = lambda folder: ImapFolderState(folder, uidvalidity)
    mailbox.search_uids_since.return_value = list(uids or [])
    return mailbox


@pytest.mark.parametrize("was_seen", [True, False], ids=["read", "unread"])
def test_newer_uid_is_processed_independent_of_seen_state(tmp_path, was_seen):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    database.reset_uid_checkpoint(
        f"{config.email_username}|{config.imap_host}:{config.imap_port}", "INBOX", "7"
    )
    database.advance_uid_checkpoint(
        f"{config.email_username}|{config.imap_host}:{config.imap_port}", "INBOX", "7", 40
    )
    mailbox = _mailbox(uids=["41"])
    mailbox.fetch_message_peek.return_value = _email(
        message_id=f"<seen-{was_seen}@example.com>"
    )
    monitor = EmailMonitor(config)
    monitor._needs_uid_reconciliation = False
    with patch("core.email_monitor.block_ip", return_value="blocked") as block:
        with patch("core.email_monitor.send_notification"):
            assert monitor._poll_folder(mailbox, "INBOX") == 1
    block.assert_called_once()
    mailbox.search_uids_since.assert_called_once_with(41)


def test_fetch_uses_body_peek_without_marking_seen():
    config = _config(__import__("pathlib").Path("."))
    mailbox = ImapMailbox(config)
    connection = MagicMock()
    connection.uid.return_value = ("OK", [(b"metadata", b"raw-message")])
    mailbox._conn = connection
    assert mailbox.fetch_message_peek("52") == b"raw-message"
    connection.uid.assert_called_once_with("FETCH", "52", "(BODY.PEEK[])")


def test_uid_search_does_not_use_unseen():
    config = _config(__import__("pathlib").Path("."))
    mailbox = ImapMailbox(config)
    connection = MagicMock()
    connection.uid.return_value = ("OK", [b"41 42"])
    mailbox._conn = connection
    assert mailbox.search_uids_since(41) == ["41", "42"]
    connection.uid.assert_called_once_with("SEARCH", None, "UID", "41:*")
    assert "UNSEEN" not in repr(connection.uid.call_args)


def test_display_name_and_case_insensitive_sender_normalization():
    assert _is_from_trusted_sender(
        "  TITANIUM SOC <SOC@Example.COM>  ", {"soc@example.com"}
    )


def test_reconnection_reconciles_recent_uid_gap(tmp_path):
    config = replace(_config(tmp_path), imap_uid_reconcile_count=20)
    database.init_db(config.database_path)
    account = f"{config.email_username}|{config.imap_host}:{config.imap_port}"
    database.reset_uid_checkpoint(account, "INBOX", "9")
    database.advance_uid_checkpoint(account, "INBOX", "9", 100)
    mailbox = _mailbox("9", [])
    monitor = EmailMonitor(config)
    monitor._needs_uid_reconciliation = True
    monitor._poll_folder(mailbox, "INBOX")
    mailbox.search_uids_since.assert_called_once_with(81)


def test_server_returning_checkpoint_uid_is_not_counted_or_fetched(tmp_path):
    """Guard against IMAP servers resolving ``333:*`` as including UID 332."""
    config = _config(tmp_path)
    database.init_db(config.database_path)
    account = f"{config.email_username}|{config.imap_host}:{config.imap_port}"
    database.reset_uid_checkpoint(account, "INBOX", "9")
    database.advance_uid_checkpoint(account, "INBOX", "9", 332)
    mailbox = _mailbox("9", ["332"])
    monitor = EmailMonitor(config)
    monitor._needs_uid_reconciliation = False

    assert monitor._poll_folder(mailbox, "INBOX") == 0
    mailbox.search_uids_since.assert_called_once_with(333)
    mailbox.fetch_message_peek.assert_not_called()
    assert database.get_uid_checkpoint(account, "INBOX")["last_fetched_uid"] == 332


def test_uidvalidity_change_resets_and_reconciles_without_duplicate_action(tmp_path, caplog):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    account = f"{config.email_username}|{config.imap_host}:{config.imap_port}"
    database.reset_uid_checkpoint(account, "INBOX", "old")
    database.advance_uid_checkpoint(account, "INBOX", "old", 500)
    database.record_alert(
        message_id="<duplicate-validity@example.com>",
        processing_status="blocked_successfully",
        action_taken="blocked",
    )
    mailbox = _mailbox("new", ["3"])
    mailbox.fetch_message_peek.return_value = _email(
        message_id="<duplicate-validity@example.com>"
    )
    monitor = EmailMonitor(config)
    with patch("core.email_monitor.block_ip") as block:
        monitor._poll_folder(mailbox, "INBOX")
    block.assert_not_called()
    checkpoint = database.get_uid_checkpoint(account, "INBOX")
    assert checkpoint["uidvalidity"] == "new"
    assert checkpoint["last_fetched_uid"] == 3
    assert "UID checkpoint reset safely" in caplog.text


def test_duplicate_message_id_across_folders_blocks_only_once(tmp_path):
    config = replace(_config(tmp_path), imap_folders=("INBOX", "SOC"))
    database.init_db(config.database_path)
    raw = _email(message_id="<same-message@example.com>")
    inbox = _mailbox("1", ["8"])
    soc = _mailbox("2", ["9"])
    inbox.fetch_message_peek.return_value = raw
    soc.fetch_message_peek.return_value = raw
    monitor = EmailMonitor(config)
    with patch("core.email_monitor.block_ip", return_value="blocked") as block:
        with patch("core.email_monitor.send_notification"):
            monitor._poll_folder(inbox, "INBOX")
            monitor._poll_folder(soc, "SOC")
    block.assert_called_once()


def test_run_once_polls_all_configured_folders(tmp_path):
    config = replace(_config(tmp_path), imap_folders=("INBOX", "SOC Alerts"))
    database.init_db(config.database_path)
    mailbox = _mailbox("4", [])
    with patch("core.email_monitor.ImapMailbox", return_value=mailbox):
        monitor = EmailMonitor(config)
        with patch.object(monitor, "_retry_pending_blocks"):
            monitor.run_once()
    assert mailbox.select_folder.call_count == 2
    assert [call.args[0] for call in mailbox.select_folder.call_args_list] == [
        "INBOX", "SOC Alerts"
    ]


def test_processing_failure_keeps_raw_email_and_advances_checkpoint(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    mailbox = _mailbox("12", ["77"])
    raw = _email(message_id="<durable@example.com>")
    mailbox.fetch_message_peek.return_value = raw
    monitor = EmailMonitor(config)
    with patch.object(monitor, "_process_message", side_effect=RuntimeError("parse broke")):
        assert monitor._poll_folder(mailbox, "INBOX") == 1
    account = f"{config.email_username}|{config.imap_host}:{config.imap_port}"
    checkpoint = database.get_uid_checkpoint(account, "INBOX")
    assert checkpoint["last_fetched_uid"] == 77
    with database._connect() as connection:
        stored = connection.execute("SELECT * FROM stored_emails").fetchone()
    assert bytes(stored["raw_message"]) == raw
    assert stored["processing_status"] == "processing_failed"
