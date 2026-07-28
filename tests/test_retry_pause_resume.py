"""Persistent pause and resume controls for automatic firewall retries."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core import database
from web.routes.api import (
    pause_pending_block,
    pending_blocks,
    resume_pending_block,
)


@pytest.fixture()
def retry_request(tmp_path):
    previous_db_path = database._db_path
    database.init_db(str(tmp_path / "retry-controls.db"))
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                config=SimpleNamespace(admin_password="", poll_interval=60)
            )
        )
    )
    yield request
    database._db_path = previous_db_path


def test_pause_and_resume_preserve_retry_entry_and_attempt_count(retry_request):
    database.reserve_pending_block("8.8.8.8", "firewall unavailable")
    original = database.get_pending_block("8.8.8.8")

    assert pause_pending_block("8.8.8.8", retry_request) == {
        "paused": True,
        "ip": "8.8.8.8",
    }
    paused = database.get_pending_block("8.8.8.8")
    assert paused["active"] is False
    assert paused["status"] == "paused"
    assert paused["attempts"] == original["attempts"]
    assert database.list_pending_blocks() == []

    queue = pending_blocks(retry_request)
    assert queue["rows"][0]["status"] == "paused"
    assert queue["rows"][0]["next_retry_at"] == ""

    assert resume_pending_block("8.8.8.8", retry_request) == {
        "resumed": True,
        "ip": "8.8.8.8",
    }
    resumed = database.get_pending_block("8.8.8.8")
    assert resumed["active"] is True
    assert resumed["status"] == "pending"
    assert resumed["attempts"] == original["attempts"]
    assert [row["ip"] for row in database.list_pending_blocks()] == ["8.8.8.8"]


def test_pause_and_resume_reject_invalid_state_transitions(retry_request):
    database.reserve_pending_block("1.1.1.1", "timeout")

    with pytest.raises(HTTPException) as resume_active:
        resume_pending_block("1.1.1.1", retry_request)
    assert resume_active.value.status_code == 404

    pause_pending_block("1.1.1.1", retry_request)
    with pytest.raises(HTTPException) as pause_again:
        pause_pending_block("1.1.1.1", retry_request)
    assert pause_again.value.status_code == 404
