"""Alert Details API integration and security regression tests."""
from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core import database
from core.email_monitor import sanitize_email_html
from web.routes.alert_details import api_get_alert_detail


@pytest.fixture()
def fake_request(tmp_path):
    previous_db_path = database._db_path
    db_path = tmp_path / "details.db"
    allowed_path = tmp_path / "allowed.txt"
    allowed_path.write_text("", encoding="utf-8")
    config = SimpleNamespace(
        database_path=str(db_path), poll_interval=60,
        admin_password="", admin_username="admin", firewall_password="fw-secret",
        email_password="mail-secret", smtp_password="smtp-secret",
    )
    database.init_db(str(db_path))
    yield SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=config)))
    database._db_path = previous_db_path


def _alert(**overrides):
    values = {
        "subject": "SOC alarm", "sender": "soc@example.com", "origin_ip": "8.8.8.8",
        "classification": "Attack", "action_taken": "blocked", "alarm_id": "ALM-42",
        "email_body": "<p>Original alert</p>",
        "parsed_data": json.dumps({"Alarm ID": "ALM-42", "Impacted IP": "10.0.0.5"}),
        "validation_results": json.dumps([
            {"check": "Trusted sender check", "result": "Passed", "message": "trusted"}
        ]),
        "validation_decision": "approved",
    }
    values.update(overrides)
    return database.record_alert(**values)


def test_successful_alert_details_retrieval(fake_request):
    alert_id = _alert()
    body = api_get_alert_detail(alert_id, fake_request)
    assert body["alert"]["id"] == alert_id
    assert body["alert"]["alert_id"] == "ALM-42"
    assert body["parsed_data"]["Impacted IP"] == "10.0.0.5"
    assert body["validation"]["decision"] == "approved"


def test_alert_not_found(fake_request):
    with pytest.raises(HTTPException) as exc_info:
        api_get_alert_detail(999999, fake_request)
    assert exc_info.value.status_code == 404


def test_alert_with_multiple_retries(fake_request):
    alert_id = _alert(action_taken="failed")
    database.reserve_pending_block("8.8.8.8", "timeout", alert_id=alert_id)
    database.record_retry_history("8.8.8.8", 1, "failure", error="timeout", alert_id=alert_id)
    database.record_retry_history("8.8.8.8", 2, "failure", error="still down", alert_id=alert_id)
    body = api_get_alert_detail(alert_id, fake_request)
    assert body["retry"]["total_attempts"] == 2
    assert [row["attempt_number"] for row in body["retry"]["history"]] == [1, 2]
    assert body["retry"]["next_retry_at"]


def test_older_alert_with_missing_fields(fake_request):
    alert_id = database.record_alert(subject="Legacy", sender="old@example.com")
    body = api_get_alert_detail(alert_id, fake_request)
    assert body["email"]["has_body"] is False
    assert body["parsed_data"] == {}
    assert body["validation"]["checks"] == []
    assert body["alert"]["updated_at"]


def test_unsafe_html_email_is_sanitized(fake_request):
    unsafe = '<p onclick="steal()">Safe</p><script>alert(1)</script><a href="java\nscript:bad()">x</a>'
    alert_id = _alert(email_body=unsafe)
    body = api_get_alert_detail(alert_id, fake_request)["email"]
    assert body["body_raw"] == unsafe
    assert "script" not in body["body_sanitized"].lower()
    assert "onclick" not in body["body_sanitized"].lower()
    assert "href" not in body["body_sanitized"].lower()
    assert "Safe" in sanitize_email_html(unsafe)


def test_secrets_are_masked(fake_request):
    alert_id = _alert(
        email_body="password=fw-secret",
        parsed_data=json.dumps({"api_key": "unknown-secret-value"}),
    )
    with database._connect() as conn:
        conn.execute(
            "UPDATE alerts SET reason = ? WHERE id = ?",
            ("token=mail-secret secret=smtp-secret", alert_id),
        )
    text = json.dumps(api_get_alert_detail(alert_id, fake_request))
    assert "fw-secret" not in text
    assert "mail-secret" not in text
    assert "smtp-secret" not in text
    assert "unknown-secret-value" not in text
    assert "***REDACTED***" in text


def test_init_db_migrates_legacy_firewall_actions_before_creating_index(tmp_path):
    """Existing installations must start even when alert_id is not present yet."""
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE firewall_actions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, ip TEXT, "
            "rule_name TEXT, result TEXT, duplicate INTEGER DEFAULT 0, "
            "allowed_list INTEGER DEFAULT 0, notification_sent INTEGER DEFAULT 0, "
            "status TEXT, detail TEXT)"
        )
        conn.commit()

    previous_db_path = database._db_path
    try:
        database.init_db(str(db_path))
        with sqlite3.connect(db_path) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(firewall_actions)")}
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(firewall_actions)")}
        assert "alert_id" in columns
        assert "idx_fw_alert_id" in indexes
    finally:
        database._db_path = previous_db_path
