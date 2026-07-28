"""Selected-row deletion for alert and firewall action history."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core import database
from web.routes.api import (
    DeleteSelectedBody,
    delete_selected_alerts,
    delete_selected_firewall_actions,
)


@pytest.fixture()
def database_request(tmp_path):
    previous_db_path = database._db_path
    database.init_db(str(tmp_path / "bulk-delete.db"))
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(config=SimpleNamespace(admin_password=""))
        )
    )
    yield request
    database._db_path = previous_db_path


def test_delete_selected_alerts_only_removes_requested_ids(database_request):
    first = database.record_alert(subject="First")
    second = database.record_alert(subject="Second")
    third = database.record_alert(subject="Third")

    result = delete_selected_alerts(
        DeleteSelectedBody(ids=[first, third, first]), database_request
    )

    assert result == {"deleted": 2}
    assert database.get_alert(first) is None
    assert database.get_alert(second) is not None
    assert database.get_alert(third) is None


def test_delete_selected_firewall_actions_only_removes_requested_ids(database_request):
    for ip in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        database.record_firewall_action(ip=ip, result="blocked")
    rows = database.query_firewall_actions(page_size=10)["rows"]
    selected = [rows[0]["id"], rows[2]["id"]]
    remaining_id = rows[1]["id"]

    result = delete_selected_firewall_actions(
        DeleteSelectedBody(ids=selected), database_request
    )

    assert result == {"deleted": 2}
    remaining = database.query_firewall_actions(page_size=10)["rows"]
    assert [row["id"] for row in remaining] == [remaining_id]


def test_delete_selected_rejects_empty_selection(database_request):
    with pytest.raises(HTTPException) as exc_info:
        delete_selected_alerts(DeleteSelectedBody(ids=[]), database_request)
    assert exc_info.value.status_code == 400


def test_delete_rows_by_ids_rejects_unknown_table(database_request):
    with pytest.raises(ValueError):
        database.delete_rows_by_ids("logs", [1])
