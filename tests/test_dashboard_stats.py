"""Regression tests for the "Protected Endpoints Ignored" dashboard KPI.

Under the binary trust policy, an alert where both Origin and Impacted are
trusted Protected Endpoints never reaches ``rule_updater.block_ip`` -- the
decision short-circuits to ``decision_status='both_trusted'`` /
``action_taken='ignored'`` before any firewall call is made. The KPI must
therefore be sourced from the alerts table's decision status, not from
``firewall_actions.result='allowed'`` (which only reflects the rare
block-time trust-guard race condition) nor from retired statuses such as
``allowlisted`` or ``protected_endpoint_review``.
"""
from __future__ import annotations

from core import database


def _init(tmp_path) -> None:
    database.init_db(str(tmp_path / "stats.db"))


def test_both_trusted_ignored_alert_is_counted(tmp_path) -> None:
    _init(tmp_path)
    database.record_alert(
        subject="Both trusted",
        origin_ip="10.0.0.1",
        impacted_ip="10.0.0.2",
        status="processed",
        action_taken="ignored",
        reason="Both Origin and Impacted are trusted Protected Endpoints",
        decision_status="both_trusted",
        decision_reason="Both Origin and Impacted are trusted Protected Endpoints",
    )
    stats = database.get_stats()
    assert stats["allowed_ips_ignored"] == 1


def test_both_untrusted_ignored_alert_is_not_counted(tmp_path) -> None:
    _init(tmp_path)
    database.record_alert(
        subject="Both untrusted",
        origin_ip="8.8.8.8",
        impacted_ip="9.9.9.9",
        status="processed",
        action_taken="ignored",
        reason="Neither Origin nor Impacted is a trusted Protected Endpoint",
        decision_status="both_untrusted",
        decision_reason="Neither Origin nor Impacted is a trusted Protected Endpoint",
    )
    stats = database.get_stats()
    assert stats["allowed_ips_ignored"] == 0
    assert stats["neither_endpoint_trusted"] == 1


def test_retired_statuses_are_not_counted(tmp_path) -> None:
    """Alerts created under the old ownership model (before this policy
    existed) must not inflate the KPI just because they share the word
    'allowed' -- only the canonical 'both_trusted' status counts."""
    _init(tmp_path)
    database.record_alert(
        subject="Legacy allowlisted",
        origin_ip="1.1.1.1",
        status="processed",
        action_taken="allowed",
        decision_status="allowlisted",
    )
    database.record_alert(
        subject="Legacy protected endpoint review",
        origin_ip="2.2.2.2",
        status="processed",
        action_taken="ignored",
        decision_status="protected_endpoint_review",
    )
    stats = database.get_stats()
    assert stats["allowed_ips_ignored"] == 0


def test_mixed_alerts_only_count_both_trusted(tmp_path) -> None:
    _init(tmp_path)
    database.record_alert(
        subject="Both trusted 1", action_taken="ignored", decision_status="both_trusted",
    )
    database.record_alert(
        subject="Both trusted 2", action_taken="ignored", decision_status="both_trusted",
    )
    database.record_alert(
        subject="Both untrusted", action_taken="ignored", decision_status="both_untrusted",
    )
    database.record_alert(
        subject="Blocked", action_taken="blocked", decision_status="approved_for_blocking",
    )
    stats = database.get_stats()
    assert stats["allowed_ips_ignored"] == 2
    assert stats["neither_endpoint_trusted"] == 1


def test_query_alerts_filters_by_decision_status(tmp_path) -> None:
    """The Alert History drill-down for this KPI relies on filtering by
    decision_status directly, since action_taken='ignored' alone is shared
    by several unrelated review reasons."""
    _init(tmp_path)
    database.record_alert(
        subject="Both trusted", origin_ip="10.0.0.1",
        action_taken="ignored", decision_status="both_trusted",
    )
    database.record_alert(
        subject="Both untrusted", origin_ip="8.8.8.8",
        action_taken="ignored", decision_status="both_untrusted",
    )

    result = database.query_alerts(decision_status="both_trusted")
    assert result["total"] == 1
    assert result["rows"][0]["subject"] == "Both trusted"


def test_alert_history_exposes_only_successfully_blocked_candidate(tmp_path) -> None:
    _init(tmp_path)
    database.record_alert(
        subject="External destination blocked",
        origin_ip="192.168.10.25",
        impacted_ip="8.8.8.8",
        selected_candidate="8.8.8.8",
        action_taken="blocked",
        firewall_action_performed=True,
    )
    database.record_alert(
        subject="Firewall failed",
        origin_ip="192.168.10.26",
        impacted_ip="9.9.9.9",
        selected_candidate="9.9.9.9",
        action_taken="failed",
        firewall_action_performed=False,
    )

    rows = {row["subject"]: row for row in database.query_alerts()["rows"]}
    assert rows["External destination blocked"]["blocked_ip"] == "8.8.8.8"
    assert rows["Firewall failed"]["blocked_ip"] == ""
