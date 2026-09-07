"""Integration tests for multi-rule blocking across module boundaries.

Where test_multi_rule_blocking.py exercises block_ip in isolation, these
cover how a partial block travels through the rest of the system: the
notification wording, the retry queue, the dashboard counters, and the
settings page.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import core.email_monitor as email_monitor_module
from core import database
from core.email_monitor import (
    EmailMonitor,
    _block_failure_status,
    _parse_failed_rules,
    _partial_block_rows,
    _render_notification,
)
from core.firewall_errors import firewall_exception_message
from core.rule_updater import PartialBlockError, RuleUpdateError

RULE_A = "Block IP"
RULE_B = "Block IP WAN"

_BRANDING = SimpleNamespace(org_name="CPBM", app_name="SecOps")


def _partial(ip: str = "8.8.8.8") -> PartialBlockError:
    return PartialBlockError(ip, [RULE_A], [(RULE_B, "Firewall API returned HTTP 502")])


# --------------------------------------------------------------------------
# Error message plumbing
# --------------------------------------------------------------------------

class TestPartialErrorPlumbing:
    def test_partial_message_survives_the_safe_message_translator(self) -> None:
        """firewall_exception_message must not flatten a partial to a generic string.

        The rule names have to reach both the notification and
        pending_blocks.last_error, which is where the resolution email
        reads them back from.
        """
        message = firewall_exception_message(_partial())
        assert RULE_A in message
        assert RULE_B in message

    def test_generic_firewall_errors_are_still_translated(self) -> None:
        import requests

        message = firewall_exception_message(
            requests.exceptions.ConnectionError("boom")
        )
        assert message == "Firewall is currently unreachable"

    def test_failed_rule_names_round_trip_through_the_stored_error(self) -> None:
        stored = firewall_exception_message(_partial())
        assert _parse_failed_rules(stored) == [RULE_B]

    def test_multiple_failed_rules_round_trip(self) -> None:
        error = PartialBlockError(
            "8.8.8.8", [RULE_A], [(RULE_B, "HTTP 502"), ("Block DMZ", "missing")]
        )
        assert _parse_failed_rules(str(error)) == [RULE_B, "Block DMZ"]

    def test_ordinary_failure_yields_no_rule_names(self) -> None:
        assert _parse_failed_rules("Firewall is currently unreachable") == []

    def test_empty_last_error_is_safe(self) -> None:
        assert _parse_failed_rules("") == []


# --------------------------------------------------------------------------
# Notification content
# --------------------------------------------------------------------------

class TestPartialNotification:
    def test_partial_uses_the_partially_blocked_status(self) -> None:
        status, tag = _block_failure_status(_partial())
        assert status == "PARTIALLY BLOCKED"
        assert tag == "PARTIAL"

    def test_total_failure_keeps_the_retry_scheduled_status(self) -> None:
        status, tag = _block_failure_status(RuleUpdateError("everything failed"))
        assert status == "RETRY SCHEDULED"
        assert tag == "ALERT"

    def test_partial_rows_name_both_sides(self) -> None:
        rows = dict(_partial_block_rows(_partial()))
        assert rows["Blocked In Rules"] == RULE_A
        assert RULE_B in rows["Failed In Rules"]

    def test_partial_rows_report_none_when_nothing_succeeded(self) -> None:
        error = PartialBlockError("8.8.8.8", [], [(RULE_B, "HTTP 502")])
        assert dict(_partial_block_rows(error))["Blocked In Rules"] == "None"

    def test_nonexistent_rule_reason_reaches_the_notification(self) -> None:
        error = PartialBlockError(
            "8.8.8.8",
            [RULE_A],
            [("Typo Rule", "Firewall rule 'Typo Rule' does not exist on the firewall.")],
        )
        rows = dict(_partial_block_rows(error))
        assert "does not exist" in rows["Failed In Rules"]
        assert "Typo Rule" in rows["Failed In Rules"]

    def test_rendered_partial_email_names_the_failing_rule(self) -> None:
        error = _partial()
        plain, html = _render_notification(
            _BRANDING,
            "PARTIALLY BLOCKED",
            "Partially blocked 8.8.8.8",
            "ALARM-123",
            [("Alarm ID", "ALARM-123"), *_partial_block_rows(error)],
        )
        assert "PARTIALLY BLOCKED" in plain
        assert RULE_B in plain
        assert "ALARM-123" in plain
        assert RULE_B in html


# --------------------------------------------------------------------------
# Retry queue
# --------------------------------------------------------------------------

class TestPartialRetryQueue:
    def _monitor(self, config) -> EmailMonitor:
        monitor = EmailMonitor.__new__(EmailMonitor)
        monitor._config = config
        return monitor

    def test_partial_block_is_queued_for_retry_like_a_failure(
        self, monkeypatch
    ) -> None:
        """A partial block must land in pending_blocks, not be treated as done."""
        ip = "203.0.113.10"
        error = _partial(ip)
        database.reserve_pending_block(ip, firewall_exception_message(error))

        entry = database.get_pending_block(ip)
        assert entry is not None
        assert _parse_failed_rules(entry["last_error"]) == [RULE_B]

    def test_retry_reattempts_the_queued_ip(self, monkeypatch) -> None:
        ip = "203.0.113.11"
        database.reserve_pending_block(ip, firewall_exception_message(_partial(ip)))
        config = SimpleNamespace(
            firewall_rule_names=(RULE_A, RULE_B), poll_interval=60,
            org_name="CPBM", app_name="SecOps",
        )
        seen: dict[str, str] = {}

        def _fake_block_ip(target_ip, cfg, alert_id=None):
            seen["ip"] = target_ip
            return "duplicate"  # avoids the notification path

        monkeypatch.setattr(email_monitor_module, "block_ip", _fake_block_ip)
        self._monitor(config)._retry_pending_blocks()

        assert seen["ip"] == ip

    def test_successful_retry_email_names_the_previously_failed_rule(
        self, monkeypatch
    ) -> None:
        """Q1: the resolution email says which rule the retry actually fixed."""
        ip = "203.0.113.12"
        database.reserve_pending_block(
            ip, firewall_exception_message(_partial(ip)), alarm_id="ALARM-77"
        )
        config = SimpleNamespace(
            firewall_rule_names=(RULE_A, RULE_B), poll_interval=60,
            org_name="CPBM", app_name="SecOps",
            notification_email="ops@example.com",
        )
        sent: dict[str, str] = {}

        monkeypatch.setattr(
            email_monitor_module, "block_ip", lambda *a, **k: "blocked"
        )

        def _capture(cfg, subject, body, html_body=None):
            sent["subject"] = subject
            sent["body"] = body
            return True

        monkeypatch.setattr(email_monitor_module, "_notify", _capture)
        self._monitor(config)._retry_pending_blocks()

        assert "already blocked" in sent["body"]
        assert RULE_B in sent["body"]
        assert "ALARM-77" in sent["body"]
        assert "attempt" in sent["body"].lower()

    def test_successful_retry_after_a_plain_failure_uses_generic_wording(
        self, monkeypatch
    ) -> None:
        """A non-partial failure has no rule list, so wording must not claim one."""
        ip = "203.0.113.13"
        database.reserve_pending_block(ip, "Firewall is currently unreachable")
        config = SimpleNamespace(
            firewall_rule_names=(RULE_A, RULE_B), poll_interval=60,
            org_name="CPBM", app_name="SecOps",
            notification_email="ops@example.com",
        )
        sent: dict[str, str] = {}

        monkeypatch.setattr(
            email_monitor_module, "block_ip", lambda *a, **k: "blocked"
        )
        monkeypatch.setattr(
            email_monitor_module,
            "_notify",
            lambda cfg, subject, body, html_body=None: sent.update(body=body) or True,
        )
        self._monitor(config)._retry_pending_blocks()

        assert "already blocked" not in sent["body"]
        assert "previously failed to block" in sent["body"]

    def test_resolved_retry_leaves_the_queue(self, monkeypatch) -> None:
        ip = "203.0.113.14"
        database.reserve_pending_block(ip, firewall_exception_message(_partial(ip)))
        config = SimpleNamespace(
            firewall_rule_names=(RULE_A, RULE_B), poll_interval=60,
            org_name="CPBM", app_name="SecOps",
            notification_email="ops@example.com",
        )
        monkeypatch.setattr(
            email_monitor_module, "block_ip", lambda *a, **k: "blocked"
        )
        monkeypatch.setattr(
            email_monitor_module, "_notify", lambda *a, **k: True
        )
        self._monitor(config)._retry_pending_blocks()

        assert database.get_pending_block(ip) is None

    def test_still_failing_retry_stays_queued_with_no_limit(
        self, monkeypatch
    ) -> None:
        """There is no attempt cap: the row survives repeated failures."""
        ip = "203.0.113.15"
        database.reserve_pending_block(ip, firewall_exception_message(_partial(ip)))
        config = SimpleNamespace(
            firewall_rule_names=(RULE_A, RULE_B), poll_interval=60,
            org_name="CPBM", app_name="SecOps",
        )

        def _still_partial(*a, **k):
            raise _partial(ip)

        monkeypatch.setattr(email_monitor_module, "block_ip", _still_partial)
        monitor = self._monitor(config)
        for _ in range(5):
            monitor._retry_pending_blocks()

        entry = database.get_pending_block(ip)
        assert entry is not None
        assert entry["attempts"] >= 5


# --------------------------------------------------------------------------
# Dashboard counters
# --------------------------------------------------------------------------

class TestDashboardCounts:
    def test_partial_does_not_count_toward_blocked_kpi(self) -> None:
        """Partial rolls up as failed: only fully-successful rules count."""
        database.record_firewall_action(
            ip="8.8.8.8", rule_name=RULE_A, result="blocked", status="success"
        )
        database.record_firewall_action(
            ip="8.8.8.8", rule_name=RULE_B, result="failed", status="failure"
        )

        rows = database.list_firewall_actions_for_ip("8.8.8.8")
        blocked = [r for r in rows if r["result"] == "blocked"]
        failed = [r for r in rows if r["result"] == "failed"]
        assert len(blocked) == 1
        assert len(failed) == 1

    def test_history_keeps_one_row_per_rule(self) -> None:
        """The table shows per-rule truth even though the KPI says failed."""
        for rule, result, status in (
            (RULE_A, "blocked", "success"),
            (RULE_B, "failed", "failure"),
        ):
            database.record_firewall_action(
                ip="9.9.9.9", rule_name=rule, result=result, status=status
            )

        rows = database.list_firewall_actions_for_ip("9.9.9.9")
        assert {r["rule_name"] for r in rows} == {RULE_A, RULE_B}


# --------------------------------------------------------------------------
# Settings page
# --------------------------------------------------------------------------

class TestSettingsService:
    def test_comma_separated_rule_names_are_accepted(self, monkeypatch, tmp_path):
        import web.services.settings_service as settings

        env_path = tmp_path / ".env"
        env_path.write_text("FIREWALL_RULE_NAMES=Block IP\n", encoding="utf-8")
        monkeypatch.setattr(settings, "_ENV_PATH", str(env_path))

        errors = settings.save_settings({"FIREWALL_RULE_NAMES": "Block IP, Block IP WAN"})

        assert errors == []
        assert "Block IP, Block IP WAN" in env_path.read_text(encoding="utf-8")

    def test_blank_rule_names_leave_the_existing_value_untouched(
        self, monkeypatch, tmp_path
    ):
        import web.services.settings_service as settings

        env_path = tmp_path / ".env"
        env_path.write_text("FIREWALL_RULE_NAMES=Block IP\n", encoding="utf-8")
        monkeypatch.setattr(settings, "_ENV_PATH", str(env_path))

        settings.save_settings({"FIREWALL_RULE_NAMES": "   "})

        assert "Block IP" in env_path.read_text(encoding="utf-8")

    def test_legacy_singular_key_is_shown_in_the_form(self, monkeypatch, tmp_path):
        import web.services.settings_service as settings

        env_path = tmp_path / ".env"
        env_path.write_text("FIREWALL_RULE_NAME=Legacy Rule\n", encoding="utf-8")
        monkeypatch.setattr(settings, "_ENV_PATH", str(env_path))

        loaded = settings.load_settings()

        assert loaded["firewall"]["FIREWALL_RULE_NAMES"]["value"] == "Legacy Rule"

    def test_form_hint_explains_comma_separation(self, monkeypatch, tmp_path):
        import web.services.settings_service as settings

        env_path = tmp_path / ".env"
        env_path.write_text("FIREWALL_RULE_NAMES=Block IP\n", encoding="utf-8")
        monkeypatch.setattr(settings, "_ENV_PATH", str(env_path))

        hint = settings.load_settings()["firewall"]["FIREWALL_RULE_NAMES"]["hint"]

        assert hint and "omma" in hint
