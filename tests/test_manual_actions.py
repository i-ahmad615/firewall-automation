"""Tests for core/manual_actions.py

Covers: IP eligibility validation (invalid/private/loopback/multicast/
        reserved/allowlisted), duplicate detection, protected-IP unblock
        rejection, and selective retry-queue enqueueing on firewall failure.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

import pytest

from core.manual_actions import (
    IneligibleIPError,
    ProtectedIPError,
    manual_block_ip,
    manual_unblock_ip,
    validate_blockable_ip,
)
from core.rule_updater import RuleUpdateError
from core.firewall_client import FirewallAPIError


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_ENV_BASE: dict[str, str] = {
    "FIREWALL_HOST": "192.168.1.1",
    "FIREWALL_PORT": "4444",
    "FIREWALL_USERNAME": "admin",
    "FIREWALL_PASSWORD": "pass",
    "FIREWALL_RULE_NAME": "Block IP",
    "IMAP_HOST": "outlook.office365.com",
    "IMAP_PORT": "993",
    "EMAIL_USERNAME": "user@example.com",
    "EMAIL_PASSWORD": "emailpass",
    "SMTP_HOST": "smtp.office365.com",
    "SMTP_PORT": "587",
    "NOTIFICATION_EMAIL": "security-alerts@example.com",
    "TRUSTED_SENDERS": "alerts@company.com",
    "ALERT_KEYWORDS": "attack",
}


def _make_config(monkeypatch: pytest.MonkeyPatch, allowed_file: str = ""):
    from core.config import load_config
    for k, v in _ENV_BASE.items():
        monkeypatch.setenv(k, v)
    if allowed_file:
        monkeypatch.setenv("ALLOWED_IPS_FILE", allowed_file)
    else:
        monkeypatch.setenv("ALLOWED_IPS_FILE", "config/nonexistent_allowed.txt")
    return load_config()


def _make_response(existing_ips: list[str]) -> ET.Element:
    networks_xml = "".join(f"<Network>{ip}</Network>" for ip in existing_ips)
    return ET.fromstring(
        f"<Response>"
        f"  <FirewallRule>"
        f"    <Name>Block IP</Name>"
        f"    <NetworkPolicy>"
        f"      <SourceNetworks>{networks_xml}</SourceNetworks>"
        f"    </NetworkPolicy>"
        f"  </FirewallRule>"
        f"</Response>"
    )


def _mock_client(get_response: ET.Element) -> MagicMock:
    client = MagicMock()
    client.last_response = ""
    client.get_firewall_rule.return_value = get_response
    client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
    client.create_ip_host.return_value = None
    client.delete_ip_host.return_value = None
    return client


# ──────────────────────────────────────────────────────────────────────────────
# validate_blockable_ip
# ──────────────────────────────────────────────────────────────────────────────

class TestValidateBlockableIp:
    def test_valid_public_ip_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        assert validate_blockable_ip("8.8.8.8", config) == "8.8.8.8"

    def test_invalid_syntax_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError, match="not a valid IP"):
            validate_blockable_ip("not-an-ip", config)

    def test_loopback_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError, match="loopback"):
            validate_blockable_ip("127.0.0.1", config)

    def test_private_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError, match="private"):
            validate_blockable_ip("192.168.1.5", config)

    def test_multicast_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError, match="multicast"):
            validate_blockable_ip("224.0.0.1", config)

    def test_reserved_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError, match="reserved"):
            validate_blockable_ip("240.0.0.1", config)

    def test_unspecified_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError):
            validate_blockable_ip("0.0.0.0", config)

    def test_allowlisted_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        allowed_file = tmp_path / "allowed.txt"
        allowed_file.write_text("8.8.4.4\n")
        config = _make_config(monkeypatch, str(allowed_file))
        with pytest.raises(IneligibleIPError, match="allow"):
            validate_blockable_ip("8.8.4.4", config)


# ──────────────────────────────────────────────────────────────────────────────
# manual_block_ip
# ──────────────────────────────────────────────────────────────────────────────

class TestManualBlockIp:
    def test_valid_block_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response([]))
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            outcome = manual_block_ip("8.8.8.8", "test reason", config)
        assert outcome.result == "blocked"
        assert outcome.ip == "8.8.8.8"
        mock_client.create_ip_host.assert_called_once_with("blocked-8-8-8-8", "8.8.8.8")

    def test_valid_block_records_manual_source_and_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response([]))
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch("core.database.record_firewall_action") as mock_record:
                manual_block_ip("8.8.8.8", "brute force", config)
        _, kwargs = mock_record.call_args
        assert kwargs["source"] == "manual"
        assert kwargs["reason"] == "brute force"
        assert kwargs["result"] == "blocked"

    def test_invalid_ip_rejected_before_touching_firewall(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        with patch("core.rule_updater.SophosClient") as mock_cls:
            with pytest.raises(IneligibleIPError):
                manual_block_ip("not-an-ip", "", config)
        mock_cls.assert_not_called()

    def test_private_ip_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        with pytest.raises(IneligibleIPError, match="private"):
            manual_block_ip("10.0.0.5", "", config)

    def test_allowlisted_ip_rejected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        allowed_file = tmp_path / "allowed.txt"
        allowed_file.write_text("8.8.4.4\n")
        config = _make_config(monkeypatch, str(allowed_file))
        with pytest.raises(IneligibleIPError, match="allow"):
            manual_block_ip("8.8.4.4", "", config)

    def test_duplicate_block_returns_duplicate_not_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response(["blocked-8-8-8-8"]))
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            outcome = manual_block_ip("8.8.8.8", "", config)
        assert outcome.result == "duplicate"
        mock_client.create_ip_host.assert_not_called()
        mock_client.set_firewall_rule.assert_not_called()

    def test_recoverable_firewall_failure_is_queued_for_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.get_firewall_rule.side_effect = FirewallAPIError("timeout", code="500")
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch("core.database.reserve_pending_block") as mock_reserve:
                with pytest.raises(RuleUpdateError):
                    manual_block_ip("8.8.8.8", "", config)
        mock_reserve.assert_called_once()
        assert mock_reserve.call_args[0][0] == "8.8.8.8"

    def test_non_recoverable_failure_is_not_queued_for_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing/misconfigured rule name would fail identically on every
        retry -- it must not be silently queued forever."""
        config = _make_config(monkeypatch)
        bad_response = ET.fromstring(
            "<Response><FirewallRule><Name>Other Rule</Name></FirewallRule></Response>"
        )
        mock_client = _mock_client(bad_response)
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch("core.database.reserve_pending_block") as mock_reserve:
                with pytest.raises(RuleUpdateError):
                    manual_block_ip("8.8.8.8", "", config)
        mock_reserve.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# manual_unblock_ip
# ──────────────────────────────────────────────────────────────────────────────

class TestManualUnblockIp:
    def test_successful_unblock(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
        mock_client.delete_ip_host.return_value = None
        mock_client.get_firewall_rule.side_effect = [
            _make_response(["blocked-8-8-8-8"]),
            _make_response([]),
        ]
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch("core.database.get_blocked_ip", return_value=None):
                with patch("core.database.mark_ip_unblocked") as mock_mark:
                    outcome = manual_unblock_ip("8.8.8.8", config)
        assert outcome.result == "unblocked"
        mock_mark.assert_called_once_with("8.8.8.8", source="manual")

    def test_not_currently_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response([]))
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch("core.database.get_blocked_ip", return_value=None):
                outcome = manual_unblock_ip("9.9.9.9", config)
        assert outcome.result == "not_blocked"

    def test_firewall_failure_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = _make_config(monkeypatch)
        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.get_firewall_rule.side_effect = FirewallAPIError("timeout", code="500")
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch("core.database.get_blocked_ip", return_value=None):
                with pytest.raises(RuleUpdateError):
                    manual_unblock_ip("8.8.8.8", config)

    def test_protected_ip_rejected_before_touching_firewall(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        with patch(
            "core.database.get_blocked_ip",
            return_value={"ip": "8.8.8.8", "protected": 1},
        ):
            with patch("core.rule_updater.SophosClient") as mock_cls:
                with pytest.raises(ProtectedIPError):
                    manual_unblock_ip("8.8.8.8", config)
        mock_cls.assert_not_called()

    def test_non_protected_ip_with_row_proceeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
        mock_client.delete_ip_host.return_value = None
        mock_client.get_firewall_rule.side_effect = [
            _make_response(["blocked-8-8-8-8"]),
            _make_response([]),
        ]
        with patch("core.rule_updater.SophosClient", return_value=mock_client):
            with patch(
                "core.database.get_blocked_ip",
                return_value={"ip": "8.8.8.8", "protected": 0},
            ):
                with patch("core.database.mark_ip_unblocked"):
                    outcome = manual_unblock_ip("8.8.8.8", config)
        assert outcome.result == "unblocked"
