"""Tests for core/rule_updater.py

Covers: allowed IP, duplicate IP, new IP, invalid rule ID / missing rule,
        upload success, upload failure.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import pytest
from unittest.mock import MagicMock, patch

from core.rule_updater import block_ip, RuleUpdateError
from core.firewall_client import FirewallAPIError
from core import database
from core.endpoint_registry import normalize_value


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


def _make_config(monkeypatch: pytest.MonkeyPatch, allowed_file: str = "") -> "AppConfig":  # type: ignore[name-defined]
    from core.config import load_config
    for k, v in _ENV_BASE.items():
        monkeypatch.setenv(k, v)
    if database.get_protected_endpoint_by_normalized("192.168.250.0/24") is None:
        database.add_protected_endpoint(
            "192.168.250.0/24", "192.168.250.0/24", "CIDR", "CENTURY_OWNED"
        )
    if allowed_file:
        for value in open(allowed_file, encoding="utf-8").read().splitlines():
            if value.strip():
                normalized, kind = normalize_value(value)
                database.add_protected_endpoint(value, normalized, kind, "EXTERNAL_ALLOWLIST")
    return load_config()


def _make_response(existing_ips: list[str]) -> ET.Element:
    """Build a minimal SFOS GET response containing a Block IP rule."""
    networks_xml = "".join(f"<Network>{ip}</Network>" for ip in existing_ips)
    return ET.fromstring(
        f"<Response>"
        f"  <FirewallRule>"
        f"    <Name>Block IP</Name>"
        f"    <Status>Enable</Status>"
        f"    <NetworkPolicy>"
        f"      <Action>Reject</Action>"
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
    client.create_ip_host.return_value = None  # void
    return client


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Tests
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestBlockIp:
    def test_allowed_ip_returns_allowed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
    ) -> None:
        allowed_file = tmp_path / "allowed.txt"
        allowed_file.write_text("10.0.0.1\n")
        config = _make_config(monkeypatch, str(allowed_file))
        mock_client = _mock_client(_make_response([]))

        result = block_ip("10.0.0.1", config, client=mock_client)

        assert result == "allowed"
        mock_client.get_firewall_rule.assert_not_called()
        mock_client.set_firewall_rule.assert_not_called()

    def test_non_allowed_ip_proceeds(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
    ) -> None:
        allowed_file = tmp_path / "allowed.txt"
        allowed_file.write_text("10.0.0.1\n")
        config = _make_config(monkeypatch, str(allowed_file))
        mock_client = _mock_client(_make_response([]))

        # 8.8.8.8 is NOT in the allowed list
        result = block_ip("8.8.8.8", config, client=mock_client)
        assert result in ("blocked", "duplicate")

    def test_duplicate_ip_returns_duplicate_raw(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Raw IP already in rule -> duplicate (legacy/edge case)."""
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response(["1.1.1.1", "2.2.2.2"]))

        result = block_ip("1.1.1.1", config, client=mock_client)

        assert result == "duplicate"
        mock_client.set_firewall_rule.assert_not_called()

    def test_duplicate_ip_returns_duplicate_host_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Host-name entry already in rule -> duplicate (normal case)."""
        config = _make_config(monkeypatch)
        # Rule already contains the host object name from a previous run
        mock_client = _mock_client(_make_response(["blocked-1-1-1-1", "blocked-2-2-2-2"]))

        result = block_ip("1.1.1.1", config, client=mock_client)

        assert result == "duplicate"
        mock_client.create_ip_host.assert_not_called()
        mock_client.set_firewall_rule.assert_not_called()

    def test_duplicate_rule_entry_does_not_touch_host_object(self, monkeypatch):
        """Catch-up idempotency: rule duplicate is detected before host checks."""
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response(["blocked-1-1-1-1"]))

        assert block_ip("1.1.1.1", config, client=mock_client) == "duplicate"

        mock_client.ip_host_exists.assert_not_called()
        mock_client.create_ip_host.assert_not_called()
        mock_client.set_firewall_rule.assert_not_called()

    def test_existing_host_is_reused_without_duplicate_creation(self, monkeypatch):
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response([]))
        mock_client.ip_host_exists.return_value = True

        assert block_ip("3.3.3.3", config, client=mock_client) == "blocked"

        mock_client.ip_host_exists.assert_called_once_with("blocked-3-3-3-3", "3.3.3.3")
        mock_client.create_ip_host.assert_not_called()
        mock_client.set_firewall_rule.assert_called_once()

    def test_new_ip_returns_blocked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response(["1.1.1.1"]))

        result = block_ip("3.3.3.3", config, client=mock_client)

        assert result == "blocked"
        mock_client.create_ip_host.assert_called_once_with("blocked-3-3-3-3", "3.3.3.3")
        mock_client.set_firewall_rule.assert_called_once()

    def test_existing_ips_preserved_on_new_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        # Pre-existing entries are host object names (as SFOS stores them)
        mock_client = _mock_client(_make_response(["blocked-1-1-1-1", "blocked-2-2-2-2"]))

        block_ip("3.3.3.3", config, client=mock_client)

        call_args = mock_client.set_firewall_rule.call_args
        updated_rule: ET.Element = call_args[0][0]
        networks = [n.text for n in updated_rule.findall(".//SourceNetworks/Network")]
        # Existing host names are preserved
        assert "blocked-1-1-1-1" in networks
        assert "blocked-2-2-2-2" in networks
        # New host name (not raw IP) is appended
        assert "blocked-3-3-3-3" in networks
        assert "3.3.3.3" not in networks

    def test_create_ip_host_called_before_upload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """create_ip_host must be called before set_firewall_rule."""
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response([]))
        call_order: list[str] = []
        mock_client.create_ip_host.side_effect = lambda *a, **kw: call_order.append("create")
        mock_client.set_firewall_rule.side_effect = lambda *a, **kw: call_order.append("set") or ET.fromstring("<Response/>")

        block_ip("5.5.5.5", config, client=mock_client)

        assert call_order.index("create") < call_order.index("set")

    def test_missing_rule_raises_rule_update_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        # Response contains a different rule name
        bad_response = ET.fromstring(
            "<Response>"
            "  <FirewallRule><Name>Other Rule</Name></FirewallRule>"
            "</Response>"
        )
        mock_client = _mock_client(bad_response)

        with pytest.raises(RuleUpdateError, match="Block IP"):
            block_ip("5.5.5.5", config, client=mock_client)

    def test_firewall_api_error_raises_rule_update_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.get_firewall_rule.side_effect = FirewallAPIError(
            "timeout", code="500"
        )

        with pytest.raises(RuleUpdateError):
            block_ip("5.5.5.5", config, client=mock_client)

    def test_upload_failure_raises_rule_update_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response(["1.1.1.1"]))
        mock_client.set_firewall_rule.side_effect = FirewallAPIError(
            "upload failed", code="503"
        )

        with pytest.raises(RuleUpdateError):
            block_ip("9.9.9.9", config, client=mock_client)

    def test_xml_validated_before_upload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """validate_rule_xml must be called (XML is checked before upload)."""
        config = _make_config(monkeypatch)
        mock_client = _mock_client(_make_response(["1.1.1.1"]))

        with patch("core.rule_updater.validate_rule_xml") as mock_validate:
            block_ip("2.2.2.2", config, client=mock_client)
            mock_validate.assert_called_once()

    def test_client_is_logged_out_after_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When block_ip creates its own client, it logs out afterwards."""
        config = _make_config(monkeypatch)
        # Patch SophosClient so we can inspect logout calls
        mock_client_instance = _mock_client(_make_response([]))
        with patch("core.rule_updater.SophosClient", return_value=mock_client_instance):
            block_ip("3.3.3.3", config)  # no explicit client -- creates one
        mock_client_instance.logout.assert_called_once()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Post-upload verification -- prevents false "[BLOCKED]" notifications
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestBlockVerification:
    def test_raises_when_host_absent_after_upload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If SFOS reports success but the re-fetched rule lacks the host,
        block_ip must raise (so the caller sends a failure notification,
        never a false '[BLOCKED]')."""
        config = _make_config(monkeypatch)

        # First GET (fetch) has no networks; second GET (verify) STILL has none,
        # simulating SFOS silently discarding the update.
        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.create_ip_host.return_value = None
        mock_client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
        mock_client.get_firewall_rule.side_effect = [
            _make_response([]),        # initial fetch (used for append)
            _make_response([]),        # verification re-fetch (host missing!)
        ]

        with pytest.raises(RuleUpdateError, match="NOT present"):
            block_ip("4.4.4.4", config, client=mock_client)

    def test_returns_blocked_when_host_present_after_upload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the re-fetched rule contains the host object, block succeeds."""
        config = _make_config(monkeypatch)

        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.create_ip_host.return_value = None
        mock_client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
        mock_client.get_firewall_rule.side_effect = [
            _make_response([]),                     # initial fetch
            _make_response(["blocked-4-4-4-4"]),    # verification: host present
        ]

        result = block_ip("4.4.4.4", config, client=mock_client)
        assert result == "blocked"

    def test_verification_refetches_rule(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """block_ip must GET the rule twice: once to modify, once to verify."""
        config = _make_config(monkeypatch)

        mock_client = MagicMock()
        mock_client.last_response = ""
        mock_client.create_ip_host.return_value = None
        mock_client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
        mock_client.get_firewall_rule.side_effect = [
            _make_response([]),
            _make_response(["blocked-7-7-7-7"]),
        ]

        block_ip("7.7.7.7", config, client=mock_client)
        assert mock_client.get_firewall_rule.call_count == 2


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
