"""Tests for core/firewall_client.py

Covers: authenticate (token mode, per-request mode, failure),
        _check_write_status, get_firewall_rule, set_firewall_rule (success/failure),
        logout, upload success/failure.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

import pytest

from core.firewall_client import SophosClient, FirewallAPIError


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

AUTH_TOKEN = (
    '<Response APIVersion="2200.1" Token="abc123">'
    "<Login><status>Authentication Successful</status></Login>"
    "</Response>"
)
AUTH_NO_TOKEN = (
    '<Response APIVersion="2200.1">'
    "<Login><status>Authentication Successful</status></Login>"
    "</Response>"
)
AUTH_FAIL = (
    '<Response APIVersion="2200.1">'
    "<Login><status>Authentication Unsuccessful</status></Login>"
    "</Response>"
)
SET_OK = (
    '<Response>'
    '<FirewallRule transactionid=""><Status code="200">OK</Status></FirewallRule>'
    "</Response>"
)
SET_FAIL = (
    '<Response>'
    '<FirewallRule transactionid=""><Status code="500">Internal Error</Status></FirewallRule>'
    "</Response>"
)
RULE_RESPONSE = (
    "<Response>"
    "<FirewallRule>"
    "<Name>Block IP</Name>"
    "<Status>Enable</Status>"
    "<NetworkPolicy>"
    "<Action>Reject</Action>"
    "<SourceNetworks><Network>1.1.1.1</Network></SourceNetworks>"
    "</NetworkPolicy>"
    "</FirewallRule>"
    "</Response>"
)


def _mock_resp(text: str) -> MagicMock:
    r = MagicMock()
    r.text = text
    r.raise_for_status = MagicMock()
    return r


@pytest.fixture()
def client() -> SophosClient:
    return SophosClient(host="192.168.1.1", port=4444, username="admin", password="pass")


# ──────────────────────────────────────────────────────────────────────────────
# authenticate
# ──────────────────────────────────────────────────────────────────────────────

class TestAuthenticate:
    def test_stores_token_when_returned(self, client: SophosClient) -> None:
        with patch("requests.post", return_value=_mock_resp(AUTH_TOKEN)):
            client.authenticate()
        assert client._token == "abc123"
        assert client._authenticated is True
        assert client._per_request is False

    def test_per_request_mode_when_no_token(self, client: SophosClient) -> None:
        with patch("requests.post", return_value=_mock_resp(AUTH_NO_TOKEN)):
            client.authenticate()
        assert client._token is None
        assert client._per_request is True
        assert client._authenticated is True

    def test_raises_on_failed_authentication(self, client: SophosClient) -> None:
        with patch("requests.post", return_value=_mock_resp(AUTH_FAIL)):
            with pytest.raises(FirewallAPIError, match="Authentication failed"):
                client.authenticate()
        assert client._authenticated is False

    def test_auth_request_contains_login_once(self, client: SophosClient) -> None:
        """The authentication request must embed <Login> exactly once."""
        captured: list[str] = []

        def fake_post(url: str, data=None, **kw: object) -> MagicMock:
            captured.append(data.get("reqxml", "") if data else "")
            return _mock_resp(AUTH_NO_TOKEN)

        with patch("requests.post", side_effect=fake_post):
            client.authenticate()
        assert captured[0].count("<Login>") == 1

    def test_per_request_mode_embeds_creds_in_each_request(
        self, client: SophosClient
    ) -> None:
        with patch("requests.post", return_value=_mock_resp(AUTH_NO_TOKEN)):
            client.authenticate()
        body = client._build_request("<Get/>")
        assert "<Login>" in body
        assert "admin" in body

    def test_token_mode_uses_token_attribute_not_login_tag(
        self, client: SophosClient
    ) -> None:
        with patch("requests.post", return_value=_mock_resp(AUTH_TOKEN)):
            client.authenticate()
        body = client._build_request("<Get/>")
        assert 'token="abc123"' in body
        assert "<Login>" not in body


# ──────────────────────────────────────────────────────────────────────────────
# _check_write_status
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckWriteStatus:
    def test_success_code_does_not_raise(self, client: SophosClient) -> None:
        root = ET.fromstring('<Response><Status code="200">OK</Status></Response>')
        client._check_write_status(root, "test")  # no raise

    def test_error_code_raises(self, client: SophosClient) -> None:
        root = ET.fromstring('<Response><Status code="500">Error</Status></Response>')
        with pytest.raises(FirewallAPIError, match="code=500"):
            client._check_write_status(root, "test")

    def test_502_tolerated(self, client: SophosClient) -> None:
        root = ET.fromstring('<Response><Status code="502">Already exists</Status></Response>')
        client._check_write_status(root, "test")  # no raise

    def test_status_with_no_code_ignored(self, client: SophosClient) -> None:
        root = ET.fromstring("<Response><Status>OK</Status></Response>")
        client._check_write_status(root, "test")  # no raise


# ──────────────────────────────────────────────────────────────────────────────
# create_ip_host
# ──────────────────────────────────────────────────────────────────────────────

class TestCreateIpHost:
    HOST_OK = '<Response><IPHost transactionid=""><Status code="200">OK</Status></IPHost></Response>'
    HOST_EXISTS = '<Response><IPHost transactionid=""><Status code="502">Already exists</Status></IPHost></Response>'
    HOST_FAIL = '<Response><IPHost transactionid=""><Status code="500">Error</Status></IPHost></Response>'

    def test_creates_host_successfully(self, client: SophosClient) -> None:
        client._authenticated = True; client._per_request = True
        with patch("requests.post", return_value=_mock_resp(self.HOST_OK)):
            client.create_ip_host("blocked-1-2-3-4", "1.2.3.4")  # no raise

    def test_tolerates_already_exists(self, client: SophosClient) -> None:
        client._authenticated = True; client._per_request = True
        with patch("requests.post", return_value=_mock_resp(self.HOST_EXISTS)):
            client.create_ip_host("blocked-1-2-3-4", "1.2.3.4")  # no raise

    def test_raises_on_error(self, client: SophosClient) -> None:
        client._authenticated = True; client._per_request = True
        with patch("requests.post", return_value=_mock_resp(self.HOST_FAIL)):
            with pytest.raises(FirewallAPIError, match="code=500"):
                client.create_ip_host("blocked-1-2-3-4", "1.2.3.4")

    def test_request_contains_ip_address(self, client: SophosClient) -> None:
        client._authenticated = True; client._per_request = True
        captured: list[str] = []
        def fake_post(url: str, data=None, **kw: object) -> MagicMock:
            captured.append(data.get("reqxml", "") if data else "")
            return _mock_resp(self.HOST_OK)
        with patch("requests.post", side_effect=fake_post):
            client.create_ip_host("blocked-9-9-9-9", "9.9.9.9")
        assert "9.9.9.9" in captured[0]
        assert "blocked-9-9-9-9" in captured[0]


# ──────────────────────────────────────────────────────────────────────────────
# get_firewall_rule
# ──────────────────────────────────────────────────────────────────────────────

class TestGetFirewallRule:
    def test_returns_response_root(self, client: SophosClient) -> None:
        client._authenticated = True
        client._per_request = True
        with patch("requests.post", return_value=_mock_resp(RULE_RESPONSE)):
            root = client.get_firewall_rule("Block IP")
        assert root.find(".//FirewallRule/Name").text == "Block IP"

    def test_triggers_authenticate_when_not_authenticated(
        self, client: SophosClient
    ) -> None:
        responses = [_mock_resp(AUTH_NO_TOKEN), _mock_resp(RULE_RESPONSE)]
        with patch("requests.post", side_effect=responses):
            root = client.get_firewall_rule("Block IP")
        assert client._authenticated is True
        assert root.find(".//FirewallRule/Name").text == "Block IP"


# ──────────────────────────────────────────────────────────────────────────────
# set_firewall_rule -- upload success / failure
# ──────────────────────────────────────────────────────────────────────────────

class TestSetFirewallRule:
    def test_upload_success(self, client: SophosClient) -> None:
        client._authenticated = True
        client._per_request = True
        rule_elem = ET.fromstring(
            "<FirewallRule>"
            "<Name>Block IP</Name>"
            "<NetworkPolicy>"
            "<SourceNetworks><Network>1.1.1.1</Network></SourceNetworks>"
            "</NetworkPolicy>"
            "</FirewallRule>"
        )
        with patch("requests.post", return_value=_mock_resp(SET_OK)):
            client.set_firewall_rule(rule_elem, "Block IP")  # no raise

    def test_upload_failure_raises(self, client: SophosClient) -> None:
        client._authenticated = True
        client._per_request = True
        rule_elem = ET.fromstring(
            "<FirewallRule><Name>Block IP</Name></FirewallRule>"
        )
        with patch("requests.post", return_value=_mock_resp(SET_FAIL)):
            with pytest.raises(FirewallAPIError, match="code=500"):
                client.set_firewall_rule(rule_elem, "Block IP")

    def test_set_request_includes_update_operation(
        self, client: SophosClient
    ) -> None:
        """The Set request must use operation='update'."""
        client._authenticated = True
        client._per_request = True
        rule_elem = ET.fromstring(
            "<FirewallRule><Name>Block IP</Name></FirewallRule>"
        )
        captured: list[str] = []

        def fake_post(url: str, data=None, **kw: object) -> MagicMock:
            captured.append(data.get("reqxml", "") if data else "")
            return _mock_resp(SET_OK)

        with patch("requests.post", side_effect=fake_post):
            client.set_firewall_rule(rule_elem, "Block IP")
        assert 'operation="update"' in captured[0]

    def test_set_request_strips_transactionid(
        self, client: SophosClient
    ) -> None:
        """Read-only transactionid attributes from a GET must not be echoed back."""
        client._authenticated = True
        client._per_request = True
        rule_elem = ET.fromstring(
            '<FirewallRule transactionid="abc">'
            "<Name>Block IP</Name>"
            "<NetworkPolicy>"
            '<SourceNetworks transactionid="xyz"><Network>1.1.1.1</Network></SourceNetworks>'
            "</NetworkPolicy>"
            "</FirewallRule>"
        )
        captured: list[str] = []

        def fake_post(url: str, data=None, **kw: object) -> MagicMock:
            captured.append(data.get("reqxml", "") if data else "")
            return _mock_resp(SET_OK)

        with patch("requests.post", side_effect=fake_post):
            client.set_firewall_rule(rule_elem, "Block IP")
        assert "transactionid" not in captured[0]


# ──────────────────────────────────────────────────────────────────────────────
# logout
# ──────────────────────────────────────────────────────────────────────────────

class TestLogout:
    def test_resets_state(self, client: SophosClient) -> None:
        with patch("requests.post", return_value=_mock_resp(AUTH_NO_TOKEN)):
            client.authenticate()
        with patch("requests.post", return_value=_mock_resp("<Response/>")):
            client.logout()
        assert client._authenticated is False
        assert client._token is None
        assert client._per_request is False

    def test_no_op_when_not_authenticated(self, client: SophosClient) -> None:
        with patch("requests.post") as mock_post:
            client.logout()  # should not make any requests
        mock_post.assert_not_called()
