"""End-to-end tests for multi-rule blocking.

A real SOC alert email is driven through the whole pipeline -- parse,
trust classification, block across several firewall rules, notify, queue
the retry, then resolve it -- against an in-memory firewall. Only the SMTP
transport and the SFOS HTTP client are substituted; every module in
between runs for real.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from email.message import EmailMessage
from unittest.mock import patch

import pytest

import core.email_monitor as email_monitor_module
from core import database
from core.email_monitor import EmailMonitor
from core.firewall_client import FirewallAPIError
from core.xml_handler import RuleNotFoundError

RULE_A = "Block IP"
RULE_B = "Block IP WAN"
RULE_C = "Block IP DMZ"

ATTACKER_IP = "132.200.152.126"
HOST_NAME = "blocked-132-200-152-126"

SOC_SUBJECT = (
    "Fwd: TITANIUM SOC ALERT - AIE: Century Papers: "
    "Network Anomaly: Threat List Attack IP"
)

ALERT_HTML = f"""
<html><body>
<table>
  <tr><th>Alarm ID</th><td>ALARM-9001</td></tr>
  <tr><th>Origin IP</th><td>{ATTACKER_IP}</td></tr>
  <tr><th>Impacted IP</th><td>192.168.20.50</td></tr>
  <tr><th>Classification</th><td>Threat List Attack IP</td></tr>
</table>
</body></html>
"""


def _build_alert_email() -> bytes:
    msg = EmailMessage()
    msg["Subject"] = SOC_SUBJECT
    msg["From"] = "alerts@company.com"
    msg["To"] = "soc@company.com"
    msg.set_content(ALERT_HTML, subtype="html")
    return msg.as_bytes()


class _InMemoryFirewall:
    """Stateful SFOS stand-in shared by the whole end-to-end run.

    Rules can be made to fail and then repaired mid-test, which is what
    lets a single test observe a partial block, its retry, and the
    eventual resolution.
    """

    def __init__(self, rules: dict[str, list[str]]) -> None:
        self.rules = {name: list(nets) for name, nets in rules.items()}
        self.broken: set[str] = set()
        self.missing: set[str] = set()
        self.last_response = ""
        self._hosts: set[str] = set()
        self.upload_log: list[str] = []

    def break_rule(self, name: str) -> None:
        self.broken.add(name)

    def repair_rule(self, name: str) -> None:
        self.broken.discard(name)
        self.missing.discard(name)

    def remove_rule(self, name: str) -> None:
        self.missing.add(name)

    # -- client API --------------------------------------------------------
    def authenticate(self) -> None:
        pass

    def logout(self) -> None:
        pass

    def ip_host_exists(self, name: str, ip: str = "") -> bool:
        return name in self._hosts

    def create_ip_host(self, name: str, ip: str) -> None:
        self._hosts.add(name)

    def get_firewall_rule(self, rule_name: str) -> ET.Element:
        if rule_name in self.missing or rule_name not in self.rules:
            raise RuleNotFoundError(
                f"Firewall rule {rule_name!r} does not exist on the firewall."
            )
        networks = "".join(f"<Network>{n}</Network>" for n in self.rules[rule_name])
        return ET.fromstring(
            "<Response><FirewallRule>"
            f"<Name>{rule_name}</Name><Status>Enable</Status>"
            "<NetworkPolicy><Action>Reject</Action>"
            f"<SourceNetworks>{networks}</SourceNetworks>"
            "</NetworkPolicy></FirewallRule></Response>"
        )

    def set_firewall_rule(self, rule_element: ET.Element, rule_name: str) -> ET.Element:
        if rule_name in self.broken:
            raise FirewallAPIError(f"rule {rule_name} rejected the update", code="502")
        self.upload_log.append(rule_name)
        self.rules[rule_name] = [
            (n.text or "").strip()
            for n in rule_element.findall(".//SourceNetworks/Network")
        ]
        return ET.fromstring("<Response/>")


_ENV_BASE: dict[str, str] = {
    "FIREWALL_HOST": "192.168.1.1",
    "FIREWALL_PORT": "4444",
    "FIREWALL_USERNAME": "admin",
    "FIREWALL_PASSWORD": "pass",
    "IMAP_HOST": "outlook.office365.com",
    "IMAP_PORT": "993",
    "EMAIL_USERNAME": "monitor@company.com",
    "EMAIL_PASSWORD": "emailpass",
    "SMTP_HOST": "smtp.office365.com",
    "SMTP_PORT": "587",
    "NOTIFICATION_EMAIL": "soc@company.com",
    "TRUSTED_SENDERS": "alerts@company.com",
    "ALERT_KEYWORDS": "attack",
}


@pytest.fixture
def config(monkeypatch, tmp_path):
    """A real AppConfig with three rules, and the registry seeded.

    Built through load_config() rather than a stub so the end-to-end run
    exercises the same parsing path production uses.
    """
    from core.config import load_config

    database.add_protected_endpoint(
        "192.168.20.0/24", "192.168.20.0/24", "CIDR", "CENTURY_OWNED"
    )
    for key, value in _ENV_BASE.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("FIREWALL_RULE_NAMES", f"{RULE_A}, {RULE_B}, {RULE_C}")
    monkeypatch.delenv("FIREWALL_RULE_NAME", raising=False)
    monkeypatch.setenv("LOG_DIRECTORY", str(tmp_path / "logs"))
    return load_config()


@pytest.fixture
def sent_emails(monkeypatch):
    """Capture every notification instead of sending it."""
    captured: list[dict[str, str]] = []

    def _capture(cfg, subject, body, html_body=None):
        captured.append({"subject": subject, "body": body, "html": html_body or ""})
        return True

    monkeypatch.setattr(email_monitor_module, "_notify", _capture)
    return captured


def _run_alert(monitor: EmailMonitor, firewall: _InMemoryFirewall, uid: str = "1") -> str:
    """Feed one alert email through the monitor against *firewall*."""
    with patch(
        "core.rule_updater.SophosClient", return_value=firewall
    ):
        return monitor._process_message(uid, _build_alert_email())


# --------------------------------------------------------------------------
# Full success
# --------------------------------------------------------------------------

class TestEndToEndAllRulesSucceed:
    def test_alert_email_blocks_the_attacker_in_every_rule(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        monitor = EmailMonitor(config)

        outcome = _run_alert(monitor, firewall)

        assert outcome == "blocked_successfully"
        for rule in (RULE_A, RULE_B, RULE_C):
            assert HOST_NAME in firewall.rules[rule], rule

    def test_success_sends_a_single_blocked_notification(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})

        _run_alert(EmailMonitor(config), firewall)

        assert len(sent_emails) == 1
        assert sent_emails[0]["subject"].startswith("[BLOCKED]")

    def test_success_leaves_nothing_in_the_retry_queue(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})

        _run_alert(EmailMonitor(config), firewall)

        assert database.get_pending_block(ATTACKER_IP) is None

    def test_success_records_one_history_row_per_rule(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})

        _run_alert(EmailMonitor(config), firewall)

        rows = database.list_firewall_actions_for_ip(ATTACKER_IP)
        assert {r["rule_name"] for r in rows} == {RULE_A, RULE_B, RULE_C}
        assert all(r["result"] == "blocked" for r in rows)


# --------------------------------------------------------------------------
# Partial block
# --------------------------------------------------------------------------

class TestEndToEndPartialBlock:
    def test_one_broken_rule_still_blocks_in_the_others(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)

        outcome = _run_alert(EmailMonitor(config), firewall)

        assert outcome == "processing_failed"
        assert HOST_NAME in firewall.rules[RULE_A]
        assert HOST_NAME in firewall.rules[RULE_C]
        assert HOST_NAME not in firewall.rules[RULE_B]

    def test_partial_sends_exactly_one_partial_notification(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)

        _run_alert(EmailMonitor(config), firewall)

        assert len(sent_emails) == 1
        assert sent_emails[0]["subject"].startswith("[PARTIAL]")
        assert "PARTIALLY BLOCKED" in sent_emails[0]["body"]

    def test_partial_notification_names_the_failing_rule(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)

        _run_alert(EmailMonitor(config), firewall)

        body = sent_emails[0]["body"]
        assert RULE_B in body
        assert RULE_A in body
        assert "ALARM-9001" in body

    def test_partial_is_queued_for_retry(self, config, sent_emails) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)

        _run_alert(EmailMonitor(config), firewall)

        assert database.get_pending_block(ATTACKER_IP) is not None

    def test_partial_history_shows_per_rule_truth(self, config, sent_emails) -> None:
        """The table distinguishes the rules even though the KPI says failed."""
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)

        _run_alert(EmailMonitor(config), firewall)

        rows = {r["rule_name"]: r for r in database.list_firewall_actions_for_ip(ATTACKER_IP)}
        assert rows[RULE_A]["result"] == "blocked"
        assert rows[RULE_C]["result"] == "blocked"
        assert rows[RULE_B]["result"] == "failed"

    def test_misnamed_rule_in_env_is_reported_as_nonexistent(
        self, config, sent_emails
    ) -> None:
        """A typo in FIREWALL_RULE_NAMES must be identifiable from the email."""
        firewall = _InMemoryFirewall({RULE_A: [], RULE_C: []})
        firewall.remove_rule(RULE_B)

        _run_alert(EmailMonitor(config), firewall)

        body = sent_emails[0]["body"]
        assert RULE_B in body
        assert "does not exist" in body


# --------------------------------------------------------------------------
# Total failure
# --------------------------------------------------------------------------

class TestEndToEndTotalFailure:
    def test_all_rules_broken_reports_a_plain_failure(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        for rule in (RULE_A, RULE_B, RULE_C):
            firewall.break_rule(rule)

        outcome = _run_alert(EmailMonitor(config), firewall)

        assert outcome == "processing_failed"
        assert sent_emails[0]["subject"].startswith("[ALERT]")
        assert "RETRY SCHEDULED" in sent_emails[0]["body"]

    def test_all_rules_broken_is_queued_for_retry(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        for rule in (RULE_A, RULE_B, RULE_C):
            firewall.break_rule(rule)

        _run_alert(EmailMonitor(config), firewall)

        assert database.get_pending_block(ATTACKER_IP) is not None


# --------------------------------------------------------------------------
# Partial -> retry -> resolution
# --------------------------------------------------------------------------

class TestEndToEndPartialResolution:
    def _retry(self, monitor, firewall) -> None:
        with patch("core.rule_updater.SophosClient", return_value=firewall):
            monitor._retry_pending_blocks()

    def test_retry_only_reuploads_the_previously_failed_rule(
        self, config, sent_emails
    ) -> None:
        """Rules that already hold the IP short-circuit as duplicates."""
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)
        monitor = EmailMonitor(config)
        _run_alert(monitor, firewall)

        firewall.upload_log.clear()
        firewall.repair_rule(RULE_B)
        self._retry(monitor, firewall)

        assert firewall.upload_log == [RULE_B]

    def test_retry_completes_the_block_in_every_rule(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)
        monitor = EmailMonitor(config)
        _run_alert(monitor, firewall)

        firewall.repair_rule(RULE_B)
        self._retry(monitor, firewall)

        for rule in (RULE_A, RULE_B, RULE_C):
            assert HOST_NAME in firewall.rules[rule], rule

    def test_exactly_two_emails_for_the_whole_partial_lifecycle(
        self, config, sent_emails
    ) -> None:
        """The agreed contract: one on first partial failure, one on success."""
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)
        monitor = EmailMonitor(config)
        _run_alert(monitor, firewall)

        # Several quiet retries while the rule is still broken.
        for _ in range(3):
            self._retry(monitor, firewall)
        assert len(sent_emails) == 1, "retries must not send further emails"

        firewall.repair_rule(RULE_B)
        self._retry(monitor, firewall)

        assert len(sent_emails) == 2
        assert sent_emails[0]["subject"].startswith("[PARTIAL]")
        assert sent_emails[1]["subject"].startswith("[BLOCKED]")

    def test_resolution_email_names_the_rule_the_retry_fixed(
        self, config, sent_emails
    ) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)
        monitor = EmailMonitor(config)
        _run_alert(monitor, firewall)

        firewall.repair_rule(RULE_B)
        self._retry(monitor, firewall)

        resolution = sent_emails[-1]["body"]
        assert RULE_B in resolution
        assert "already blocked" in resolution
        assert "ALARM-9001" in resolution

    def test_resolution_clears_the_retry_queue(self, config, sent_emails) -> None:
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)
        monitor = EmailMonitor(config)
        _run_alert(monitor, firewall)

        firewall.repair_rule(RULE_B)
        self._retry(monitor, firewall)

        assert database.get_pending_block(ATTACKER_IP) is None

    def test_unfixed_partial_retries_indefinitely_without_further_email(
        self, config, sent_emails
    ) -> None:
        """No attempt cap: the row survives and stays quiet until resolved."""
        firewall = _InMemoryFirewall({RULE_A: [], RULE_B: [], RULE_C: []})
        firewall.break_rule(RULE_B)
        monitor = EmailMonitor(config)
        _run_alert(monitor, firewall)

        for _ in range(10):
            self._retry(monitor, firewall)

        entry = database.get_pending_block(ATTACKER_IP)
        assert entry is not None
        assert entry["attempts"] >= 10
        assert len(sent_emails) == 1
