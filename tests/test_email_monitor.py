"""Tests for core/email_monitor.py

Covers: sender filtering, Origin IP extraction, HTML extraction,
        keyword filtering, and end-to-end message processing logic.
"""
from __future__ import annotations

import io
from email import policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import pytest
from core import database

from core.email_monitor import (
    EmailMonitor,
    _extract_classification,
    _extract_html,
    _extract_origin_ip_from_html,
    _find_matching_keyword,
    _is_from_trusted_sender,
    _should_process,
    _parse_headers,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

# Real-world SOC alert: subject always contains "Attack IP" even for
# benign events, so keyword matching must target Classification, not subject.
SOC_SUBJECT = (
    "Fwd: TITANIUM SOC ALERT - AIE: Century Papers: "
    "Network Anomaly: Threat List Attack IP"
)

ALERT_TABLE_HTML = """
<html><body>
<table>
  <tr><th>Alarm ID</th><td>1234</td></tr>
  <tr><th>Origin IP</th><td>132.200.152.126</td></tr>
  <tr><th>Impacted IP</th><td>192.168.20.50</td></tr>
  <tr><th>Classification</th><td>Threat List Attack IP</td></tr>
</table>
</body></html>
"""

AUTH_SUCCESS_HTML = """
<html><body>
<table>
  <tr><th>Alarm ID</th><td>5678</td></tr>
  <tr><th>Origin IP</th><td>10.0.0.5</td></tr>
  <tr><th>Classification</th><td>Authentication Success</td></tr>
</table>
</body></html>
"""


def _build_raw_email(
    subject: str = "Test",
    from_: str = "sender@example.com",
    html_body: str | None = None,
    plain_body: str | None = None,
) -> bytes:
    """Build raw RFC 822 bytes for testing."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = "recipient@example.com"
    if html_body and plain_body:
        msg.set_content(plain_body)
        msg.add_alternative(html_body, subtype="html")
    elif html_body:
        msg.set_content(html_body, subtype="html")
    else:
        msg.set_content(plain_body or "")
    buf = io.BytesIO()
    BytesGenerator(buf, policy=policy.default).flatten(msg)
    return buf.getvalue()


def _make_config(
    trusted: str | frozenset[str] = "alerts@company.com",
    keywords: frozenset[str] = frozenset({"attack"}),
) -> MagicMock:
    cfg = MagicMock()
    cfg.trusted_senders = frozenset({trusted}) if isinstance(trusted, str) else frozenset(trusted)
    cfg.alert_keywords = keywords
    cfg.firewall_rule_name = "Block IP"
    database.add_protected_endpoint(
        "192.168.20.0/24", "192.168.20.0/24", "CIDR", "CENTURY_OWNED"
    )
    return cfg


# ──────────────────────────────────────────────────────────────────────────────
# _is_from_trusted_sender
# ──────────────────────────────────────────────────────────────────────────────

class TestIsTrustedSender:
    def test_exact_match_returns_true(self) -> None:
        assert _is_from_trusted_sender("alerts@company.com", {"alerts@company.com"})

    def test_display_name_bracket_format(self) -> None:
        assert _is_from_trusted_sender(
            "SOC Team <alerts@company.com>", {"alerts@company.com"}
        )

    def test_different_domain_returns_false(self) -> None:
        assert not _is_from_trusted_sender("evil@attacker.com", {"alerts@company.com"})

    def test_case_insensitive(self) -> None:
        assert _is_from_trusted_sender("Alerts@COMPANY.COM", {"alerts@company.com"})

    def test_empty_from_header_returns_false(self) -> None:
        assert not _is_from_trusted_sender("", {"alerts@company.com"})

    def test_empty_trusted_set_returns_false(self) -> None:
        assert not _is_from_trusted_sender("alerts@company.com", frozenset())

    def test_matches_any_of_multiple_trusted_senders(self) -> None:
        trusted = frozenset({"soc@company.com", "alerts@company.com", "ops@company.com"})
        assert _is_from_trusted_sender("alerts@company.com", trusted)
        assert _is_from_trusted_sender("SOC@Company.com", trusted)
        assert _is_from_trusted_sender("ops@company.com", trusted)

    def test_does_not_match_when_absent_from_multiple(self) -> None:
        trusted = frozenset({"soc@company.com", "alerts@company.com"})
        assert not _is_from_trusted_sender("evil@attacker.com", trusted)

    def test_case_insensitive_with_whitespace_padded_trusted_entries(self) -> None:
        # Defensive: matches even if a trusted-list entry carries stray
        # whitespace (shouldn't happen post-parse_trusted_senders, but the
        # matcher itself doesn't assume its callers always normalize).
        trusted = frozenset({" Alerts@Company.com "})
        assert _is_from_trusted_sender("alerts@company.com", trusted)


# ──────────────────────────────────────────────────────────────────────────────
# _extract_origin_ip_from_html
# ──────────────────────────────────────────────────────────────────────────────

class TestExtractOriginIp:
    def test_extracts_from_table_key_origin_ip(self) -> None:
        ip = _extract_origin_ip_from_html(ALERT_TABLE_HTML)
        assert ip == "132.200.152.126"

    def test_returns_none_when_no_ip(self) -> None:
        html = "<table><tr><td>nothing here</td></tr></table>"
        ip = _extract_origin_ip_from_html(html)
        assert ip is None

    def test_handles_ip_with_trailing_count(self) -> None:
        html = (
            "<table><tr><th>Origin IP</th><td>1.2.3.4 (3 hits)</td></tr></table>"
        )
        ip = _extract_origin_ip_from_html(html)
        assert ip == "1.2.3.4"

    def test_host_origin_alias(self) -> None:
        html = (
            "<table><tr><th>Host (Origin)</th><td>5.6.7.8</td></tr></table>"
        )
        ip = _extract_origin_ip_from_html(html)
        assert ip == "5.6.7.8"

    def test_case_insensitive_key(self) -> None:
        html = (
            "<table><tr><th>ORIGIN IP</th><td>9.8.7.6</td></tr></table>"
        )
        ip = _extract_origin_ip_from_html(html)
        assert ip == "9.8.7.6"


# ──────────────────────────────────────────────────────────────────────────────
# _extract_html
# ──────────────────────────────────────────────────────────────────────────────

class TestExtractHtml:
    def test_extracts_html_part_from_multipart(self) -> None:
        raw = _build_raw_email(
            html_body="<html><body>hello</body></html>",
            plain_body="hello plain",
        )
        html = _extract_html(raw)
        assert html is not None
        assert "hello" in html

    def test_plain_text_wrapped_in_pre(self) -> None:
        raw = _build_raw_email(plain_body="just plain text")
        html = _extract_html(raw)
        assert html is not None
        assert "just plain text" in html

    def test_returns_none_for_empty_message(self) -> None:
        raw = b"Subject: test\r\nFrom: a@b.com\r\n\r\n"
        html = _extract_html(raw)
        assert html is None or html.strip() in ("", "<pre></pre>")


# ──────────────────────────────────────────────────────────────────────────────
# _extract_classification
# ──────────────────────────────────────────────────────────────────────────────

class TestExtractClassification:
    def test_extracts_attack_classification(self) -> None:
        assert _extract_classification(ALERT_TABLE_HTML) == "Threat List Attack IP"

    def test_extracts_auth_success_classification(self) -> None:
        assert _extract_classification(AUTH_SUCCESS_HTML) == "Authentication Success"

    def test_returns_none_when_row_absent(self) -> None:
        html = "<table><tr><th>Origin IP</th><td>1.2.3.4</td></tr></table>"
        assert _extract_classification(html) is None

    def test_returns_none_for_empty_string(self) -> None:
        assert _extract_classification("") is None

    def test_case_insensitive_key(self) -> None:
        html = (
            "<table><tr><th>CLASSIFICATION</th>"
            "<td>Threat List Attack IP</td></tr></table>"
        )
        assert _extract_classification(html) == "Threat List Attack IP"

    def test_nbsp_in_key_normalised(self) -> None:
        html = (
            "<table><tr><th>Classification\u00a0</th>"
            "<td>Brute Force</td></tr></table>"
        )
        assert _extract_classification(html) == "Brute Force"


# ──────────────────────────────────────────────────────────────────────────────
# Keyword filtering
# ──────────────────────────────────────────────────────────────────────────────

class TestFindMatchingKeyword:
    # ── Classification-targeted matching (primary path) ──────────────────────

    def test_matches_classification_containing_keyword(self) -> None:
        """Attack classification → keyword found."""
        matched = _find_matching_keyword(
            ALERT_TABLE_HTML,
            SOC_SUBJECT,
            frozenset({"attack"}),
        )
        assert matched == "attack"

    def test_auth_success_classification_ignored_despite_attack_in_subject(self) -> None:
        """The real-world false-positive: subject has 'Attack IP' but the
        Classification field says 'Authentication Success' → must be ignored."""
        matched = _find_matching_keyword(
            AUTH_SUCCESS_HTML,
            SOC_SUBJECT,   # still contains "Attack IP"
            frozenset({"attack"}),
        )
        assert matched is None

    def test_classification_match_case_insensitive(self) -> None:
        html = (
            "<table>"
            "<tr><th>Classification</th><td>THREAT LIST ATTACK IP</td></tr>"
            "</table>"
        )
        matched = _find_matching_keyword(html, "some subject", frozenset({"attack"}))
        assert matched == "attack"

    def test_multiple_keywords_classification_any_match(self) -> None:
        html = (
            "<table>"
            "<tr><th>Classification</th><td>Brute Force Login</td></tr>"
            "</table>"
        )
        matched = _find_matching_keyword(
            html, "Daily report", frozenset({"attack", "brute", "malware"})
        )
        assert matched == "brute"

    def test_no_keyword_in_classification_returns_none(self) -> None:
        matched = _find_matching_keyword(
            AUTH_SUCCESS_HTML,
            "Daily report",
            frozenset({"attack", "threat", "malicious"}),
        )
        assert matched is None

    def test_does_not_match_substring_in_classification(self) -> None:
        html = (
            "<table>"
            "<tr><th>Classification</th><td>Counterattack Simulation</td></tr>"
            "</table>"
        )
        matched = _find_matching_keyword(html, "Exercise", frozenset({"attack"}))
        assert matched is None

    # ── Fallback path (no Classification cell present) ────────────────────────

    def test_fallback_matches_keyword_in_html_body(self) -> None:
        """No Classification row → falls back to full-text matching."""
        matched = _find_matching_keyword(
            "<html>malicious activity detected</html>",
            "Routine notice",
            frozenset({"attack", "malicious"}),
        )
        assert matched == "malicious"

    def test_fallback_matches_keyword_in_subject(self) -> None:
        matched = _find_matching_keyword(
            "<html>nothing here</html>",
            "Threat List Alert",
            frozenset({"attack", "threat"}),
        )
        assert matched == "threat"

    def test_fallback_no_match_returns_none(self) -> None:
        matched = _find_matching_keyword(
            "<html>routine system information</html>",
            "Daily report",
            frozenset({"attack", "threat", "malicious"}),
        )
        assert matched is None

    def test_fallback_does_not_match_substring_inside_word(self) -> None:
        matched = _find_matching_keyword(
            "<html>counterattack simulation</html>",
            "Exercise",
            frozenset({"attack"}),
        )
        assert matched is None

    def test_fallback_multiple_keywords_any_match(self) -> None:
        matched = _find_matching_keyword(
            "<html>unusual traffic</html>",
            "Malware detected on host",
            frozenset({"attack", "malware", "threat"}),
        )
        assert matched == "malware"


class TestShouldProcess:
    def test_attack_classification_returns_true(self) -> None:
        cfg = _make_config(keywords=frozenset({"attack"}))
        assert _should_process(ALERT_TABLE_HTML, SOC_SUBJECT, cfg) is True

    def test_auth_success_classification_returns_false(self) -> None:
        cfg = _make_config(keywords=frozenset({"attack"}))
        assert _should_process(AUTH_SUCCESS_HTML, SOC_SUBJECT, cfg) is False

    def test_no_keyword_match_returns_false(self) -> None:
        cfg = _make_config(keywords=frozenset({"attack", "threat"}))
        assert _should_process("<html>routine info</html>", "Hello", cfg) is False

    def test_keyword_in_subject_fallback_returns_true(self) -> None:
        """When no Classification cell present, subject match still works."""
        cfg = _make_config(keywords=frozenset({"attack"}))
        assert _should_process("<html>nothing</html>", "Attack Alert", cfg) is True


# ──────────────────────────────────────────────────────────────────────────────
# _parse_headers
# ──────────────────────────────────────────────────────────────────────────────

class TestParseHeaders:
    def test_extracts_from_and_subject(self) -> None:
        raw = _build_raw_email(
            subject="Security Alert",
            from_="soc@company.com",
        )
        headers = _parse_headers(raw)
        assert headers["subject"] == "Security Alert"
        assert "soc@company.com" in headers["from"]

    def test_missing_subject_returns_empty_string(self) -> None:
        raw = b"From: a@b.com\r\n\r\n"
        headers = _parse_headers(raw)
        assert headers["subject"] == ""


# ──────────────────────────────────────────────────────────────────────────────
# EmailMonitor message processing
# ──────────────────────────────────────────────────────────────────────────────

class TestEmailMonitorProcessing:
    def test_attack_classification_triggers_block(self) -> None:
        """Real-world attack alert: Classification contains keyword → blocked."""
        config = _make_config()
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="alerts@company.com",
            html_body=ALERT_TABLE_HTML,
        )
        monitor = EmailMonitor(config)

        with patch("core.email_monitor.block_ip", return_value="blocked") as mock_block:
            with patch("core.email_monitor.send_notification"):
                monitor._process_message("1", raw)

        mock_block.assert_called_once_with("132.200.152.126", config)

    def test_auth_success_classification_skips_blocking(self) -> None:
        """Real-world false-positive: same SOC subject but Classification is
        'Authentication Success' → must NOT block any IP."""
        config = _make_config()
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="alerts@company.com",
            html_body=AUTH_SUCCESS_HTML,
        )
        monitor = EmailMonitor(config)

        with patch("core.email_monitor.block_ip") as mock_block:
            monitor._process_message("2", raw)

        mock_block.assert_not_called()

    def test_no_keyword_in_classification_skips_blocking(self) -> None:
        config = _make_config(keywords=frozenset({"attack", "threat"}))
        raw = _build_raw_email(
            subject="Weekly status update",
            from_="alerts@company.com",
            html_body=(
                "<html><table>"
                "<tr><th>Classification</th><td>Routine Check</td></tr>"
                "<tr><th>Origin IP</th><td>1.2.3.4</td></tr>"
                "</table></html>"
            ),
        )
        monitor = EmailMonitor(config)

        with patch("core.email_monitor.block_ip") as mock_block:
            monitor._process_message("3", raw)

        mock_block.assert_not_called()

    def test_untrusted_sender_skips_before_keyword_check(self) -> None:
        config = _make_config()
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="evil@attacker.com",
            html_body=ALERT_TABLE_HTML,
        )
        monitor = EmailMonitor(config)

        with patch("core.email_monitor.block_ip") as mock_block:
            monitor._process_message("4", raw)

        mock_block.assert_not_called()

    def test_second_of_multiple_trusted_senders_is_processed(self) -> None:
        """A sender that matches ANY configured trusted address is processed,
        not just the first one in the list."""
        config = _make_config(
            trusted=frozenset({"soc@company.com", "alerts@company.com"})
        )
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="alerts@company.com",
            html_body=ALERT_TABLE_HTML,
        )
        monitor = EmailMonitor(config)

        with patch("core.email_monitor.block_ip", return_value="blocked") as mock_block:
            with patch("core.email_monitor.send_notification"):
                monitor._process_message("5", raw)

        mock_block.assert_called_once_with("132.200.152.126", config)

    def test_sender_outside_multiple_trusted_senders_skips(self) -> None:
        config = _make_config(
            trusted=frozenset({"soc@company.com", "alerts@company.com"})
        )
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="evil@attacker.com",
            html_body=ALERT_TABLE_HTML,
        )
        monitor = EmailMonitor(config)

        with patch("core.email_monitor.block_ip") as mock_block:
            monitor._process_message("6", raw)

        mock_block.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# Sender filtering (integration-style)
# ──────────────────────────────────────────────────────────────────────────────

class TestEmailParsing:
    def test_full_alert_email_parsed_correctly(self) -> None:
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="alerts@company.com",
            html_body=ALERT_TABLE_HTML,
        )
        headers = _parse_headers(raw)
        html = _extract_html(raw)
        assert html is not None
        ip = _extract_origin_ip_from_html(html)
        assert ip == "132.200.152.126"
        assert _is_from_trusted_sender(headers["from"], {"alerts@company.com"})
        assert _find_matching_keyword(html, headers["subject"], frozenset({"attack"})) == "attack"
        assert _extract_classification(html) == "Threat List Attack IP"

    def test_auth_success_email_would_be_ignored(self) -> None:
        raw = _build_raw_email(
            subject=SOC_SUBJECT,
            from_="alerts@company.com",
            html_body=AUTH_SUCCESS_HTML,
        )
        html = _extract_html(raw)
        assert html is not None
        assert _extract_classification(html) == "Authentication Success"
        assert _find_matching_keyword(html, SOC_SUBJECT, frozenset({"attack"})) is None

    def test_untrusted_sender_would_be_rejected(self) -> None:
        raw = _build_raw_email(
            subject="Sophos Attack Alert",
            from_="evil@attacker.com",
            html_body=ALERT_TABLE_HTML,
        )
        headers = _parse_headers(raw)
        assert not _is_from_trusted_sender(headers["from"], {"alerts@company.com"})
