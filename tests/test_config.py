"""Tests for core/config.py

Covers: load_config validation, env-var parsing, and keyword parsing.
"""
from __future__ import annotations

import os
import pytest

from core.config import load_config, parse_trusted_senders

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_FULL_ENV: dict[str, str] = {
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


def _set_full_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _FULL_ENV.items():
        monkeypatch.setenv(k, v)


# ──────────────────────────────────────────────────────────────────────────────
# load_allowed_ips
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# is_ip_allowed
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# load_config
# ──────────────────────────────────────────────────────────────────────────────

class TestLoadConfig:
    @pytest.fixture(autouse=True)
    def isolate_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Prevent load_dotenv from reading the real .env during config tests."""
        monkeypatch.setattr("core.config.load_dotenv", lambda *a, **kw: None)

    def test_raises_when_required_var_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for key in _FULL_ENV:
            monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv("TRUSTED_SENDER", raising=False)  # legacy alias
        with pytest.raises(EnvironmentError, match="Missing required"):
            load_config()

    def test_raises_when_single_var_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.delenv("FIREWALL_RULE_NAME")
        with pytest.raises(EnvironmentError, match="FIREWALL_RULE_NAME"):
            load_config()

    def test_loads_all_required_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        cfg = load_config()
        assert cfg.firewall_host == "192.168.1.1"
        assert cfg.firewall_port == 4444
        assert cfg.firewall_rule_name == "Block IP"
        assert cfg.trusted_senders == frozenset({"alerts@company.com"})

    def test_trusted_senders_lowercased(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("TRUSTED_SENDERS", "ALERTS@COMPANY.COM")
        cfg = load_config()
        assert cfg.trusted_senders == frozenset({"alerts@company.com"})

    def test_trusted_senders_multiple_comma_separated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv(
            "TRUSTED_SENDERS", "soc@company.com,alerts@company.com,ops@company.com"
        )
        cfg = load_config()
        assert cfg.trusted_senders == frozenset(
            {"soc@company.com", "alerts@company.com", "ops@company.com"}
        )

    def test_trusted_senders_whitespace_trimmed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv(
            "TRUSTED_SENDERS", "  soc@company.com , alerts@company.com  ,ops@company.com "
        )
        cfg = load_config()
        assert cfg.trusted_senders == frozenset(
            {"soc@company.com", "alerts@company.com", "ops@company.com"}
        )

    def test_trusted_senders_invalid_entry_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("TRUSTED_SENDERS", "soc@company.com,not-an-email")
        with pytest.raises(EnvironmentError, match="TRUSTED_SENDERS"):
            load_config()

    def test_trusted_senders_blank_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("TRUSTED_SENDERS", "")
        monkeypatch.delenv("TRUSTED_SENDER", raising=False)
        with pytest.raises(EnvironmentError, match="TRUSTED_SENDERS"):
            load_config()

    def test_legacy_trusted_sender_singular_still_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backward compatibility: an existing .env with only the old
        singular TRUSTED_SENDER (no TRUSTED_SENDERS) must keep working."""
        _set_full_env(monkeypatch)
        monkeypatch.delenv("TRUSTED_SENDERS", raising=False)
        monkeypatch.setenv("TRUSTED_SENDER", "legacy@company.com")
        cfg = load_config()
        assert cfg.trusted_senders == frozenset({"legacy@company.com"})

    def test_trusted_senders_takes_precedence_over_legacy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("TRUSTED_SENDERS", "new@company.com")
        monkeypatch.setenv("TRUSTED_SENDER", "legacy@company.com")
        cfg = load_config()
        assert cfg.trusted_senders == frozenset({"new@company.com"})

    def test_alert_keywords_parsed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("ALERT_KEYWORDS", "attack, threat, malware")
        cfg = load_config()
        assert "attack" in cfg.alert_keywords
        assert "threat" in cfg.alert_keywords
        assert "malware" in cfg.alert_keywords

    def test_empty_keywords_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("ALERT_KEYWORDS", "")
        with pytest.raises(EnvironmentError, match="ALERT_KEYWORDS"):
            load_config()

    def test_whitespace_only_keywords_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("ALERT_KEYWORDS", "  ,  , ")
        with pytest.raises(EnvironmentError, match="ALERT_KEYWORDS"):
            load_config()

    def test_run_loop_defaults_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.delenv("IMAP_RUN_LOOP", raising=False)
        cfg = load_config()
        assert cfg.run_loop is True

    def test_run_loop_false_when_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("IMAP_RUN_LOOP", "false")
        cfg = load_config()
        assert cfg.run_loop is False

    def test_notification_email_required(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.delenv("NOTIFICATION_EMAIL", raising=False)
        with pytest.raises(EnvironmentError, match="NOTIFICATION_EMAIL"):
            load_config()

    def test_invalid_notification_email_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("NOTIFICATION_EMAIL", "not-an-email")
        with pytest.raises(EnvironmentError, match="NOTIFICATION_EMAIL"):
            load_config()

    def test_invalid_imap_port_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("IMAP_PORT", "not-a-port")
        with pytest.raises(EnvironmentError, match="IMAP_PORT"):
            load_config()

    def test_smtp_defaults_to_email_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        cfg = load_config()
        assert cfg.smtp_username == "user@example.com"
        assert cfg.smtp_password == "emailpass"
        assert cfg.smtp_from_address == "user@example.com"

    def test_smtp_ssl_mode_disables_tls_even_if_env_sets_both(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SMTP_USE_SSL=true forces SMTP_USE_TLS off at load time."""
        _set_full_env(monkeypatch)
        monkeypatch.setenv("SMTP_USE_SSL", "true")
        monkeypatch.setenv("SMTP_USE_TLS", "true")
        monkeypatch.setenv("SMTP_PORT", "465")
        cfg = load_config()
        assert cfg.smtp_use_ssl is True
        assert cfg.smtp_use_tls is False
        assert cfg.smtp_port == 465

    def test_outlook_imap_ssl_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        cfg = load_config()
        assert cfg.imap_host == "outlook.office365.com"
        assert cfg.imap_use_ssl is True
        assert cfg.smtp_host == "smtp.office365.com"
        assert cfg.smtp_use_tls is True
        assert cfg.smtp_use_ssl is False

    def test_environment_loading(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify all env vars are correctly mapped to AppConfig fields."""
        _set_full_env(monkeypatch)
        monkeypatch.setenv("NOTIFICATION_EMAIL", "notify@example.com")
        monkeypatch.setenv("LOG_DIRECTORY", "logs/")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("IMAP_POLL_INTERVAL", "120")
        monkeypatch.setenv("IMAP_RUN_LOOP", "true")
        cfg = load_config()
        assert cfg.notification_email == "notify@example.com"
        assert cfg.log_level == "DEBUG"
        assert cfg.poll_interval == 120
        assert cfg.run_loop is True

    @pytest.mark.parametrize("raw", ["invalid", "0", "-5", ""])
    def test_invalid_startup_email_limit_uses_safe_default(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("IMAP_STARTUP_EMAIL_LIMIT", raw)
        cfg = load_config()
        assert cfg.imap_startup_email_limit == 10

    def test_debug_logging_defaults_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.delenv("DEBUG_LOGGING", raising=False)
        monkeypatch.delenv("DEBUG_LOG_MAX_CHARS", raising=False)
        cfg = load_config()
        assert cfg.debug_logging is False
        assert cfg.debug_log_max_chars == 2000

    def test_debug_logging_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("DEBUG_LOGGING", "true")
        monkeypatch.setenv("DEBUG_LOG_MAX_CHARS", "750")
        cfg = load_config()
        assert cfg.debug_logging is True
        assert cfg.debug_log_max_chars == 750

    def test_imap_folders_and_startup_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("IMAP_FOLDERS", "INBOX, SOC Alerts,INBOX")
        monkeypatch.setenv("IMAP_STARTUP_EMAIL_LIMIT", "35")
        cfg = load_config()
        assert cfg.imap_folders == ("INBOX", "SOC Alerts")
        assert cfg.imap_mailbox == "INBOX"
        assert cfg.imap_startup_email_limit == 35


# ──────────────────────────────────────────────────────────────────────────────
# parse_trusted_senders
# ──────────────────────────────────────────────────────────────────────────────

class TestParseTrustedSenders:
    def test_single_address(self) -> None:
        assert parse_trusted_senders("alerts@company.com") == frozenset(
            {"alerts@company.com"}
        )

    def test_multiple_addresses(self) -> None:
        result = parse_trusted_senders("a@company.com,b@company.com")
        assert result == frozenset({"a@company.com", "b@company.com"})

    def test_trims_whitespace(self) -> None:
        result = parse_trusted_senders(" a@company.com , b@company.com ")
        assert result == frozenset({"a@company.com", "b@company.com"})

    def test_lowercases(self) -> None:
        result = parse_trusted_senders("Alerts@Company.COM")
        assert result == frozenset({"alerts@company.com"})

    def test_deduplicates_case_insensitively(self) -> None:
        result = parse_trusted_senders("Alerts@Company.com,alerts@company.com")
        assert result == frozenset({"alerts@company.com"})

    def test_ignores_blank_entries_between_commas(self) -> None:
        result = parse_trusted_senders("a@company.com,,b@company.com,")
        assert result == frozenset({"a@company.com", "b@company.com"})

    def test_empty_raises_when_required(self) -> None:
        with pytest.raises(EnvironmentError, match="TRUSTED_SENDERS"):
            parse_trusted_senders("")

    def test_empty_returns_empty_set_when_not_required(self) -> None:
        assert parse_trusted_senders("", required=False) == frozenset()

    def test_invalid_email_raises(self) -> None:
        with pytest.raises(EnvironmentError, match="invalid email"):
            parse_trusted_senders("a@company.com,not-an-email")

    def test_invalid_email_raises_even_when_not_required(self) -> None:
        with pytest.raises(EnvironmentError, match="invalid email"):
            parse_trusted_senders("not-an-email", required=False)
