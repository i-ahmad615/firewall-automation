"""Tests for core/config.py

Covers: allowed-IP loading, is_ip_allowed, load_config validation,
        env-var parsing, and keyword parsing.
"""
from __future__ import annotations

import os
import pytest

from core.config import load_allowed_ips, is_ip_allowed, load_config

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
    "TRUSTED_SENDER": "alerts@company.com",
    "ALERT_KEYWORDS": "attack",
}


def _set_full_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _FULL_ENV.items():
        monkeypatch.setenv(k, v)


# ──────────────────────────────────────────────────────────────────────────────
# load_allowed_ips
# ──────────────────────────────────────────────────────────────────────────────

class TestLoadAllowedIps:
    def test_reads_ip_addresses(self, tmp_path: pytest.TempPathFactory) -> None:
        f = tmp_path / "allowed.txt"
        f.write_text("192.168.1.1\n10.0.0.5\n172.16.20.50\n")
        result = load_allowed_ips(str(f))
        assert result == frozenset({"192.168.1.1", "10.0.0.5", "172.16.20.50"})

    def test_missing_file_returns_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        result = load_allowed_ips(str(tmp_path / "does_not_exist.txt"))
        assert result == frozenset()

    def test_comments_are_ignored(self, tmp_path: pytest.TempPathFactory) -> None:
        f = tmp_path / "allowed.txt"
        f.write_text("# this is a comment\n1.2.3.4\n")
        result = load_allowed_ips(str(f))
        assert "1.2.3.4" in result
        assert not any(r.startswith("#") for r in result)

    def test_blank_lines_are_ignored(self, tmp_path: pytest.TempPathFactory) -> None:
        f = tmp_path / "allowed.txt"
        f.write_text("\n\n1.2.3.4\n\n")
        result = load_allowed_ips(str(f))
        assert result == frozenset({"1.2.3.4"})

    def test_empty_file_returns_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        f = tmp_path / "allowed.txt"
        f.write_text("")
        result = load_allowed_ips(str(f))
        assert result == frozenset()


# ──────────────────────────────────────────────────────────────────────────────
# is_ip_allowed
# ──────────────────────────────────────────────────────────────────────────────

class TestIsIpAllowed:
    ALLOWED = frozenset({"192.168.1.10", "10.0.0.5"})

    def test_listed_ip_returns_true(self) -> None:
        assert is_ip_allowed("192.168.1.10", self.ALLOWED) is True

    def test_unlisted_ip_returns_false(self) -> None:
        assert is_ip_allowed("8.8.8.8", self.ALLOWED) is False

    def test_empty_set_always_false(self) -> None:
        assert is_ip_allowed("1.2.3.4", frozenset()) is False

    def test_strips_whitespace_from_ip(self) -> None:
        assert is_ip_allowed("  192.168.1.10  ", self.ALLOWED) is True


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
        assert cfg.trusted_sender == "alerts@company.com"

    def test_trusted_sender_lowercased(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_full_env(monkeypatch)
        monkeypatch.setenv("TRUSTED_SENDER", "ALERTS@COMPANY.COM")
        cfg = load_config()
        assert cfg.trusted_sender == "alerts@company.com"

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
        monkeypatch.setenv("ALLOWED_IPS_FILE", "config/allowed_ips.txt")
        monkeypatch.setenv("LOG_DIRECTORY", "logs/")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("IMAP_POLL_INTERVAL", "120")
        monkeypatch.setenv("IMAP_RUN_LOOP", "true")
        cfg = load_config()
        assert cfg.notification_email == "notify@example.com"
        assert cfg.allowed_ips_file == "config/allowed_ips.txt"
        assert cfg.log_level == "DEBUG"
        assert cfg.poll_interval == 120
        assert cfg.run_loop is True
