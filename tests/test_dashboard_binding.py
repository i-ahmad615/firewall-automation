"""Dashboard bind-address and Settings persistence regression tests."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import main
from core import config as config_module
from core.env_file import read_env_pairs
from web.services import settings_service


_REQUIRED_ENV = {
    "FIREWALL_HOST": "192.168.1.1",
    "FIREWALL_PORT": "4444",
    "FIREWALL_USERNAME": "admin",
    "FIREWALL_PASSWORD": "secret",
    "FIREWALL_RULE_NAME": "Block IP",
    "IMAP_HOST": "imap.example.com",
    "IMAP_PORT": "993",
    "EMAIL_USERNAME": "soc@example.com",
    "EMAIL_PASSWORD": "secret",
    "SMTP_HOST": "smtp.example.com",
    "SMTP_PORT": "587",
    "NOTIFICATION_EMAIL": "notify@example.com",
    "TRUSTED_SENDERS": "soc@example.com",
    "ALERT_KEYWORDS": "attack",
}


def test_saved_dashboard_binding_overrides_stale_process_values(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "DASHBOARD_HOST=0.0.0.0\nDASHBOARD_PORT=5000\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "_ENV_PATH", env_path)
    for key, value in _REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DASHBOARD_HOST", "127.0.0.1")
    monkeypatch.setenv("DASHBOARD_PORT", "8765")

    config = config_module.load_config()

    assert config.dashboard_host == "0.0.0.0"
    assert config.dashboard_port == 5000


def test_settings_page_persists_dashboard_host_and_port(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "DASHBOARD_HOST=127.0.0.1\nDASHBOARD_PORT=8765\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings_service, "_ENV_PATH", str(env_path))

    errors = settings_service.save_settings(
        {"DASHBOARD_HOST": "0.0.0.0", "DASHBOARD_PORT": "5000"}
    )

    assert errors == []
    saved = read_env_pairs(str(env_path))
    assert saved["DASHBOARD_HOST"] == "0.0.0.0"
    assert saved["DASHBOARD_PORT"] == "5000"
    displayed = settings_service.load_settings()["application"]
    assert displayed["DASHBOARD_HOST"]["value"] == "0.0.0.0"
    assert displayed["DASHBOARD_PORT"]["value"] == "5000"


def test_settings_page_saves_and_reloads_startup_email_limit(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("IMAP_STARTUP_EMAIL_LIMIT=10\n", encoding="utf-8")
    monkeypatch.setattr(settings_service, "_ENV_PATH", str(env_path))

    assert settings_service.save_settings({"IMAP_STARTUP_EMAIL_LIMIT": "25"}) == []
    assert read_env_pairs(str(env_path))["IMAP_STARTUP_EMAIL_LIMIT"] == "25"
    displayed = settings_service.load_settings()["imap"]["IMAP_STARTUP_EMAIL_LIMIT"]
    assert displayed["value"] == "25"
    assert displayed["label"] == "Startup Email Limit"


def test_settings_page_rejects_non_positive_startup_email_limit(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("IMAP_STARTUP_EMAIL_LIMIT=10\n", encoding="utf-8")
    monkeypatch.setattr(settings_service, "_ENV_PATH", str(env_path))

    errors = settings_service.save_settings({"IMAP_STARTUP_EMAIL_LIMIT": "0"})

    assert errors == ["Startup Email Limit must be a positive integer"]
    assert read_env_pairs(str(env_path))["IMAP_STARTUP_EMAIL_LIMIT"] == "10"


def test_uvicorn_receives_saved_bind_address(monkeypatch):
    captured: dict[str, object] = {}

    class FakeConfig:
        def __init__(self, app, **kwargs):
            captured["app"] = app
            captured.update(kwargs)

    class FakeServer:
        def __init__(self, config):
            captured["config"] = config
            self.should_exit = False

        async def serve(self):
            captured["served"] = True

    monkeypatch.setattr(main.uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(main.uvicorn, "Server", FakeServer)
    app = SimpleNamespace(state=SimpleNamespace())

    main._run_dashboard(app, "0.0.0.0", 5000)

    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 5000
    assert captured["served"] is True
    assert app.state.server is not None


def test_wildcard_bind_uses_localhost_only_for_auto_open_url():
    assert main._dashboard_browser_url("0.0.0.0", 5000) == "http://localhost:5000"


def test_background_email_worker_scans_before_live_monitoring(monkeypatch):
    events: list[str] = []

    class FakeMonitor:
        def __init__(self, config):
            events.append("created")

        def run_startup_scan(self):
            events.append("startup_scan")

        def start(self):
            events.append("live_monitor")

    monkeypatch.setattr(main, "EmailMonitor", FakeMonitor)

    main._run_monitor(SimpleNamespace())

    assert events == ["created", "startup_scan", "live_monitor"]


def test_live_monitor_starts_even_if_background_startup_scan_fails(monkeypatch):
    events: list[str] = []

    class FakeMonitor:
        def __init__(self, config):
            pass

        def run_startup_scan(self):
            events.append("startup_scan")
            raise RuntimeError("IMAP unavailable")

        def start(self):
            events.append("live_monitor")

    monkeypatch.setattr(main, "EmailMonitor", FakeMonitor)

    main._run_monitor(SimpleNamespace())

    assert events == ["startup_scan", "live_monitor"]


def test_main_reaches_dashboard_without_running_startup_scan_inline(monkeypatch):
    events: list[str] = []
    config = SimpleNamespace(
        database_path="test.db",
        log_directory="logs",
        log_level="INFO",
        debug_logging=False,
        debug_log_max_chars=2000,
        firewall_host="192.0.2.1",
        firewall_port=4444,
        firewall_rule_name="Block IP",
        firewall_ping_interval=60,
        imap_host="imap.example.com",
        imap_port=993,
        imap_startup_email_limit=10,
        smtp_host="smtp.example.com",
        smtp_port=587,
        dashboard_host="0.0.0.0",
        dashboard_port=5000,
        auto_open_browser=True,
    )

    class DeferredThread:
        def __init__(self, *, target, args=(), name=None, daemon=None):
            self.name = name

        def start(self):
            events.append(f"thread:{self.name}")

    monkeypatch.setattr(main, "load_config", lambda: config)
    monkeypatch.setattr(main, "configure_logging", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.database, "init_db", lambda path: events.append("database"))
    monkeypatch.setattr(main.threading, "Thread", DeferredThread)
    monkeypatch.setattr(
        "core.legacy_endpoint_migration.run_legacy_endpoint_migration",
        lambda: {"already_applied": True},
    )
    monkeypatch.setattr(
        "core.rule_updater.sync_blocked_ips_from_history", lambda: 0
    )
    monkeypatch.setattr("web.app.create_app", lambda cfg: "dashboard-app")
    monkeypatch.setattr(
        main,
        "_run_dashboard",
        lambda app, host, port: events.append("dashboard"),
    )

    main.main()

    assert events[0] == "database"
    assert events.index("thread:dashboard-browser") < events.index("thread:email-monitor")
    assert "thread:email-monitor" in events
    assert events[-1] == "dashboard"
