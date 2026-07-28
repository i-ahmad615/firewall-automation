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
