"""Safe firewall-console header link tests."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from web.routes import pages


def _request(host: str = "192.168.20.210", port: int = 20792):
    config = SimpleNamespace(
        admin_password="",
        firewall_host=host,
        firewall_port=port,
    )
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=config)))


def test_firewall_console_redirect_uses_configured_host_and_port():
    response = pages.open_firewall_console(_request())
    assert response.status_code == 307
    assert response.headers["location"] == "https://192.168.20.210:20792/"


def test_firewall_console_redirect_supports_ipv6_hosts():
    response = pages.open_firewall_console(_request("2001:db8::10", 4444))
    assert response.headers["location"] == "https://[2001:db8::10]:4444/"


def test_header_link_never_contains_firewall_credentials():
    template = Path("web/templates/base.html").read_text(encoding="utf-8")
    assert 'href="/firewall-console"' in template
    assert "firewall_username" not in template
    assert "firewall_password" not in template
