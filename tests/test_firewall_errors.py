"""Safe firewall exception translation and retry logging tests."""
from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from core import database
from core.email_monitor import EmailMonitor
from core.firewall_errors import firewall_exception_message
from core.logger import configure_logging
from core.rule_updater import RuleUpdateError
from tests.test_email_catchup import _config


@pytest.fixture(autouse=True)
def _remove_managed_handlers_after_test():
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_security_automation_handler", False):
            root.removeHandler(handler)
            handler.close()
    root.setLevel(logging.WARNING)


def _wrapped(cause: BaseException) -> RuleUpdateError:
    wrapper = RuleUpdateError(str(cause))
    wrapper.__cause__ = cause
    return wrapper


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (
            requests.ConnectTimeout("HTTPSConnectionPool: Max retries exceeded"),
            "Firewall connection timed out after 30 seconds",
        ),
        (
            requests.ReadTimeout("read timed out"),
            "Firewall did not respond within 30 seconds",
        ),
        (
            requests.ConnectionError("connection refused"),
            "Firewall is currently unreachable",
        ),
        (
            requests.exceptions.SSLError("certificate details"),
            "Secure connection to the firewall failed",
        ),
        (RuntimeError("object at 0x1234"), "Firewall request failed unexpectedly"),
    ],
)
def test_firewall_exception_translation(exception, expected):
    assert firewall_exception_message(_wrapped(exception)) == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "Firewall authentication failed"),
        (403, "Firewall authentication failed"),
        (502, "Firewall API returned HTTP 502"),
    ],
)
def test_http_error_translation(status, expected):
    response = requests.Response()
    response.status_code = status
    error = requests.HTTPError("technical HTTP failure", response=response)
    assert firewall_exception_message(_wrapped(error)) == expected


def _flush_logs() -> None:
    for handler in logging.getLogger().handlers:
        handler.flush()


def test_retry_has_one_safe_production_error_and_full_debug_only(tmp_path):
    config = _config(tmp_path)
    database.init_db(config.database_path)
    database.reserve_pending_block("8.8.4.4", "previous failure")
    log_dir = Path(tmp_path) / "logs"
    configure_logging(
        str(log_dir), "INFO", debug_logging=True, debug_max_chars=2000
    )
    technical_text = (
        "HTTPSConnectionPool(host='192.168.20.210'): "
        "Max retries exceeded with url: /webconsole/APIController"
    )
    failure = _wrapped(requests.ConnectTimeout(technical_text))

    with patch("core.email_monitor.block_ip", side_effect=failure):
        EmailMonitor(config)._retry_pending_blocks()
    _flush_logs()

    production = (log_dir / "application.log").read_text(encoding="utf-8")
    debug = (log_dir / "debug.log").read_text(encoding="utf-8")
    errors = (log_dir / "error.log").read_text(encoding="utf-8")
    assert production.count("Firewall retry failed") == 1
    assert production.count("Retry scheduled") == 1
    assert "Firewall connection timed out after 30 seconds" in production
    assert "HTTPSConnectionPool" not in production
    assert "Max retries exceeded" not in production
    assert "Full firewall retry exception" in debug
    assert "HTTPSConnectionPool" in debug
    assert "HTTPSConnectionPool" not in errors
