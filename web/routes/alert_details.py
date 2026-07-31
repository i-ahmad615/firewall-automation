"""API + page route for the Alert Details page.

Aggregates data already recorded by the existing alerts/pending_blocks/
retry_history/blocked_ips tables into a single response --
no new "source of truth" is introduced here, this route only reads and
lightly enriches (IP classification, host-object name, next-retry time)
using the same pure helpers the rest of the app already relies on.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from core import database
from core.endpoint_registry import RegistryUnavailable, registry
from core.email_monitor import sanitize_email_html
from core.xml_handler import make_host_name

from .. import auth

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")

_IMPACTED_IP_ALIASES = frozenset({"impacted ip", "destination ip", "target ip", "host (impacted)"})


def _require_api_auth(request: Request) -> None:
    if not auth.is_logged_in(request):
        raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail_page(alert_id: int, request: Request):
    redirect = auth.require_login_page(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        request, "alert_detail.html", {"active": "alerts", "alert_id": alert_id}
    )


def _safe_json(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except ValueError:
        return default


def _compute_next_retry(last_attempt_at: str, interval_seconds: int) -> Optional[str]:
    try:
        dt = datetime.fromisoformat(last_attempt_at)
    except (TypeError, ValueError):
        return None
    return (dt + timedelta(seconds=interval_seconds)).isoformat()


_SECRET_FIELD_RE = re.compile(
    r"(?i)(password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)"
    r"(\s*[=:]\s*|\s*[\"']\s*:\s*[\"'])([^\s&<\"']+)"
)
_SECRET_XML_RE = re.compile(
    r"(?is)(<(?:Password|Token|ApiKey|Secret)>).*?(</(?:Password|Token|ApiKey|Secret)>)"
)


def _mask_text(value: str, config: Any) -> str:
    """Redact configured credentials and common secret-shaped fields."""
    masked = value
    for attr in (
        "firewall_password", "email_password", "smtp_password", "admin_password",
    ):
        secret = str(getattr(config, attr, "") or "")
        if secret:
            masked = masked.replace(secret, "***REDACTED***")
    masked = _SECRET_XML_RE.sub(r"\1***REDACTED***\2", masked)
    masked = _SECRET_FIELD_RE.sub(r"\1\2***REDACTED***", masked)
    return masked


def _mask_secrets(value: Any, config: Any) -> Any:
    if isinstance(value, str):
        return _mask_text(value, config)
    if isinstance(value, list):
        return [_mask_secrets(item, config) for item in value]
    if isinstance(value, dict):
        masked: dict[Any, Any] = {}
        for key, item in value.items():
            key_name = str(key).lower().replace("-", "_")
            if any(token in key_name for token in ("password", "passwd", "api_key", "token", "secret")):
                masked[key] = "***REDACTED***"
            else:
                masked[key] = _mask_secrets(item, config)
        return masked
    return value


@router.get("/api/alerts/{alert_id}")
def api_get_alert_detail(alert_id: int, request: Request):
    _require_api_auth(request)
    config = request.app.state.config

    alert = database.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    parsed_data = _safe_json(alert.get("parsed_data"), {})
    validation_checks = _safe_json(alert.get("validation_results"), [])
    ip = (alert.get("origin_ip") or "").strip()

    email_raw = alert.get("email_body") or ""
    email = {
        "subject": alert.get("subject", ""),
        "sender": alert.get("sender", ""),
        "received_at": alert.get("received_at", ""),
        "body_raw": email_raw,
        "body_sanitized": sanitize_email_html(email_raw) if email_raw else "",
        "has_body": bool(email_raw),
    }

    impacted_ip = next(
        (v for k, v in parsed_data.items() if k.strip().lower() in _IMPACTED_IP_ALIASES and v),
        None,
    )

    ip_info: dict[str, Any] = {
        "origin_ip": ip or None,
        "impacted_ip": impacted_ip,
        "ip_type": None,
        "is_public": None,
        "is_allowlisted": None,
        "already_blocked": None,
        "host_name": None,
        "first_seen": None,
        "last_seen": None,
        "previous_alert_count": 0,
    }
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
            ip_info["ip_type"] = f"IPv{addr.version}"
            ip_info["is_public"] = not addr.is_private
        except ValueError:
            pass
        try:
            ip_info["is_allowlisted"] = registry.is_external_allowlisted(ip)
        except RegistryUnavailable:
            ip_info["is_allowlisted"] = None
        blocked_row = database.get_blocked_ip(ip)
        ip_info["already_blocked"] = bool(blocked_row and blocked_row.get("status") == "blocked")
        ip_info["host_name"] = make_host_name(ip)
        stats = database.get_ip_alert_stats(ip)
        ip_info["first_seen"] = stats.get("first_seen")
        ip_info["last_seen"] = stats.get("last_seen")
        ip_info["previous_alert_count"] = max(0, (stats.get("count") or 0) - 1)

    pending = database.get_pending_block(ip) if ip else None
    history = database.list_retry_history(ip) if ip else []
    for attempt in history:
        attempt["next_retry_at"] = (
            _compute_next_retry(attempt.get("attempted_at", ""), config.poll_interval)
            if attempt.get("status") == "failure" else None
        )
    next_retry_at = None
    if pending and pending.get("active", True):
        next_retry_at = _compute_next_retry(pending["last_attempt_at"], config.poll_interval)

    summary = {
        "id": alert["id"],
        "alert_id": alert.get("alarm_id") or alert["id"],
        "received_at": alert.get("received_at"),
        "sender": alert.get("sender") or "",
        "subject": alert.get("subject") or "",
        "classification": alert.get("classification") or "",
        "current_status": alert.get("action_taken") or alert.get("status") or "",
        "processing_status": alert.get("processing_status") or alert.get("status") or "",
        "processing_source": alert.get("processing_source") or "live_monitor",
        "created_at": alert.get("received_at"),
        "updated_at": alert.get("updated_at") or alert.get("received_at"),
        "reason": alert.get("reason") or "",
    }
    payload = {
        "alert": summary,
        "email": email,
        "parsed_data": parsed_data,
        "ip_info": ip_info,
        "validation": {
            "checks": validation_checks,
            "decision": alert.get("validation_decision") or "",
        },
        "retry": {
            "pending": pending,
            "history": history,
            "total_attempts": len(history),
            "next_retry_at": next_retry_at,
            "active": bool(pending and pending.get("active", True)),
            "status": pending.get("status") if pending else "not_queued",
        },
    }
    return _mask_secrets(payload, config)
