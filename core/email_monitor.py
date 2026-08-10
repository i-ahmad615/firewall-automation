"""Email monitoring and alert extraction.

Polls IMAP by durable UID checkpoints, verifies the sender, extracts the Origin IP
from the alert HTML, and delegates to :func:`rule_updater.block_ip`.
Sends an SMTP notification on success or failure.
"""
from __future__ import annotations

import ipaddress
import html as html_lib
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any, Iterable, Optional

from bs4 import BeautifulSoup

from . import database
from .config import AppConfig
from .endpoint_registry import (
    REGISTRY_UNAVAILABLE_MESSAGE, RegistryUnavailable, clean_parsed_endpoint, decide_endpoints,
)
from .email_client import EmailConnectionError, ImapMailbox, send_notification
from .logger import SUCCESS
from .firewall_errors import firewall_exception_message
from .rule_updater import block_ip, RuleUpdateError

logger = logging.getLogger(__name__)

# Address-indicator and role tokens for endpoint label classification. A
# table row's label is treated as a given role only if it contains at least
# one address-indicator word *and* at least one word for that role. This
# lets differently-phrased vendor templates ("IP Address (Origin)",
# "Host (Origin)", "Origin IP", "Destination IP", "Target IP", ...) resolve
# to the same role without hardcoding every exact phrase, while avoiding
# accidental matches on unrelated fields that merely mention "origin" or
# "destination" in passing (e.g. a free-text "Description" cell).
_ADDRESS_TOKENS: frozenset[str] = frozenset({"ip", "host", "address"})
_ORIGIN_ROLE_TOKENS: frozenset[str] = frozenset({"origin", "source", "src", "attacker"})
_IMPACTED_ROLE_TOKENS: frozenset[str] = frozenset(
    {"impacted", "destination", "dest", "target", "victim"}
)
_UNDETERMINED_TRUST_TYPES = frozenset({"MISSING", "MASKED", "INVALID"})


def _trust_label(classification) -> str:
    """Human-readable trust label for notifications/dashboard display only.

    This is purely cosmetic -- it never feeds back into the blocking
    decision, which relies solely on ``EndpointClassification.is_trusted``.
    """
    if classification.value_type in _UNDETERMINED_TRUST_TYPES:
        return "unknown"
    return "trusted" if classification.is_trusted else "untrusted"
_FINAL_PROCESSING_STATUSES: frozenset[str] = frozenset({
    "blocked_successfully",
    "already_blocked",
    "allowlisted",
    "invalid_ip",
    "manually_resolved",
})
_REPROCESSABLE_STATUSES: frozenset[str] = frozenset({
    "no_keyword_match",
    "not_processed",
    "processing_failed",
    "partial_parse",
    "partially_blocked",
})

# ── HTML sanitization for safe rendering on the Alert Details page ─────────
# Original email bodies are stored verbatim (untouched) for audit purposes;
# this allowlist-based sanitizer is applied only when producing a version
# safe to render as live HTML. Denylisted tags are removed with their
# content; anything else not on the allowlist is unwrapped (text kept, tag
# dropped) rather than removed outright, so unexpected vendor-specific
# markup degrades to plain text instead of vanishing.
_SANITIZE_DENYLIST_TAGS: frozenset[str] = frozenset(
    {"script", "style", "iframe", "object", "embed", "form", "link", "meta", "noscript", "svg"}
)
_SANITIZE_ALLOWED_TAGS: frozenset[str] = frozenset({
    "table", "thead", "tbody", "tr", "td", "th", "p", "div", "span",
    "b", "strong", "i", "em", "br", "a", "pre", "ul", "ol", "li",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "blockquote", "code",
})
_SANITIZE_ALLOWED_ATTRS: dict[str, frozenset[str]] = {
    "a": frozenset({"href"}),
    "table": frozenset({"border", "cellpadding", "cellspacing"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan"}),
}
_UNSAFE_HREF_SCHEMES: tuple[str, ...] = ("javascript:", "data:", "vbscript:")


def sanitize_email_html(html: str) -> str:
    """Return *html* with scripts, event handlers, and unsafe schemes stripped.

    Allowlist-based: denylisted tags (script/style/iframe/...) are removed
    together with their content; every other tag not on the allowlist is
    unwrapped (its text is kept, the tag itself is dropped); every attribute
    not explicitly allowed for its tag is stripped (this alone removes all
    ``on*`` event-handler attributes, since none are ever allowlisted).
    """
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(_SANITIZE_DENYLIST_TAGS):
        tag.decompose()
    for tag in soup.find_all(True):
        if tag.name not in _SANITIZE_ALLOWED_TAGS:
            tag.unwrap()
            continue
        allowed_attrs = _SANITIZE_ALLOWED_ATTRS.get(tag.name, frozenset())
        for attr in list(tag.attrs):
            if attr not in allowed_attrs:
                del tag.attrs[attr]
        if tag.name == "a" and "href" in tag.attrs:
            href = (tag.attrs.get("href") or "").strip()
            normalized_href = re.sub(r"[\x00-\x20]+", "", href).lower()
            if normalized_href.startswith(_UNSAFE_HREF_SCHEMES):
                del tag.attrs["href"]
    return str(soup)


# ──────────────────────────────────────────────────────────────────────────────
# Pure parsing helpers (no I/O -- fully testable)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_headers(raw: bytes) -> dict[str, str]:
    """Extract the processing-relevant RFC 822 headers from *raw*."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return {
        "subject": str(msg.get("subject", "")),
        "from": str(msg.get("from", "")),
        "date": str(msg.get("date", "")),
        "message_id": str(msg.get("message-id", "")),
    }


def _normalize_message_id(value: str) -> str:
    """Normalize Message-ID for durable, case-insensitive de-duplication."""
    return "".join(value.split()).lower()


def _received_datetime(date_header: str) -> Optional[datetime]:
    """Parse an email Date header into an aware UTC datetime."""
    if not date_header:
        return None
    try:
        value = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, OverflowError):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _extract_html(raw: bytes) -> Optional[str]:
    """Return the first ``text/html`` body part from *raw* RFC 822 bytes."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    def _get_html(m: object) -> Optional[str]:
        for part in (m.walk() if hasattr(m, "walk") else [m]):
            if part.get_content_type() == "text/html":
                return part.get_content()
        return None

    def _get_plain(m: object) -> Optional[str]:
        for part in (m.walk() if hasattr(m, "walk") else [m]):
            if part.get_content_type() == "text/plain":
                content = part.get_content()
                if content and content.strip():
                    return "<pre>" + html_lib.escape(content) + "</pre>"
        return None

    return _get_html(msg) or _get_plain(msg)


def _label_role(key: str) -> Optional[str]:
    """Classify a normalized table-row label as ``"origin"``, ``"impacted"``, or ``None``."""
    words = set(re.findall(r"[a-z0-9]+", key))
    if not words & _ADDRESS_TOKENS:
        return None
    if words & _ORIGIN_ROLE_TOKENS:
        return "origin"
    if words & _IMPACTED_ROLE_TOKENS:
        return "impacted"
    return None


def _first_endpoint_for_role(html: str, role: str) -> Optional[str]:
    """Return the first endpoint value found in a table row classified as *role*.

    Only the row's own two cells are ever consulted -- there is no
    whole-document fallback. Blindly grabbing "any IP/hostname in the
    email" risks silently picking an unrelated value (an email can
    legitimately contain several) instead of correctly reporting the field
    as missing so it can be reviewed manually.

    The value cell is trusted as-is once its label is classified as
    *role* -- an IP and a hostname are equally valid endpoints. The only
    cleanup applied here is stripping a trailing SOC event count such as
    `` (2)`` (see :func:`core.endpoint_registry.clean_parsed_endpoint`);
    everything else (embedded-IP extraction, hostname normalization,
    trust/type classification) is the endpoint registry's job, applied
    later on the value this function returns.
    """
    soup = BeautifulSoup(html, "html.parser")
    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            raw_key = cells[0].get_text(separator=" ", strip=True)
            key = " ".join(raw_key.replace("\u00a0", " ").lower().split())
            if _label_role(key) != role:
                continue
            raw_value = cells[1].get_text(separator=" ", strip=True)
            cleaned = clean_parsed_endpoint(raw_value)
            if cleaned:
                return cleaned
    return None


def _extract_origin_ip_from_html(html: str) -> Optional[str]:
    """Parse the SOC alert HTML and return the Origin endpoint (IP or hostname)."""
    return _first_endpoint_for_role(html, "origin")


def _is_from_trusted_sender(from_header: str, trusted: Iterable[str]) -> bool:
    """Return True if the ``From`` header matches any address in *trusted* (case-insensitive)."""
    _, addr = parseaddr(from_header)
    addr = addr.strip().lower()
    return any(addr == t.strip().lower() for t in trusted)


_CLASSIFICATION_KEYS: frozenset[str] = frozenset({"classification"})


def _extract_classification(html: str) -> Optional[str]:
    """Return the ``Classification`` cell value from the alert HTML table.

    Returns ``None`` when the table row is absent.
    """
    soup = BeautifulSoup(html, "html.parser")
    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            raw_key = cells[0].get_text(separator=" ", strip=True)
            key = " ".join(raw_key.replace("\u00a0", " ").lower().split())
            if key in _CLASSIFICATION_KEYS:
                return cells[1].get_text(separator=" ", strip=True)
    return None


_ALARM_ID_KEYS: frozenset[str] = frozenset({"alarm id"})


def _extract_alarm_id(html: str) -> Optional[str]:
    """Return the ``Alarm ID`` cell value from the alert HTML table, if present."""
    soup = BeautifulSoup(html, "html.parser")
    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            raw_key = cells[0].get_text(separator=" ", strip=True)
            key = " ".join(raw_key.replace("\u00a0", " ").lower().split())
            if key in _ALARM_ID_KEYS:
                return cells[1].get_text(separator=" ", strip=True)
    return None


def _extract_all_fields(html: str) -> dict[str, str]:
    """Return every key/value row found in the alert's HTML table(s).

    Generic superset of the individual ``_extract_*`` helpers above --
    captures whatever fields a given SOC alert email actually contains
    (Alarm Date, Common Event, Description, Alarm Link, Rule Block,
    Impacted IP, etc.) without needing a hardcoded key for each one. Keys
    keep their original (whitespace-normalized) casing for display; if a
    key repeats, the last occurrence wins.
    """
    fields: dict[str, str] = {}
    soup = BeautifulSoup(html, "html.parser")
    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            raw_key = cells[0].get_text(separator=" ", strip=True)
            key = " ".join(raw_key.replace("\u00a0", " ").split())
            value = cells[1].get_text(separator=" ", strip=True)
            if key:
                fields[key] = value
    return fields


def _extract_impacted_ip(html: str) -> Optional[str]:
    """Return the Impacted endpoint (IP or hostname) from the alert HTML table, if present."""
    return _first_endpoint_for_role(html, "impacted")


def _find_matching_keyword(
    html: Optional[str],
    subject: str,
    keywords: frozenset[str],
) -> Optional[str]:
    """Return the first configured keyword matched against the alert classification.

    Matching strategy:

    1. Extract the ``Classification`` table cell from *html*.
       If present, match keywords **only** against that value — this prevents
       the SOC alert subject line (which always contains "Attack IP") from
       triggering a false positive on non-threat alerts such as
       ``Classification: Authentication Success``.
    2. When no ``Classification`` cell is found, fall back to matching
       against the full subject + body text.

    Word-boundary matching is used throughout so ``attack`` matches
    ``Threat List Attack IP`` but not ``counterattack``.
    """
    if not keywords:
        return None

    classification = _extract_classification(html or "")
    if classification is not None:
        text = classification
        source = f"classification={classification!r}"
    else:
        text = f"{subject} {html or ''}"
        source = "subject+body (no Classification cell found)"

    for keyword in sorted(keywords, key=len, reverse=True):
        pattern = re.compile(rf"\b{re.escape(keyword)}\b", re.IGNORECASE)
        if pattern.search(text):
            logger.debug(
                "Keyword %r matched in %s", keyword, source
            )
            return keyword
    return None


def _should_process(html: Optional[str], subject: str, config: AppConfig) -> bool:
    """Return True only when the alert classification matches a configured keyword."""
    return _find_matching_keyword(html, subject, config.alert_keywords) is not None


# ── Notification email presentation ─────────────────────────────────────────
# Pure formatting helpers: turn the same decision data already computed by
# _process_message into a plain-text body (unchanged content, for clients
# without HTML support) and a matching HTML body with a colored status
# header and a table layout. No decision or notification-triggering logic
# lives here -- callers decide *whether* and *what* to report; this only
# decides *how it looks*.
_STATUS_COLORS: dict[str, str] = {
    "BLOCKED": "#15803d",
    "REVIEW REQUIRED": "#b45309",
    "PARTIALLY BLOCKED": "#c2410c",
    "RETRY SCHEDULED": "#1d4ed8",
    "FAILED": "#b91c1c",
}
_TRUST_COLORS: dict[str, str] = {
    "trusted": "#15803d",
    "untrusted": "#b91c1c",
    "unknown": "#6b7280",
}


def _html_escape(value: str) -> str:
    return html_lib.escape(str(value), quote=True)


def _render_trust_badge(value: str) -> str:
    color = _TRUST_COLORS.get(value.strip().lower(), "#6b7280")
    return f'<span style="color:{color};font-weight:600;">{_html_escape(value)}</span>'


def _render_notification(
    config: AppConfig,
    status: str,
    heading: str,
    alarm_id: str,
    rows: list[tuple[str, Optional[str]]],
) -> tuple[str, str]:
    """Render a notification as ``(plain_text, html)``.

    *rows* is the ordered set of label/value pairs to display. A row whose
    value is ``None`` is omitted -- some events (e.g. a retry resolution)
    simply do not have every field available, and a table row must not
    claim data that was never known. Every notification opens with a short
    notice naming the triggering SOC Alarm ID and closes with a footer
    identifying the sending system.
    """
    color = _STATUS_COLORS.get(status, "#374151")
    populated = [(label, value) for label, value in rows if value is not None]
    top_notice = (
        "This is an automated security notification generated in response "
        f"to SOC Alarm ID: {alarm_id or 'Unavailable'}."
    )
    footer = (
        f"This email was generated automatically by the {config.org_name} "
        f"Security Alert & Firewall Automation System - {config.app_name}."
    )

    plain_lines = [f"{status} -- {heading}", "", top_notice, ""]
    plain_lines.extend(f"{label}: {value}" for label, value in populated)
    plain_lines.extend(["", footer])
    plain_text = "\n".join(plain_lines)

    html_rows: list[str] = []
    for label, value in populated:
        value_html = (
            _render_trust_badge(value)
            if label in ("Origin Trust", "Impacted Trust")
            else _html_escape(value).replace("\n", "<br>")
        )
        html_rows.append(
            "<tr>"
            '<td style="width:180px;padding:10px 14px;background-color:#f7f7f8;'
            "font-weight:600;color:#374151;border-bottom:1px solid #eceef1;"
            f'vertical-align:top;font-size:13px;">{_html_escape(label)}</td>'
            '<td style="padding:10px 14px;border-bottom:1px solid #eceef1;'
            f'color:#111827;font-size:13px;white-space:pre-wrap;">{value_html}</td>'
            "</tr>"
        )

    html = (
        '<div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;max-width:640px;margin:0 auto;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="border-collapse:collapse;border:1px solid #e2e4e8;border-radius:6px;overflow:hidden;">'
        "<tr>"
        f'<td style="background-color:{color};color:#ffffff;padding:16px 20px;'
        'font-size:16px;font-weight:700;letter-spacing:0.3px;">'
        f"{_html_escape(status)}"
        f'<div style="font-weight:400;font-size:13px;margin-top:2px;opacity:0.9;">{_html_escape(heading)}</div>'
        "</td></tr>"
        '<tr><td style="padding:10px 20px;background-color:#f9fafb;'
        'border-bottom:1px solid #eceef1;font-size:12px;color:#6b7280;">'
        f"{_html_escape(top_notice)}"
        "</td></tr>"
        '<tr><td style="padding:0;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
        f"{''.join(html_rows)}"
        "</table></td></tr>"
        "</table>"
        '<p style="font-size:11px;color:#9ca3af;margin:12px 4px 0;">'
        f"{_html_escape(footer)}"
        "</p></div>"
    )
    return plain_text, html


def _notify(
    config: AppConfig, subject: str, body: str, html_body: Optional[str] = None
) -> bool:
    """Send a notification email; logs warnings but does not crash the monitor.

    Returns True if the notification was sent successfully.
    """
    try:
        send_notification(config, subject, body, html_body=html_body)
    except EmailConnectionError as exc:
        logger.warning(
            "Confirmation email not sent | Email service unavailable",
            extra={"category": "Notification"},
        )
        logger.debug("Notification transport error: %s", exc, extra={"technical": True})
        database.record_notification(
            subject=subject, recipient=str(config.notification_email), status="failed"
        )
        return False
    except Exception as exc:
        logger.warning(
            "Confirmation email not sent | Unexpected email service error",
            extra={"category": "Notification"},
        )
        logger.debug("Unexpected notification error: %s", exc, extra={"technical": True})
        database.record_notification(
            subject=subject, recipient=str(config.notification_email), status="failed"
        )
        return False
    database.record_notification(
        subject=subject, recipient=str(config.notification_email), status="sent"
    )
    logger.info("Confirmation email sent", extra={"category": "Notification"})
    return True


def _vcheck(check: str, passed: bool, message: str = "", *, skipped: bool = False) -> dict[str, str]:
    """Build one entry for the per-alert validation-results list."""
    result = "Skipped" if skipped else ("Passed" if passed else "Failed")
    return {"check": check, "result": result, "message": message}


# ──────────────────────────────────────────────────────────────────────────────
# Main monitor class
# ──────────────────────────────────────────────────────────────────────────────

class EmailMonitor:
    """Polls IMAP and triggers firewall rule updates for each detected threat."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._imap_account = (
            f"{config.email_username.strip().lower()}|"
            f"{config.imap_host.strip().lower()}:{config.imap_port}"
        )
        self._imap_connected: Optional[bool] = None

    def _process_message(
        self,
        uid: str,
        raw: bytes,
        *,
        processing_source: str = "live_monitor",
        received_at: Optional[str] = None,
        existing_alert: Optional[dict[str, Any]] = None,
        imap_account: str = "",
        imap_folder: str = "",
        imap_uidvalidity: str = "",
        stored_email_id: Optional[int] = None,
    ) -> str:
        """Process one message through the shared live/startup pipeline."""
        headers = _parse_headers(raw)
        subject = headers.get("subject", "")
        from_header = headers.get("from", "")
        message_id = _normalize_message_id(headers.get("message_id", ""))
        received_dt = _received_datetime(headers.get("date", ""))
        original_received_at = received_at or (
            received_dt.isoformat() if received_dt else None
        )
        html = _extract_html(raw)
        classification = _extract_classification(html or "")
        alarm_id = _extract_alarm_id(html or "") or ""
        parsed_fields = _extract_all_fields(html or "")

        if existing_alert is None:
            existing_alert = database.find_alert_by_message_identity(
                message_id,
                uid,
                imap_folder,
                imap_account,
                imap_uidvalidity,
            )
        if existing_alert is None and processing_source == "startup_scan":
            existing_alert = database.find_legacy_alert(
                subject=subject,
                sender=from_header,
                alarm_id=alarm_id,
                email_body=html or "",
            )

        previous_status = (
            (existing_alert or {}).get("processing_status") or "not_processed"
        )
        if existing_alert and database.has_active_retry_for_alert(existing_alert.get("id")):
            database.update_stored_email(
                stored_email_id,
                processing_status=previous_status,
                alert_id=existing_alert.get("id"),
            )
            logger.debug(
                "uid=%s message_id=%s: skipped because retry queue owns alert",
                uid,
                message_id or "<missing>",
            )
            return "skipped:active_retry"
        if existing_alert and previous_status in _FINAL_PROCESSING_STATUSES:
            database.update_stored_email(
                stored_email_id,
                processing_status=previous_status,
                alert_id=existing_alert.get("id"),
            )
            logger.debug(
                "uid=%s message_id=%s: skipped final status=%s",
                uid,
                message_id or "<missing>",
                previous_status,
            )
            return f"skipped:{previous_status}"
        if existing_alert and previous_status not in _REPROCESSABLE_STATUSES:
            database.update_stored_email(
                stored_email_id,
                processing_status=previous_status,
                alert_id=existing_alert.get("id"),
            )
            logger.debug(
                "uid=%s message_id=%s: skipped non-reprocessable status=%s",
                uid,
                message_id or "<missing>",
                previous_status,
            )
            return f"skipped:{previous_status}"

        alert_id = (existing_alert or {}).get("id")
        identity_kwargs: dict[str, Any] = {
            "subject": subject,
            "sender": from_header,
            "classification": classification or "",
            "alarm_id": alarm_id,
            "email_body": html or "",
            "parsed_data": json.dumps(parsed_fields),
            "message_id": message_id,
            "imap_uid": uid,
            "imap_account": imap_account,
            "imap_folder": imap_folder,
            "imap_uidvalidity": imap_uidvalidity,
            "processing_source": processing_source,
        }
        if alert_id:
            database.update_alert(alert_id, **identity_kwargs)
        else:
            alert_id = database.record_alert(
                **identity_kwargs,
                received_at=original_received_at,
                status="processed",
                action_taken="",
                processing_status="not_processed",
            )

        def _save_result(processing_status: str, **values: Any) -> None:
            payload = {**identity_kwargs, **values, "processing_status": processing_status}
            if alert_id:
                database.update_alert(alert_id, **payload)
            else:
                database.record_alert(
                    **payload,
                    received_at=original_received_at,
                )
            database.update_stored_email(
                stored_email_id,
                processing_status=processing_status,
                alert_id=alert_id,
            )

        logger.debug(
            "Email processing: uid=%s message_id=%s source=%s subject=%r from=%r",
            uid,
            message_id or "<missing>",
            processing_source,
            subject,
            from_header,
            extra={"technical": True},
        )
        checks: list[dict[str, str]] = []
        trusted = _is_from_trusted_sender(from_header, self._config.trusted_senders)
        checks.append(_vcheck(
            "Trusted sender check", trusted,
            "Sender matches a configured trusted address" if trusted
            else f"{from_header!r} is not in TRUSTED_SENDERS",
        ))
        if not trusted:
            logger.info(
                "Alert ignored | Sender is not trusted",
                extra={"category": "Alert Processing"},
            )
            _save_result(
                "untrusted_sender",
                status="ignored",
                action_taken="ignored",
                reason="Sender is not trusted",
                validation_results=json.dumps(checks),
                validation_decision="ignored",
            )
            return "untrusted_sender"

        alert_label = f"Alert #{alert_id}" if alert_id else "Alert"
        logger.info(
            "Trusted alert received | Alert ID: %s",
            alert_id if alert_id else "pending",
            extra={"category": "Alert Processing"},
        )

        if not html:
            logger.warning(
                "%s could not be processed | No readable message body",
                alert_label,
                extra={"category": "Alert Processing"},
            )
            _save_result(
                "partial_parse",
                status="ignored",
                action_taken="ignored",
                reason="No readable message body",
                validation_results=json.dumps(checks),
                validation_decision="ignored",
            )
            return "partial_parse"

        matched_keyword = _find_matching_keyword(
            html, subject, self._config.alert_keywords
        )
        checks.append(_vcheck(
            "Alert classification check", classification is not None,
            f"classification={classification!r}" if classification is not None
            else "No Classification cell found in alert body",
        ))
        checks.append(_vcheck(
            "Keyword match result", matched_keyword is not None,
            f"matched keyword {matched_keyword!r}" if matched_keyword
            else f"none of {sorted(self._config.alert_keywords)} matched",
        ))
        if matched_keyword is None:
            logger.info(
                "%s ignored | No configured keyword matched",
                alert_label,
                extra={"category": "Alert Processing"},
            )
            _save_result(
                "no_keyword_match",
                status="ignored",
                action_taken="ignored",
                reason="Classification does not match configured alert keywords",
                validation_results=json.dumps(checks),
                validation_decision="ignored",
            )
            return "no_keyword_match"

        origin_value = _extract_origin_ip_from_html(html) or ""
        impacted_value = _extract_impacted_ip(html) or ""
        try:
            decision = decide_endpoints(origin_value, impacted_value)
        except RegistryUnavailable:
            logger.warning(REGISTRY_UNAVAILABLE_MESSAGE, extra={"category": "Alert Processing"})
            plain_body, html_body = _render_notification(
                self._config,
                "REVIEW REQUIRED",
                "Protected endpoint registry unavailable",
                alarm_id,
                [
                    ("Alarm ID", alarm_id or "Unavailable"),
                    ("Original Subject", subject),
                    ("Classification", classification or "N/A"),
                    ("Origin", origin_value or "Unavailable"),
                    ("Origin Trust", "N/A"),
                    ("Impacted", impacted_value or "Unavailable"),
                    ("Impacted Trust", "N/A"),
                    ("Action Taken", "No firewall action was performed."),
                    ("Reason", REGISTRY_UNAVAILABLE_MESSAGE),
                    ("Recommended Action", "N/A"),
                ],
            )
            notified = _notify(
                self._config, "[REVIEW REQUIRED] Protected endpoint registry unavailable",
                plain_body, html_body=html_body,
            )
            _save_result(
                "protected_registry_unavailable", status="processed", action_taken="ignored",
                reason=REGISTRY_UNAVAILABLE_MESSAGE, notification_sent=notified,
                validation_results=json.dumps(checks), validation_decision="rejected",
                origin_original=origin_value, impacted_original=impacted_value,
                decision_status="protected_registry_unavailable",
                decision_reason=REGISTRY_UNAVAILABLE_MESSAGE,
            )
            return "protected_registry_unavailable"

        endpoint_values = {
            "origin_ip": (
                decision.origin.normalized_value
                if decision.origin.value_type in ("IP", "HOSTNAME") else origin_value
            ),
            "impacted_ip": (
                decision.impacted.normalized_value
                if decision.impacted.value_type in ("IP", "HOSTNAME") else impacted_value
            ),
            "origin_original": origin_value, "origin_normalized": decision.origin.normalized_value,
            "origin_type": decision.origin.value_type, "origin_ownership": _trust_label(decision.origin),
            "impacted_original": impacted_value, "impacted_normalized": decision.impacted.normalized_value,
            "impacted_type": decision.impacted.value_type, "impacted_ownership": _trust_label(decision.impacted),
            "selected_candidate": ",".join(ip for _, ip in decision.candidates),
            "decision_status": decision.status, "decision_reason": decision.reason,
        }
        identity_kwargs.update(endpoint_values)
        checks.append(_vcheck(
            "Endpoint decision", decision.status == "approved_for_blocking",
            f"{decision.status}: {decision.reason}",
        ))
        if decision.status != "approved_for_blocking":
            origin_display = origin_value or "Unavailable"
            impacted_display = impacted_value or "Unavailable"
            logger.info(
                "Automatic block skipped | Origin: %s | Impacted: %s | Reason: %s",
                origin_display, impacted_display, decision.reason,
                extra={"category": "Alert Processing"},
            )
            notification_subject = (
                f"[REVIEW REQUIRED] Automatic blocking skipped - Alarm {alarm_id}"
                if alarm_id else f"[REVIEW REQUIRED] Automatic blocking skipped - {subject}"
            )
            plain_body, html_body = _render_notification(
                self._config,
                "REVIEW REQUIRED",
                "Automatic blocking skipped",
                alarm_id,
                [
                    ("Alarm ID", alarm_id or "Unavailable"),
                    ("Original Subject", subject),
                    ("Classification", classification or "N/A"),
                    ("Origin", origin_display),
                    ("Origin Trust", _trust_label(decision.origin)),
                    ("Impacted", impacted_display),
                    ("Impacted Trust", _trust_label(decision.impacted)),
                    ("Action Taken", "No automatic firewall block was performed."),
                    ("Reason", decision.reason),
                    ("Recommended Action", "Review the original SOC alert and endpoint trust status manually."),
                ],
            )
            notified = _notify(
                self._config, notification_subject, plain_body, html_body=html_body,
            )
            action = "ignored"
            _save_result(
                decision.status, status="processed", action_taken=action,
                reason=decision.reason, notification_sent=notified,
                validation_results=json.dumps(checks), validation_decision="rejected",
                **endpoint_values,
            )
            return decision.status

        checks.append(_vcheck(
            "Firewall duplicate check", True,
            "Sophos rule membership is checked by the shared firewall service",
        ))
        review_note = ""
        if decision.review_sides:
            reviewed_label = "Origin" if decision.review_sides[0] == "origin" else "Impacted"
            review_note = (
                f"\n\nAlso requires manual review:\n{reviewed_label} is an untrusted "
                "hostname/CIDR and cannot be sent to the firewall."
            )

        if len(decision.candidates) == 1:
            candidate_ip = decision.selected_candidate or ""
            logger.info(
                "External %s selected | Origin: %s | Impacted: %s | Reason: %s",
                "destination" if decision.selected_side == "impacted" else "source",
                origin_value, impacted_value, decision.reason,
                extra={"category": "Alert Processing"},
            )

            try:
                if processing_source == "startup_scan":
                    result = block_ip(
                        candidate_ip,
                        self._config,
                        source="startup_scan",
                        alert_id=alert_id,
                    )
                else:
                    # Preserve the established live-monitor call contract.
                    result = block_ip(candidate_ip, self._config)
            except RuleUpdateError as exc:
                safe_reason = firewall_exception_message(exc)
                logger.error(
                    "Failed to block %s | Reason: %s",
                    candidate_ip,
                    safe_reason,
                    extra={"category": "Firewall Action"},
                )
                logger.debug(
                    "Full firewall block exception",
                    exc_info=True,
                    extra={"technical": True},
                )
                recommended_lines = ["This IP has been queued for automatic retry."]
                if review_note:
                    recommended_lines.append(review_note.strip())
                plain_body, html_body = _render_notification(
                    self._config,
                    "RETRY SCHEDULED",
                    f"Failed to block {candidate_ip}",
                    alarm_id,
                    [
                        ("Alarm ID", alarm_id or "Unavailable"),
                        ("Original Subject", subject),
                        ("Classification", classification or "N/A"),
                        ("Origin", origin_value or "Unavailable"),
                        ("Origin Trust", _trust_label(decision.origin)),
                        ("Impacted", impacted_value or "Unavailable"),
                        ("Impacted Trust", _trust_label(decision.impacted)),
                        ("Action Taken", f"Attempted to block {candidate_ip} -- firewall update failed."),
                        ("Reason", safe_reason),
                        ("Recommended Action", "\n".join(recommended_lines)),
                    ],
                )
                notified = _notify(
                    self._config,
                    subject=f"[ALERT] Failed to block {candidate_ip}",
                    body=plain_body,
                    html_body=html_body,
                )
                checks.append(_vcheck(
                    "Duplicate check", True,
                    "not evaluated -- firewall call failed", skipped=True,
                ))
                _save_result(
                    "processing_failed",
                    status="processed",
                    action_taken="failed",
                    reason=safe_reason,
                    notification_sent=notified,
                    validation_results=json.dumps(checks),
                    validation_decision="approved",
                    **endpoint_values,
                )
                database.reserve_pending_block(
                    candidate_ip, safe_reason, alarm_id=alarm_id or None, alert_id=alert_id
                )
                database.record_retry_history(
                    candidate_ip, attempt_number=1, status="failure", error=safe_reason,
                    alert_id=alert_id,
                    source="startup_scan" if processing_source == "startup_scan" else "automatic",
                )
                logger.warning(
                    "Retry scheduled | IP: %s | Attempt: 1",
                    candidate_ip,
                    extra={"category": "Retry Queue"},
                )
                return "processing_failed"

            if result == "allowed":
                logger.info(
                    "IP %s is allowlisted | No firewall action required",
                    candidate_ip,
                    extra={"category": "Firewall Action"},
                )
                _save_result(
                    "allowlisted",
                    status="processed",
                    action_taken="allowed",
                    reason="Selected endpoint is protected by the external allowlist",
                    validation_results=json.dumps(checks),
                    validation_decision="rejected",
                    **endpoint_values,
                )
                return "allowlisted"
            if result == "duplicate":
                logger.info(
                    "IP %s is already blocked",
                    candidate_ip,
                    extra={"category": "Firewall Action"},
                )
                checks.append(_vcheck(
                    "Duplicate check", False,
                    "Selected external IP already present in firewall rule",
                ))
                _save_result(
                    "already_blocked",
                    status="processed",
                    action_taken="duplicate",
                    reason="Selected external IP already present in firewall rule",
                    validation_results=json.dumps(checks),
                    validation_decision="approved",
                    **endpoint_values,
                )
                return "already_blocked"

            checks.append(_vcheck(
                "Duplicate check", True, "Selected external IP was not already present"
            ))
            logger.info(
                "Blocking IP %s",
                candidate_ip,
                extra={"category": "Firewall Action"},
            )
            logger.log(
                SUCCESS,
                "IP %s blocked successfully",
                candidate_ip,
                extra={"category": "Firewall Action"},
            )
            plain_body, html_body = _render_notification(
                self._config,
                "BLOCKED",
                f"External {'destination' if decision.selected_side == 'impacted' else 'source'} blocked",
                alarm_id,
                [
                    ("Alarm ID", alarm_id or "Unavailable"),
                    ("Original Subject", subject),
                    ("Classification", classification or "N/A"),
                    ("Origin", origin_value or "Unavailable"),
                    ("Origin Trust", _trust_label(decision.origin)),
                    ("Impacted", impacted_value or "Unavailable"),
                    ("Impacted Trust", _trust_label(decision.impacted)),
                    ("Action Taken", f"External IP {candidate_ip} was blocked successfully."),
                    ("Reason", decision.reason),
                    ("Recommended Action", review_note.strip() if review_note else "N/A"),
                ],
            )
            notified = _notify(
                self._config,
                subject=f"[BLOCKED] External {'destination' if decision.selected_side == 'impacted' else 'source'} blocked - Alarm {alarm_id or subject}",
                body=plain_body,
                html_body=html_body,
            )
            _save_result(
                "blocked_successfully",
                status="processed",
                action_taken="blocked",
                reason="Selected external IP appended to firewall rule",
                notification_sent=notified,
                validation_results=json.dumps(checks),
                validation_decision="approved",
                firewall_action_performed=True,
                **endpoint_values,
            )
            return "blocked_successfully"

        # ── Both Origin and Impacted are untrusted valid IPs: attempt both,
        # independently, so a failure on one never suppresses the other. ──
        logger.info(
            "Both external endpoints selected | Origin: %s | Impacted: %s | Reason: %s",
            origin_value, impacted_value, decision.reason,
            extra={"category": "Alert Processing"},
        )

        def _label(side: str) -> str:
            return "Origin" if side == "origin" else "Impacted"

        outcomes: list[dict[str, str]] = []
        for side, candidate_ip in decision.candidates:
            try:
                if processing_source == "startup_scan":
                    result = block_ip(
                        candidate_ip, self._config, source="startup_scan", alert_id=alert_id,
                    )
                else:
                    result = block_ip(candidate_ip, self._config)
            except RuleUpdateError as exc:
                safe_reason = firewall_exception_message(exc)
                logger.error(
                    "Failed to block %s | Reason: %s", candidate_ip, safe_reason,
                    extra={"category": "Firewall Action"},
                )
                logger.debug(
                    "Full firewall block exception", exc_info=True, extra={"technical": True},
                )
                database.reserve_pending_block(
                    candidate_ip, safe_reason, alarm_id=alarm_id or None, alert_id=alert_id
                )
                database.record_retry_history(
                    candidate_ip, attempt_number=1, status="failure", error=safe_reason,
                    alert_id=alert_id,
                    source="startup_scan" if processing_source == "startup_scan" else "automatic",
                )
                logger.warning(
                    "Retry scheduled | IP: %s | Attempt: 1", candidate_ip,
                    extra={"category": "Retry Queue"},
                )
                outcomes.append({"side": side, "ip": candidate_ip, "result": "failed", "detail": safe_reason})
                continue

            if result == "blocked":
                logger.info("Blocking IP %s", candidate_ip, extra={"category": "Firewall Action"})
                logger.log(
                    SUCCESS, "IP %s blocked successfully", candidate_ip,
                    extra={"category": "Firewall Action"},
                )
            elif result == "duplicate":
                logger.info(
                    "IP %s is already blocked", candidate_ip, extra={"category": "Firewall Action"}
                )
            else:
                logger.info(
                    "IP %s is allowlisted | No firewall action required", candidate_ip,
                    extra={"category": "Firewall Action"},
                )
            outcomes.append({"side": side, "ip": candidate_ip, "result": result, "detail": ""})

        results = [o["result"] for o in outcomes]
        if all(r == "failed" for r in results):
            aggregate_status, action_taken = "processing_failed", "failed"
        elif any(r == "failed" for r in results):
            aggregate_status, action_taken = "partially_blocked", "partial"
        elif any(r == "blocked" for r in results):
            aggregate_status, action_taken = "blocked_successfully", "blocked"
        elif any(r == "duplicate" for r in results):
            aggregate_status, action_taken = "already_blocked", "duplicate"
        else:
            aggregate_status, action_taken = "allowlisted", "allowed"

        def _describe(outcome: dict[str, str]) -> str:
            label = _label(outcome["side"])
            if outcome["result"] == "failed":
                return f"{label} {outcome['ip']}: FAILED to block ({outcome['detail']}) -- queued for automatic retry"
            if outcome["result"] == "blocked":
                return f"{label} {outcome['ip']}: blocked successfully"
            if outcome["result"] == "duplicate":
                return f"{label} {outcome['ip']}: already present in the firewall rule"
            return f"{label} {outcome['ip']}: protected by the external allowlist -- no action needed"

        outcome_lines = "\n".join(_describe(o) for o in outcomes)
        subject_by_status = {
            "blocked_successfully": f"[BLOCKED] Both external endpoints blocked - Alarm {alarm_id or subject}",
            "partially_blocked": f"[PARTIAL] One of two external endpoints blocked - Alarm {alarm_id or subject}",
            "processing_failed": f"[ALERT] Failed to block both external endpoints - Alarm {alarm_id or subject}",
            "already_blocked": f"[REVIEW REQUIRED] Both external endpoints already blocked - Alarm {alarm_id or subject}",
            "allowlisted": f"[REVIEW REQUIRED] Both external endpoints are allowlisted - Alarm {alarm_id or subject}",
        }
        heading_by_status = {
            "blocked_successfully": "Both external endpoints blocked",
            "partially_blocked": "One of two external endpoints blocked",
            "processing_failed": "Failed to block both external endpoints",
            "already_blocked": "Both external endpoints already blocked",
            "allowlisted": "Both external endpoints are allowlisted",
        }
        status_by_aggregate = {
            "blocked_successfully": "BLOCKED",
            "partially_blocked": "PARTIALLY BLOCKED",
            "processing_failed": "RETRY SCHEDULED",
            "already_blocked": "REVIEW REQUIRED",
            "allowlisted": "REVIEW REQUIRED",
        }
        recommended_action = (
            "Failed endpoint(s) have been queued for automatic retry."
            if aggregate_status in ("processing_failed", "partially_blocked")
            else "N/A"
        )
        plain_body, html_body = _render_notification(
            self._config,
            status_by_aggregate[aggregate_status],
            heading_by_status[aggregate_status],
            alarm_id,
            [
                ("Alarm ID", alarm_id or "Unavailable"),
                ("Original Subject", subject),
                ("Classification", classification or "N/A"),
                ("Origin", origin_value or "Unavailable"),
                ("Origin Trust", _trust_label(decision.origin)),
                ("Impacted", impacted_value or "Unavailable"),
                ("Impacted Trust", _trust_label(decision.impacted)),
                (
                    "Action Taken",
                    "Both endpoints were untrusted valid IPs and were evaluated "
                    f"independently:\n{outcome_lines}",
                ),
                ("Reason", decision.reason),
                ("Recommended Action", recommended_action),
            ],
        )
        notified = _notify(
            self._config,
            subject=subject_by_status[aggregate_status],
            body=plain_body,
            html_body=html_body,
        )
        checks.append(_vcheck(
            "Duplicate check", aggregate_status != "processing_failed",
            "; ".join(f"{o['side']}={o['result']}" for o in outcomes),
        ))
        extra_save_kwargs: dict[str, Any] = {}
        if any(r == "blocked" for r in results):
            extra_save_kwargs["firewall_action_performed"] = True
        _save_result(
            aggregate_status,
            status="processed",
            action_taken=action_taken,
            reason="; ".join(_describe(o) for o in outcomes),
            notification_sent=notified,
            validation_results=json.dumps(checks),
            validation_decision="rejected" if aggregate_status == "allowlisted" else "approved",
            **endpoint_values,
            **extra_save_kwargs,
        )
        return aggregate_status

    def run_startup_scan(self) -> dict[str, int]:
        """Check only the latest configured messages in every IMAP folder."""
        summary = {"fetched": 0, "processed": 0, "skipped": 0, "failed": 0}
        mailbox = ImapMailbox(self._config)
        seen_identities: set[str] = set()
        try:
            mailbox.connect()
        except EmailConnectionError as exc:
            logger.warning(
                "Startup email scan unavailable | Email service connection failed",
                extra={"category": "Email Service"},
            )
            logger.debug("Startup IMAP error: %s", exc, extra={"technical": True})
            mailbox.disconnect()
            return summary

        try:
            for folder in self._config.imap_folders:
                try:
                    state = mailbox.select_folder(folder)
                    observed_uids = mailbox.search_uids_since(1)
                except Exception:
                    summary["failed"] += 1
                    logger.error(
                        "Startup email scan failed | Folder: %s",
                        folder,
                        extra={"category": "Email Service"},
                    )
                    logger.debug(
                        "Startup folder scan failure | folder=%r",
                        folder,
                        exc_info=True,
                        extra={"technical": True},
                    )
                    continue

                numeric_uids = sorted(
                    {uid for uid in observed_uids if str(uid).isdigit()}, key=int
                )
                selected_uids = numeric_uids[-self._config.imap_startup_email_limit:]
                highest_observed = int(numeric_uids[-1]) if numeric_uids else 0

                for uid in selected_uids:
                    stored_email_id: Optional[int] = None
                    message_id = ""
                    try:
                        raw = mailbox.fetch_message_peek(uid)
                        stored_email_id, _ = database.store_fetched_email(
                            self._imap_account,
                            folder,
                            state.uidvalidity,
                            uid,
                            raw,
                        )
                        summary["fetched"] += 1
                        headers = _parse_headers(raw)
                        message_id = _normalize_message_id(
                            headers.get("message_id", "")
                        )
                        identity = (
                            f"message-id:{message_id}"
                            if message_id
                            else f"uid:{folder}:{state.uidvalidity}:{uid}"
                        )
                        if identity in seen_identities:
                            summary["skipped"] += 1
                            continue
                        seen_identities.add(identity)
                        result = self._process_message(
                            uid,
                            raw,
                            processing_source="startup_scan",
                            imap_account=self._imap_account,
                            imap_folder=folder,
                            imap_uidvalidity=state.uidvalidity,
                            stored_email_id=stored_email_id,
                        )
                    except Exception:
                        summary["failed"] += 1
                        failed_alert = database.find_alert_by_message_identity(
                            message_id,
                            uid,
                            folder,
                            self._imap_account,
                            state.uidvalidity,
                        )
                        if failed_alert:
                            database.update_alert(
                                failed_alert["id"],
                                processing_status="processing_failed",
                                status="processed",
                                action_taken="failed",
                                reason="Startup email processing failed unexpectedly",
                                processing_source="startup_scan",
                            )
                        if stored_email_id is not None:
                            database.update_stored_email(
                                stored_email_id,
                                processing_status="processing_failed",
                                alert_id=(failed_alert or {}).get("id"),
                            )
                        logger.error(
                            "Startup email processing failed | Folder: %s | UID: %s",
                            folder,
                            uid,
                            extra={"category": "Alert Processing"},
                        )
                        logger.debug(
                            "Startup message failure | folder=%r uid=%s",
                            folder,
                            uid,
                            exc_info=True,
                            extra={"technical": True},
                        )
                        continue
                    if result.startswith("skipped:"):
                        summary["skipped"] += 1
                    else:
                        summary["processed"] += 1

                # Startup establishes the generation and checkpoint even when
                # every selected message was already final or retry-owned.
                database.reset_uid_checkpoint(
                    self._imap_account, folder, state.uidvalidity
                )
                if highest_observed:
                    database.advance_uid_checkpoint(
                        self._imap_account,
                        folder,
                        state.uidvalidity,
                        highest_observed,
                    )
        finally:
            mailbox.disconnect()

        logger.info(
            "Startup email scan completed | Checked: %d | Processed: %d | Skipped: %d | Failed: %d",
            summary["fetched"],
            summary["processed"],
            summary["skipped"],
            summary["failed"],
            extra={"category": "Application"},
        )
        return summary

    def _retry_pending_blocks(self) -> None:
        """Retry every IP reserved after a prior failed block attempt.

        Runs once per polling cycle, before new mail is processed. An IP
        stays reserved (and keeps counting toward the Failed Blocks KPI)
        until the firewall accepts it -- there is no retry limit.
        """
        recovered = database.sync_pending_blocks_from_alerts()
        if recovered:
            logger.info(
                "Recovered %d historical failed block(s) into the retry queue",
                recovered,
                extra={"category": "Retry Queue"},
            )
        pending = database.list_pending_blocks()
        if not pending:
            return
        logger.debug("Retry worker found %d pending block(s)", len(pending))
        for entry in pending:
            ip = entry["ip"]
            alert_id = entry.get("alert_id")
            attempt_number = entry["attempts"] + 1
            database.mark_retrying(ip)
            try:
                result = block_ip(ip, self._config, alert_id=alert_id)
            except RuleUpdateError as exc:
                safe_reason = firewall_exception_message(exc)
                logger.error(
                    "Firewall retry failed | IP: %s | Attempt: %d | Reason: %s",
                    ip, attempt_number, safe_reason,
                    extra={"category": "Retry Queue"},
                )
                logger.debug(
                    "Full firewall retry exception",
                    exc_info=True,
                    extra={"technical": True},
                )
                # Update-only: if an administrator removed this IP from the
                # queue while this retry was in flight, this is a no-op
                # rather than resurrecting the cancelled entry.
                database.record_retry_attempt(ip, safe_reason)
                database.record_retry_history(
                    ip, attempt_number=attempt_number, status="failure",
                    error=safe_reason, alert_id=alert_id, source="automatic",
                )
                next_attempt = (
                    datetime.now().astimezone()
                    + timedelta(seconds=self._config.poll_interval)
                ).strftime("%I:%M %p")
                logger.warning(
                    "Retry scheduled | IP: %s | Next attempt: %s",
                    ip,
                    next_attempt,
                    extra={"category": "Retry Queue"},
                )
                continue
            finally:
                database.clear_retrying(ip)

            logger.log(
                SUCCESS,
                "Retry succeeded | IP: %s | Result: %s | Attempt: %d",
                ip, result, attempt_number,
                extra={"category": "Retry Queue"},
            )
            database.record_retry_history(
                ip, attempt_number=attempt_number, status="success",
                alert_id=alert_id, source="automatic",
            )
            notified = False
            if result == "blocked":
                plain_body, html_body = _render_notification(
                    self._config,
                    "BLOCKED",
                    f"{ip} blocked (resolved on retry)",
                    entry.get("alarm_id") or "",
                    [
                        (
                            "Action Taken",
                            f"IP {ip} previously failed to block but has now been "
                            f"successfully appended to the firewall rule "
                            f"'{self._config.firewall_rule_name}' after "
                            f"{attempt_number} attempt(s).",
                        ),
                    ],
                )
                notified = _notify(
                    self._config,
                    subject=f"[BLOCKED] {ip} added to firewall rule (resolved on retry)",
                    body=plain_body,
                    html_body=html_body,
                )
            database.resolve_pending_block(ip, result, notified=notified)

    def _poll_folder(self, mailbox: ImapMailbox, folder: str) -> int:
        """Fetch, durably store, then process new UIDs from one folder."""
        state = mailbox.select_folder(folder)
        checkpoint = database.get_uid_checkpoint(self._imap_account, folder)
        validity_changed = bool(
            checkpoint and str(checkpoint.get("uidvalidity", "")) != state.uidvalidity
        )
        if checkpoint is None or validity_changed:
            database.reset_uid_checkpoint(
                self._imap_account, folder, state.uidvalidity
            )
            last_uid = 0
            if validity_changed:
                logger.warning(
                    "UID checkpoint reset safely | Folder: %s",
                    folder,
                    extra={"category": "Email Service"},
                )
        else:
            last_uid = int(checkpoint.get("last_fetched_uid") or 0)

        uids = mailbox.search_uids_since(max(1, last_uid + 1))
        # Some IMAP servers treat ``333:*`` as the reversed inclusive range
        # ``332:333`` when 332 is currently highest. Enforce the checkpoint
        # locally so runtime monitoring processes only strictly newer UIDs.
        uids = [uid for uid in uids if uid.isdigit() and int(uid) > last_uid]
        if not last_uid:
            # Startup normally creates the checkpoint. If startup could not
            # connect, or UIDVALIDITY changed later, recover with the same
            # bounded latest-N policy rather than scanning the full mailbox.
            uids = sorted(set(uids), key=int)[-self._config.imap_startup_email_limit:]

        newly_stored = 0
        for uid in uids:
            raw = mailbox.fetch_message_peek(uid)
            stored_email_id, inserted = database.store_fetched_email(
                self._imap_account,
                folder,
                state.uidvalidity,
                uid,
                raw,
            )
            # The checkpoint moves only after the raw bytes are durable.
            database.advance_uid_checkpoint(
                self._imap_account,
                folder,
                state.uidvalidity,
                int(uid),
            )
            if inserted:
                newly_stored += 1
            try:
                self._process_message(
                    uid,
                    raw,
                    imap_account=self._imap_account,
                    imap_folder=folder,
                    imap_uidvalidity=state.uidvalidity,
                    stored_email_id=stored_email_id,
                )
            except Exception as exc:
                database.update_stored_email(
                    stored_email_id, processing_status="processing_failed"
                )
                logger.error(
                    "Stored alert processing failed | Folder: %s",
                    folder,
                    extra={"category": "Alert Processing"},
                )
                logger.debug(
                    "Stored email processing failure | folder=%r uid=%s",
                    folder,
                    uid,
                    exc_info=True,
                    extra={"technical": True},
                )
                continue
        return newly_stored

    def run_once(self) -> int:
        """Execute one folder-aware, UID-checkpointed IMAP polling cycle."""
        self._retry_pending_blocks()
        mailbox = ImapMailbox(self._config)
        try:
            mailbox.connect()
            try:
                fetched = sum(
                    self._poll_folder(mailbox, folder)
                    for folder in self._config.imap_folders
                )
            finally:
                mailbox.disconnect()
            if self._imap_connected is False:
                logger.info(
                    "IMAP connection restored",
                    extra={"category": "Email Service"},
                )
            self._imap_connected = True
            if fetched:
                logger.info(
                    "IMAP poll completed | Status: connected | New emails found: %d",
                    fetched,
                    extra={"category": "Email Service"},
                )
            else:
                logger.info(
                    "IMAP poll completed | Status: connected | No new emails",
                    extra={"category": "Email Service"},
                )
            return fetched
        except EmailConnectionError as exc:
            if self._imap_connected is not False:
                logger.warning(
                    "IMAP connection lost",
                    extra={"category": "Email Service"},
                )
            self._imap_connected = False
            logger.debug(
                "IMAP polling failure",
                exc_info=True,
                extra={"technical": True},
            )
            raise

    def run_forever(self) -> None:
        """Poll IMAP indefinitely."""
        logger.info(
            "Email monitoring started",
            extra={"category": "Email Service"},
        )
        logger.debug(
            "Email monitor endpoints | imap=%s:%s smtp=%s:%s interval=%ds",
            self._config.imap_host, self._config.imap_port,
            self._config.smtp_host, self._config.smtp_port,
            self._config.poll_interval,
            extra={"technical": True},
        )
        while True:
            try:
                self.run_once()
            except EmailConnectionError as exc:
                logger.debug("IMAP polling error: %s", exc, extra={"technical": True})
            except Exception as exc:
                logger.exception(
                    "Technical polling-cycle failure: %s",
                    exc,
                    extra={"technical": True},
                )
            time.sleep(self._config.poll_interval)

    def start(self) -> None:
        """Start the monitor in loop or single-cycle mode per config."""
        if self._config.run_loop:
            self.run_forever()
        else:
            count = self.run_once()
            logger.info(
                "Single email scan completed | Processed: %d",
                count,
                extra={"category": "Email Service"},
            )
