"""Email monitoring and alert extraction.

Polls IMAP for unread messages, verifies the sender, extracts the Origin IP
from the alert HTML, and delegates to :func:`rule_updater.block_ip`.
Sends an SMTP notification on success or failure.
"""
from __future__ import annotations

import logging
import re
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Optional

from bs4 import BeautifulSoup

from . import database
from .config import AppConfig
from .email_client import EmailConnectionError, ImapMailbox, send_notification
from .rule_updater import block_ip, RuleUpdateError

logger = logging.getLogger(__name__)

_ORIGIN_IP_KEYS: frozenset[str] = frozenset({"origin ip", "host (origin)"})
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ──────────────────────────────────────────────────────────────────────────────
# Pure parsing helpers (no I/O -- fully testable)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_headers(raw: bytes) -> dict[str, str]:
    """Extract subject, from, and date from *raw* RFC 822 bytes."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return {
        "subject": str(msg.get("subject", "")),
        "from": str(msg.get("from", "")),
        "date": str(msg.get("date", "")),
    }


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
                    return "<pre>" + content + "</pre>"
        return None

    return _get_html(msg) or _get_plain(msg)


def _extract_origin_ip_from_html(html: str) -> Optional[str]:
    """Parse the SOC alert HTML and return the Origin IP address."""
    soup = BeautifulSoup(html, "html.parser")

    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            raw_key = cells[0].get_text(separator=" ", strip=True)
            key = " ".join(raw_key.replace("\u00a0", " ").lower().split())
            if key not in _ORIGIN_IP_KEYS:
                continue
            value = cells[1].get_text(separator=" ", strip=True)
            match = _IPV4_RE.search(value)
            if match:
                return match.group(0)

    match = _IPV4_RE.search(html)
    if match:
        logger.debug(
            "Origin IP extracted via regex fallback: %s", match.group(0)
        )
        return match.group(0)
    return None


def _is_from_trusted_sender(from_header: str, trusted: str) -> bool:
    """Return True if the ``From`` header matches *trusted* (case-insensitive)."""
    _, addr = parseaddr(from_header)
    return addr.strip().lower() == trusted.strip().lower()


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


def _notify(config: AppConfig, subject: str, body: str) -> bool:
    """Send a notification email; logs warnings but does not crash the monitor.

    Returns True if the notification was sent successfully.
    """
    try:
        send_notification(config, subject, body)
    except EmailConnectionError as exc:
        logger.warning("Notification not sent: %s", exc)
        database.record_notification(
            subject=subject, recipient=config.notification_email, status="failed"
        )
        return False
    except Exception as exc:
        logger.warning("Unexpected notification error: %s", exc)
        database.record_notification(
            subject=subject, recipient=config.notification_email, status="failed"
        )
        return False
    database.record_notification(
        subject=subject, recipient=config.notification_email, status="sent"
    )
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Main monitor class
# ──────────────────────────────────────────────────────────────────────────────

class EmailMonitor:
    """Polls IMAP and triggers firewall rule updates for each detected threat."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def _process_message(self, uid: str, raw: bytes) -> None:
        headers = _parse_headers(raw)
        subject = headers.get("subject", "")
        from_header = headers.get("from", "")

        logger.info(
            "Email received: uid=%s subject=%r from=%r", uid, subject, from_header
        )

        if not _is_from_trusted_sender(from_header, self._config.trusted_sender):
            logger.info(
                "uid=%s: ignoring -- sender %r is not trusted", uid, from_header
            )
            database.record_alert(
                subject=subject, sender=from_header, status="ignored",
                action_taken="ignored", reason="Sender is not trusted",
            )
            return

        html = _extract_html(raw)
        if not html:
            logger.warning("uid=%s: no readable body -- skipping", uid)
            database.record_alert(
                subject=subject, sender=from_header, status="ignored",
                action_taken="ignored", reason="No readable message body",
            )
            return

        classification = _extract_classification(html)
        matched_keyword = _find_matching_keyword(
            html, subject, self._config.alert_keywords
        )
        if matched_keyword is None:
            logger.info(
                "uid=%s: ignoring -- classification=%r does not match "
                "ALERT_KEYWORDS (%s)",
                uid,
                classification or "<not found>",
                ", ".join(sorted(self._config.alert_keywords)),
            )
            database.record_alert(
                subject=subject, sender=from_header,
                classification=classification or "",
                status="ignored", action_taken="ignored",
                reason="Classification does not match configured alert keywords",
            )
            return

        logger.info(
            "uid=%s: alert keyword %r matched (classification=%r) "
            "-- proceeding with IP extraction",
            uid, matched_keyword, classification or "<not found>",
        )

        origin_ip = _extract_origin_ip_from_html(html)
        if not origin_ip:
            logger.warning(
                "uid=%s: could not extract Origin IP from alert -- skipping", uid
            )
            database.record_alert(
                subject=subject, sender=from_header,
                classification=classification or "",
                status="processed", action_taken="failed",
                reason="Could not extract Origin IP from alert body",
            )
            return

        logger.info("uid=%s: Origin IP extracted: %s", uid, origin_ip)

        try:
            result = block_ip(origin_ip, self._config)
        except RuleUpdateError as exc:
            logger.error("Failed to block %s: %s", origin_ip, exc)
            notified = _notify(
                self._config,
                subject=f"[ALERT] Failed to block {origin_ip}",
                body=(
                    f"Firewall rule update FAILED for IP {origin_ip}.\n\n"
                    f"Error: {exc}\n\nOriginating alert: {subject}"
                ),
            )
            database.record_alert(
                subject=subject, sender=from_header, origin_ip=origin_ip,
                classification=classification or "",
                status="processed", action_taken="failed",
                reason=str(exc), notification_sent=notified,
            )
            database.reserve_pending_block(origin_ip, str(exc))
            return

        if result == "allowed":
            logger.info("IP %s is whitelisted -- no action taken", origin_ip)
            database.record_alert(
                subject=subject, sender=from_header, origin_ip=origin_ip,
                classification=classification or "",
                status="processed", action_taken="allowed",
                reason="Origin IP is on the allow list",
            )
        elif result == "duplicate":
            logger.info(
                "IP %s already blocked in rule %r -- no update sent",
                origin_ip, self._config.firewall_rule_name,
            )
            database.record_alert(
                subject=subject, sender=from_header, origin_ip=origin_ip,
                classification=classification or "",
                status="processed", action_taken="duplicate",
                reason="Origin IP already present in firewall rule",
            )
        elif result == "blocked":
            logger.info(
                "IP %s successfully added to rule %r",
                origin_ip, self._config.firewall_rule_name,
            )
            notified = _notify(
                self._config,
                subject=f"[BLOCKED] {origin_ip} added to firewall rule",
                body=(
                    f"IP {origin_ip} has been appended to the firewall rule "
                    f"'{self._config.firewall_rule_name}' and will be rejected.\n\n"
                    f"Originating alert: {subject}"
                ),
            )
            database.record_alert(
                subject=subject, sender=from_header, origin_ip=origin_ip,
                classification=classification or "",
                status="processed", action_taken="blocked",
                reason="Origin IP appended to firewall rule",
                notification_sent=notified,
            )

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
            )
        pending = database.list_pending_blocks()
        if not pending:
            return
        logger.info("Retrying %d pending firewall block(s)", len(pending))
        for entry in pending:
            ip = entry["ip"]
            try:
                result = block_ip(ip, self._config)
            except RuleUpdateError as exc:
                logger.error(
                    "Retry failed for %s (attempt %d): %s",
                    ip, entry["attempts"] + 1, exc,
                )
                database.reserve_pending_block(ip, str(exc))
                continue

            logger.info(
                "Retry succeeded for %s -- result=%r (attempt %d)",
                ip, result, entry["attempts"] + 1,
            )
            notified = False
            if result == "blocked":
                notified = _notify(
                    self._config,
                    subject=f"[BLOCKED] {ip} added to firewall rule (resolved on retry)",
                    body=(
                        f"IP {ip} previously failed to block but has now been "
                        f"successfully appended to the firewall rule "
                        f"'{self._config.firewall_rule_name}' after "
                        f"{entry['attempts'] + 1} attempt(s)."
                    ),
                )
            database.resolve_pending_block(ip, result, notified=notified)

    def run_once(self) -> int:
        """Execute one IMAP polling cycle."""
        self._retry_pending_blocks()
        mailbox = ImapMailbox(self._config)
        mailbox.connect()
        try:
            messages = mailbox.fetch_unread()
            for uid, raw in messages:
                try:
                    self._process_message(uid, raw)
                except Exception as exc:
                    logger.exception(
                        "Unexpected error processing uid=%s: %s", uid, exc
                    )
                finally:
                    mailbox.mark_seen(uid)
            return len(messages)
        finally:
            mailbox.disconnect()

    def run_forever(self) -> None:
        """Poll IMAP indefinitely."""
        logger.info(
            "Email monitor started | imap=%s:%s smtp=%s:%s interval=%ds",
            self._config.imap_host,
            self._config.imap_port,
            self._config.smtp_host,
            self._config.smtp_port,
            self._config.poll_interval,
        )
        while True:
            try:
                count = self.run_once()
                logger.info("Cycle complete -- %d message(s) processed", count)
            except EmailConnectionError as exc:
                logger.error("IMAP error during polling cycle: %s", exc)
            except Exception as exc:
                logger.exception("Error during polling cycle: %s", exc)
            time.sleep(self._config.poll_interval)

    def start(self) -> None:
        """Start the monitor in loop or single-cycle mode per config."""
        if self._config.run_loop:
            self.run_forever()
        else:
            count = self.run_once()
            logger.info("Single-cycle complete -- %d message(s) processed", count)
