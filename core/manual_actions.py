"""Manual (admin-triggered) IP block/unblock orchestration.

Thin wrapper around :func:`rule_updater.block_ip`/:func:`rule_updater.unblock_ip`
-- the same service the email-driven automation uses -- that adds the extra
policy manual actions need:

* Stricter IP eligibility validation (reject invalid/private/loopback/
  multicast/reserved/allowlisted addresses outright). The automatic
  email-driven flow does NOT perform this check and is intentionally left
  unchanged; it is enforced here only, before ``block_ip`` is ever called.
* Selective retry-queue enqueueing: a failed manual block is only added to
  the automatic retry queue when the failure looks recoverable (a firewall
  API/connectivity error), not for structural failures (e.g. a misconfigured
  rule name) that would just fail identically on every retry.
* A "protected" flag check before unblocking.

No network I/O of its own -- everything firewall-related is delegated to
``rule_updater``.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from . import database
from .config import AppConfig, load_allowed_ips, is_ip_allowed
from .firewall_client import FirewallAPIError
from .firewall_errors import firewall_exception_message
from .rule_updater import RuleUpdateError, block_ip, unblock_ip

logger = logging.getLogger(__name__)


class IneligibleIPError(Exception):
    """Raised when an IP must not be manually blocked."""


class ProtectedIPError(Exception):
    """Raised when an IP is flagged protected and cannot be unblocked."""


def validate_blockable_ip(ip: str, config: AppConfig) -> str:
    """Return *ip* normalized, or raise :class:`IneligibleIPError`.

    Rejects (in order): invalid syntax, loopback, multicast, reserved,
    unspecified (``0.0.0.0``), private (this also covers link-local,
    CGNAT, and documentation/test ranges under Python's ``ipaddress``
    definition), and allowlisted addresses.
    """
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise IneligibleIPError(f"{ip!r} is not a valid IP address") from exc

    if addr.is_loopback:
        raise IneligibleIPError(f"{ip} is a loopback address and cannot be blocked")
    if addr.is_multicast:
        raise IneligibleIPError(f"{ip} is a multicast address and cannot be blocked")
    if addr.is_reserved:
        raise IneligibleIPError(f"{ip} is in a reserved address range and cannot be blocked")
    if addr.is_unspecified:
        raise IneligibleIPError(f"{ip} is an unspecified address and cannot be blocked")
    if addr.is_private:
        raise IneligibleIPError(f"{ip} is a private address and cannot be blocked")

    allowed = load_allowed_ips(config.allowed_ips_file)
    if is_ip_allowed(ip, allowed):
        raise IneligibleIPError(f"{ip} is on the allowed IPs list and cannot be blocked")

    return str(addr)


@dataclass
class ManualBlockOutcome:
    result: str  # "blocked" | "duplicate" | "allowed"
    ip: str
    detail: str


def manual_block_ip(ip: str, reason: str, config: AppConfig) -> ManualBlockOutcome:
    """Validate and block *ip* through the shared ``block_ip`` service.

    Raises
    ------
    IneligibleIPError
        The IP fails eligibility validation -- never reaches the firewall.
    RuleUpdateError
        The firewall call itself failed. If the underlying cause is a
        :class:`FirewallAPIError` (a transient/connectivity-type failure),
        the IP is queued into the existing automatic retry queue so the
        background worker keeps trying without the admin needing to
        re-click; any other failure (bad rule name, malformed XML) is
        treated as non-recoverable and is surfaced to the admin instead of
        being silently retried forever.
    """
    normalized = validate_blockable_ip(ip, config)
    reason = reason.strip()

    try:
        result = block_ip(normalized, config, source="manual", reason=reason)
    except RuleUpdateError as exc:
        safe_reason = firewall_exception_message(exc)
        logger.debug(
            "Full manual firewall block exception",
            exc_info=True,
            extra={"technical": True},
        )
        recoverable = isinstance(exc.__cause__, FirewallAPIError)
        existing = database.get_pending_block(normalized)
        attempt_number = (existing["attempts"] + 1) if existing else 1
        if recoverable:
            database.reserve_pending_block(normalized, safe_reason)
            logger.error(
                "Failed to block %s | Reason: %s",
                normalized,
                safe_reason,
                extra={"category": "Firewall Action"},
            )
            logger.warning(
                "Retry scheduled | IP: %s | Attempt: %d",
                normalized,
                attempt_number,
                extra={"category": "Retry Queue"},
            )
        else:
            logger.error(
                "Failed to block %s | Reason: %s | Retry not scheduled",
                normalized,
                safe_reason,
                extra={"category": "Firewall Action"},
            )
        database.record_retry_history(
            normalized, attempt_number=attempt_number, status="failure",
            error=safe_reason, source="manual",
        )
        raise RuleUpdateError(safe_reason) from exc

    if result == "blocked":
        return ManualBlockOutcome(
            result="blocked", ip=normalized, detail=f"{normalized} has been blocked."
        )
    if result == "duplicate":
        return ManualBlockOutcome(
            result="duplicate", ip=normalized, detail=f"{normalized} is already blocked."
        )
    # "allowed" shouldn't normally occur here since validate_blockable_ip
    # already filters allowlisted IPs, but handled defensively in case the
    # allow list changed between the two checks.
    return ManualBlockOutcome(
        result="allowed", ip=normalized,
        detail=f"{normalized} is on the allow list and was not blocked.",
    )


@dataclass
class ManualUnblockOutcome:
    result: str  # "unblocked" | "not_blocked"
    ip: str
    detail: str


@dataclass
class RetryNowOutcome:
    result: str  # "blocked" | "duplicate" | "allowed" | "still_failing"
    ip: str
    detail: str


def retry_now(ip: str, config: AppConfig) -> RetryNowOutcome:
    """Immediately retry a queued failed block, without waiting for the next
    automatic polling cycle. Used by the "Retry Now" action on the Alert
    Details page's Retry History section.

    Unlike :func:`manual_block_ip`, a failed retry is reported back as a
    normal (not raised) outcome -- "still failing" is an expected, common
    result of clicking this, not an application error.

    Raises
    ------
    ValueError
        *ip* is not currently in the retry queue.
    """
    ip = ip.strip()
    entry = database.get_pending_block(ip)
    if entry is None:
        raise ValueError(f"{ip} is not currently queued for retry")

    alert_id = entry.get("alert_id")
    attempt_number = entry["attempts"] + 1
    database.mark_retrying(ip)
    try:
        result = block_ip(ip, config, source="manual", reason="Retry Now", alert_id=alert_id)
    except RuleUpdateError as exc:
        safe_reason = firewall_exception_message(exc)
        database.record_retry_attempt(ip, safe_reason)
        database.record_retry_history(
            ip, attempt_number=attempt_number, status="failure",
            error=safe_reason, alert_id=alert_id, source="manual",
        )
        logger.error(
            "Firewall retry failed | IP: %s | Attempt: %d | Reason: %s",
            ip,
            attempt_number,
            safe_reason,
            extra={"category": "Retry Queue"},
        )
        logger.debug(
            "Full firewall retry exception",
            exc_info=True,
            extra={"technical": True},
        )
        return RetryNowOutcome(result="still_failing", ip=ip, detail=safe_reason)
    finally:
        database.clear_retrying(ip)

    database.record_retry_history(
        ip, attempt_number=attempt_number, status="success",
        alert_id=alert_id, source="manual",
    )
    database.resolve_pending_block(ip, result, notified=False)
    return RetryNowOutcome(
        result=result, ip=ip, detail=f"{ip}: retry succeeded ({result})."
    )


def manual_unblock_ip(ip: str, config: AppConfig) -> ManualUnblockOutcome:
    """Unblock *ip* through the shared ``unblock_ip`` service.

    Raises
    ------
    ProtectedIPError
        *ip* is flagged ``protected`` in ``blocked_ips`` -- rejected before
        any firewall call is made.
    RuleUpdateError
        The firewall call itself failed.
    """
    ip = ip.strip()
    record = database.get_blocked_ip(ip)
    if record and record.get("protected"):
        raise ProtectedIPError(f"{ip} is protected and cannot be unblocked")

    result = unblock_ip(ip, config, source="manual")

    if result == "unblocked":
        database.mark_ip_unblocked(ip, source="manual")
        return ManualUnblockOutcome(
            result="unblocked", ip=ip, detail=f"{ip} has been unblocked."
        )
    return ManualUnblockOutcome(
        result="not_blocked", ip=ip, detail=f"{ip} is not currently blocked."
    )
