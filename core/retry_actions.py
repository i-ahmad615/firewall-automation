"""Operator-triggered actions for the automatic firewall retry queue."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from . import database
from .config import AppConfig
from .firewall_errors import firewall_exception_message
from .rule_updater import RuleUpdateError, block_ip

logger = logging.getLogger(__name__)


@dataclass
class RetryNowOutcome:
    result: str  # blocked | duplicate | allowed | still_failing
    ip: str
    detail: str


def retry_now(ip: str, config: AppConfig) -> RetryNowOutcome:
    """Immediately retry an existing automatic failed-block job."""
    ip = ip.strip()
    entry = database.get_pending_block(ip)
    if entry is None:
        raise ValueError(f"{ip} is not currently queued for retry")

    alert_id = entry.get("alert_id")
    attempt_number = entry["attempts"] + 1
    database.mark_retrying(ip)
    try:
        result = block_ip(
            ip,
            config,
            source="retry_now",
            reason="Retry Now",
            alert_id=alert_id,
        )
    except RuleUpdateError as exc:
        safe_reason = firewall_exception_message(exc)
        database.record_retry_attempt(ip, safe_reason)
        database.record_retry_history(
            ip,
            attempt_number=attempt_number,
            status="failure",
            error=safe_reason,
            alert_id=alert_id,
            source="retry_now",
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
        ip,
        attempt_number=attempt_number,
        status="success",
        alert_id=alert_id,
        source="retry_now",
    )
    database.resolve_pending_block(ip, result, notified=False)
    return RetryNowOutcome(
        result=result,
        ip=ip,
        detail=f"{ip}: retry succeeded ({result}).",
    )
