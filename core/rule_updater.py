"""High-level orchestrator for appending an IP to the firewall block rule.

Flow
----
1. Check the IP against the allowed list -- return ``"allowed"`` if whitelisted.
2. Authenticate with the firewall and fetch the target rule.
3. Check for an existing entry -- return ``"duplicate"`` if already present.
4. Append the IP to the source-network list.
5. Validate the modified XML.
6. Upload the updated rule.
7. Return ``"blocked"`` on success.

All steps are logged; every failure raises :class:`RuleUpdateError`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal, Optional

from . import database
from .config import AppConfig
from .endpoint_registry import REGISTRY_UNAVAILABLE_MESSAGE, RegistryUnavailable, registry
from .firewall_client import SophosClient, FirewallAPIError
from .firewall_errors import firewall_exception_message
from .xml_handler import (
    RuleNotFoundError,
    InvalidXMLError,
    extract_rule_element,
    append_ip_to_rule,
    get_source_networks,
    ip_in_rule,
    make_host_name,
    validate_rule_xml,
)

logger = logging.LoggerAdapter(logging.getLogger(__name__), {"technical": True})

BlockResult = Literal["allowed", "duplicate", "blocked"]


class RuleUpdateError(Exception):
    """Raised when the firewall rule update fails for any reason."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snippet(client: Optional[SophosClient]) -> str:
    """Return a truncated, credential-redacted response snippet for storage."""
    if client is None:
        return ""
    return client.last_response[:1000]


def block_ip(
    ip: str,
    config: AppConfig,
    client: Optional[SophosClient] = None,
    *,
    source: str = "automatic",
    reason: str = "",
    alert_id: Optional[int] = None,
) -> BlockResult:
    """Append *ip* to the configured firewall rule's source-network list.

    Parameters
    ----------
    ip:
        Attacker origin IP address.
    config:
        Loaded application configuration.
    client:
        Optional pre-configured :class:`SophosClient` (primarily for testing).
        When ``None`` a new client is created, used, and logged out automatically.
    source:
        Who triggered this block -- ``"automatic"`` (the default, used by the
        email-driven monitor and its retry worker) or ``"manual"`` (an admin
        action via the dashboard). Recorded on the ``firewall_actions`` row
        and on the firewall action audit row.
    reason:
        Free-text reason, e.g. an admin's note for a manual block. Recorded
        alongside *source*.
    alert_id:
        Id of the originating ``alerts`` row, when known (the automatic
        retry worker has it via ``pending_blocks.alert_id``; the very first
        attempt on a brand new alert does not, since the alert row isn't
        created until after this call returns -- see email_monitor.py).
        Recorded on the ``firewall_actions`` row so the Alert Details page
        can link straight to it; when ``None`` that page falls back to
        correlating by IP instead.

    Returns
    -------
    BlockResult
        * ``"allowed"``   -- IP is whitelisted; no change made.
        * ``"duplicate"`` -- IP is already in the rule; no upload needed.
        * ``"blocked"``   -- IP was appended and the rule was uploaded.

    Raises
    ------
    RuleUpdateError
        On any firewall API, XML, or unexpected error.
    """
    rule_name = config.firewall_rule_name
    request_started_at = _utcnow()

    # â”€â”€ 1. Final trust guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # This is the single choke point every caller (live monitor, startup
    # scan, automatic retry worker, and manual block/retry-now) funnels
    # through -- it re-checks the Protected Endpoints database at the
    # moment of the actual firewall call, not just at decision time, so a
    # candidate that became trusted in between is never blocked. Public and
    # private addresses are treated identically; only trust status matters.
    try:
        candidate = registry.classify_endpoint(ip)
    except RegistryUnavailable as exc:
        logger.warning(REGISTRY_UNAVAILABLE_MESSAGE)
        raise RuleUpdateError(REGISTRY_UNAVAILABLE_MESSAGE) from exc
    if candidate.is_trusted:
        logger.info(
            "Automatic block prevented | Candidate: %s | Reason: Trusted protected endpoint",
            ip,
        )
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="allowed",
            allowed_list=True, status="success",
            detail=f"Protected by registry category {candidate.matched_category}",
            source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
        )
        return "allowed"
    if candidate.value_type != "IP":
        message = "Only a valid IP address may be selected as a block target"
        logger.warning("Automatic block prevented | Candidate: %s | Reason: %s", ip, message)
        raise RuleUpdateError(message)

    # â”€â”€ 2-6. Firewall interaction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    own_client = client is None
    if own_client:
        client = SophosClient(
            host=config.firewall_host,
            port=config.firewall_port,
            username=config.firewall_username,
            password=config.firewall_password,
        )
    try:
        if own_client:
            logger.info(
                "Authenticating with SFOS at %s:%s",
                config.firewall_host, config.firewall_port,
            )
            client.authenticate()

        # â”€â”€ 2. Fetch rule â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        response_root = client.get_firewall_rule(rule_name)
        rule_elem = extract_rule_element(response_root, rule_name)

        # â”€â”€ 3. Duplicate check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if ip_in_rule(ip, rule_elem):
            logger.info(
                "IP %s is already in rule %r -- no upload needed",
                ip, rule_name,
            )
            database.record_firewall_action(
                ip=ip, rule_name=rule_name, result="duplicate",
                duplicate=True, status="success",
                detail="IP already present in rule -- no upload needed",
                source=source, reason=reason, alert_id=alert_id,
                request_started_at=request_started_at,
                response_snippet=_snippet(client),
            )
            return "duplicate"

        # â”€â”€ 4. Derive host-object name â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # SFOS requires every <Network> reference in a rule to be the NAME
        # of an existing IP Host object.  Raw IPs are rejected (code 501).
        host_name = make_host_name(ip)
        logger.info(
            "DEBUG make_host_name(%r) -> %r", ip, host_name
        )

        # â”€â”€ 5. Create IP Host on SFOS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        host_exists = client.ip_host_exists(host_name, ip) is True
        if host_exists:
            logger.info(
                "IP host %r (%s) already exists on SFOS -- reusing it",
                host_name,
                ip,
            )
        else:
            logger.info(
                "DEBUG calling create_ip_host(name=%r, ip=%r)", host_name, ip
            )
            client.create_ip_host(host_name, ip)
            logger.info(
                "DEBUG create_ip_host returned -- host %r exists on SFOS", host_name
            )

        # â”€â”€ 6. Append host object name (NOT raw IP) to rule â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        logger.info(
            "DEBUG SourceNetworks BEFORE append: %s",
            get_source_networks(rule_elem),
        )
        logger.info(
            "DEBUG appending host name %r (not raw IP %r) to rule %r",
            host_name, ip, rule_name,
        )
        append_ip_to_rule(host_name, rule_elem)
        logger.info(
            "DEBUG SourceNetworks AFTER append: %s",
            get_source_networks(rule_elem),
        )

        # â”€â”€ 7. Validate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        validate_rule_xml(rule_elem)
        logger.debug("XML validated successfully")

        # â”€â”€ 8. Show exact XML being uploaded â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        from .xml_handler import rule_element_to_str as _to_str
        _xml_str = _to_str(rule_elem)
        logger.debug("Firewall rule XML being uploaded:\n%s", _xml_str)

        client.set_firewall_rule(rule_elem, rule_name)

        # â”€â”€ 10. Verify the host actually appears in the rule on SFOS â”€â”€
        # SFOS can return a success code while silently discarding the change.
        # Re-fetch the rule and confirm the host object is really present so we
        # never send a false "[BLOCKED]" notification.
        verify_root = client.get_firewall_rule(rule_name)
        verify_rule = extract_rule_element(verify_root, rule_name)
        verify_networks = get_source_networks(verify_rule)
        logger.info(
            "DEBUG post-upload SourceNetworks on SFOS: %s", verify_networks
        )
        if not ip_in_rule(ip, verify_rule):
            raise RuleUpdateError(
                f"SFOS reported success but host {host_name!r} is NOT present in "
                f"rule {rule_name!r} after upload. Current source networks: "
                f"{verify_networks}. The rule was not actually changed -- check "
                f"the DEBUG set_rule payload and SFOS response in the logs."
            )

        logger.info(
            "Rule %r updated and VERIFIED -- %s blocked via host object %r",
            rule_name, ip, host_name,
        )
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="blocked", status="success",
            detail=f"Appended host object {host_name!r} and verified on firewall",
            source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
            response_snippet=_snippet(client),
        )
        return "blocked"

    except RuleUpdateError as exc:
        logger.error("Firewall rule verification failed: %s", exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail="Firewall rule verification failed", source=source,
            reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
        )
        raise
    except RuleNotFoundError as exc:
        logger.error("Rule not found: %s", exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=str(exc), source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
        )
        raise RuleUpdateError(str(exc)) from exc
    except InvalidXMLError as exc:
        logger.error("Invalid XML: %s", exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=str(exc), source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
        )
        raise RuleUpdateError(str(exc)) from exc
    except FirewallAPIError as exc:
        safe_reason = firewall_exception_message(exc)
        last = client.last_response[:500] if client else ""
        logger.error(
            "Firewall API error: %s | last response: %.500s", exc, last
        )
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=safe_reason, source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at, status_code=exc.code,
            response_snippet=_snippet(client),
        )
        raise RuleUpdateError(safe_reason) from exc
    except Exception as exc:
        safe_reason = firewall_exception_message(exc)
        logger.exception("Unexpected exception while blocking %s: %s", ip, exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=safe_reason, source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
        )
        raise RuleUpdateError(safe_reason) from exc
    finally:
        if own_client and client is not None:
            try:
                client.logout()
            except Exception:
                pass

