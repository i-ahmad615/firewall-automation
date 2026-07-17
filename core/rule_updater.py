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
from typing import Literal, Optional

from . import database
from .config import AppConfig, load_allowed_ips, is_ip_allowed
from .firewall_client import SophosClient, FirewallAPIError
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

logger = logging.getLogger(__name__)

BlockResult = Literal["allowed", "duplicate", "blocked"]


class RuleUpdateError(Exception):
    """Raised when the firewall rule update fails for any reason."""


def block_ip(
    ip: str,
    config: AppConfig,
    client: Optional[SophosClient] = None,
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

    # ── 1. Allowlist check ────────────────────────────────────────────
    allowed_set = load_allowed_ips(config.allowed_ips_file)
    if is_ip_allowed(ip, allowed_set):
        logger.info(
            "IP %s is whitelisted in %s -- no action taken",
            ip, config.allowed_ips_file,
        )
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="allowed",
            allowed_list=True, status="success",
            detail=f"IP is whitelisted in {config.allowed_ips_file}",
        )
        return "allowed"

    # ── 2-6. Firewall interaction ─────────────────────────────────────
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

        # ── 2. Fetch rule ─────────────────────────────────────────────
        response_root = client.get_firewall_rule(rule_name)
        rule_elem = extract_rule_element(response_root, rule_name)

        # ── 3. Duplicate check ────────────────────────────────────────
        if ip_in_rule(ip, rule_elem):
            logger.info(
                "IP %s is already in rule %r -- no upload needed",
                ip, rule_name,
            )
            database.record_firewall_action(
                ip=ip, rule_name=rule_name, result="duplicate",
                duplicate=True, status="success",
                detail="IP already present in rule -- no upload needed",
            )
            return "duplicate"

        # ── 4. Derive host-object name ────────────────────────────────
        # SFOS requires every <Network> reference in a rule to be the NAME
        # of an existing IP Host object.  Raw IPs are rejected (code 501).
        host_name = make_host_name(ip)
        logger.info(
            "DEBUG make_host_name(%r) -> %r", ip, host_name
        )

        # ── 5. Create IP Host on SFOS ─────────────────────────────────
        logger.info(
            "DEBUG calling create_ip_host(name=%r, ip=%r)", host_name, ip
        )
        client.create_ip_host(host_name, ip)
        logger.info(
            "DEBUG create_ip_host returned -- host %r exists on SFOS", host_name
        )

        # ── 6. Append host object name (NOT raw IP) to rule ──────────
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

        # ── 7. Validate ───────────────────────────────────────────────
        validate_rule_xml(rule_elem)
        logger.info("XML validated successfully")

        # ── 8. Show exact XML being uploaded ──────────────────────────
        from .xml_handler import rule_element_to_str as _to_str
        _xml_str = _to_str(rule_elem)
        logger.info("DEBUG XML being uploaded:\n%s", _xml_str)

        client.set_firewall_rule(rule_elem, rule_name)

        # ── 10. Verify the host actually appears in the rule on SFOS ──
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
        )
        return "blocked"

    except RuleNotFoundError as exc:
        logger.error("Rule not found: %s", exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=str(exc),
        )
        raise RuleUpdateError(str(exc)) from exc
    except InvalidXMLError as exc:
        logger.error("Invalid XML: %s", exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=str(exc),
        )
        raise RuleUpdateError(str(exc)) from exc
    except FirewallAPIError as exc:
        last = client.last_response[:500] if client else ""
        logger.error(
            "Firewall API error: %s | last response: %.500s", exc, last
        )
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=str(exc),
        )
        raise RuleUpdateError(str(exc)) from exc
    except Exception as exc:
        logger.exception("Unexpected exception while blocking %s: %s", ip, exc)
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=str(exc),
        )
        raise RuleUpdateError(str(exc)) from exc
    finally:
        if own_client and client is not None:
            try:
                client.logout()
            except Exception:
                pass
