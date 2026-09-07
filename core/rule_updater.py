"""High-level orchestrator for appending an IP to the firewall block rule(s).

Flow
----
1. Check the IP against the allowed list -- return ``"allowed"`` if whitelisted.
2. Authenticate with the firewall.
3. Create the IP Host object once (shared by every rule).
4. For each configured rule, in order:
   fetch it, skip if the IP is already present, append the host object,
   validate, upload, and re-fetch to verify the change actually took.
5. Roll the per-rule outcomes up into a single result.

Multiple rules
--------------
``FIREWALL_RULE_NAMES`` may name several rules. Every rule is attempted --
a failure on one never stops the others -- and the outcomes are then
rolled up:

* every rule succeeded (or already had the IP) -> ``"blocked"`` / ``"duplicate"``
* some succeeded, some failed                  -> :class:`PartialBlockError`
* every rule failed                            -> :class:`RuleUpdateError`

``PartialBlockError`` subclasses ``RuleUpdateError`` on purpose: a partial
block is treated exactly like a total failure by every caller, so it is
queued for automatic retry and counted as failed on the dashboard without
any caller needing to know about the distinction. On retry, rules that
already hold the IP short-circuit as duplicates, so only the rules that
are genuinely missing it are reattempted.

All steps are logged; every failure raises :class:`RuleUpdateError`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Optional

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
    rule_element_to_str,
    validate_rule_xml,
)

logger = logging.LoggerAdapter(logging.getLogger(__name__), {"technical": True})

BlockResult = Literal["allowed", "duplicate", "blocked"]


class RuleUpdateError(Exception):
    """Raised when the firewall rule update fails for any reason."""


class PartialBlockError(RuleUpdateError):
    """Raised when an IP was blocked in some configured rules but not all.

    Subclasses :class:`RuleUpdateError` so existing callers -- the live
    monitor, the startup scan, the automatic retry worker and the manual
    dashboard action -- handle a partial block exactly like a total
    failure: the IP is queued for automatic retry and counted as failed.
    The extra attributes let the notification layer say precisely which
    rules succeeded and which did not.

    Attributes
    ----------
    ip:
        The address that was being blocked.
    succeeded:
        Rule names that now contain the IP (newly appended or already present).
    failed:
        ``(rule_name, reason)`` pairs for the rules that could not be updated.
    """

    def __init__(
        self,
        ip: str,
        succeeded: list[str],
        failed: list[tuple[str, str]],
    ) -> None:
        self.ip = ip
        self.succeeded = list(succeeded)
        self.failed = list(failed)
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        failed_part = "; ".join(f"{name!r}: {reason}" for name, reason in self.failed)
        return (
            f"{self.ip} was blocked in {len(self.succeeded)} of "
            f"{len(self.succeeded) + len(self.failed)} configured rules. "
            f"Blocked in: {', '.join(repr(n) for n in self.succeeded)}. "
            f"Failed in: {failed_part}."
        )

    @property
    def failed_rule_names(self) -> list[str]:
        return [name for name, _ in self.failed]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snippet(client: Optional[SophosClient]) -> str:
    """Return a truncated, credential-redacted response snippet for storage."""
    if client is None:
        return ""
    return client.last_response[:1000]


class _HostCreator:
    """Creates the IP Host object on SFOS at most once, on first demand.

    A rule that already contains the IP needs no host object, and several
    rules that do need it must still share a single creation. Both are
    handled by deferring the call to the first rule that actually reaches
    the append step and caching the outcome for the rest.
    """

    def __init__(self, client: SophosClient, host_name: str, ip: str) -> None:
        self._client = client
        self._host_name = host_name
        self._ip = ip
        self._done = False

    def __call__(self) -> None:
        if self._done:
            return
        if self._client.ip_host_exists(self._host_name, self._ip) is True:
            logger.info(
                "IP host %r (%s) already exists on SFOS -- reusing it",
                self._host_name, self._ip,
            )
        else:
            self._client.create_ip_host(self._host_name, self._ip)
            logger.info(
                "Created IP host %r (%s) on SFOS", self._host_name, self._ip
            )
        self._done = True


@dataclass
class _RuleOutcome:
    """Result of attempting to add one host object to one firewall rule."""

    rule_name: str
    ok: bool
    detail: str = ""
    already_present: bool = False


def _logout(client: Optional[SophosClient], own_client: bool) -> None:
    """Close a client this module opened; never raises."""
    if own_client and client is not None:
        try:
            client.logout()
        except Exception:
            pass


def _record_all_rules(
    ip: str,
    rule_names: tuple[str, ...],
    **kwargs: Any,
) -> None:
    """Write one identical firewall_actions row per configured rule.

    Used for failures that happen before any individual rule was reached
    (authentication, host creation), where the outcome is genuinely the
    same for every rule.
    """
    for rule_name in rule_names:
        database.record_firewall_action(ip=ip, rule_name=rule_name, **kwargs)


def _apply_to_rule(
    *,
    client: SophosClient,
    ip: str,
    host_name: str,
    ensure_host: "_HostCreator",
    rule_name: str,
    source: str,
    reason: str,
    alert_id: Optional[int],
) -> _RuleOutcome:
    """Append *host_name* to a single rule and verify it took effect.

    Never raises: every failure mode is caught, recorded as a
    ``firewall_actions`` row, and returned as a failed :class:`_RuleOutcome`
    so the caller can continue with the remaining rules.
    """
    request_started_at = _utcnow()
    try:
        # ── Fetch rule ───────────────────────────────────────────────────────
        response_root = client.get_firewall_rule(rule_name)
        rule_elem = extract_rule_element(response_root, rule_name)

        # ── Duplicate check ──────────────────────────────────────────────────
        # Also what makes retrying a partial block safe: rules that already
        # hold the IP short-circuit here, so only the genuinely missing
        # rules are re-uploaded.
        if ip_in_rule(ip, rule_elem):
            logger.info(
                "IP %s is already in rule %r -- no upload needed", ip, rule_name
            )
            database.record_firewall_action(
                ip=ip, rule_name=rule_name, result="duplicate",
                duplicate=True, status="success",
                detail="IP already present in rule -- no upload needed",
                source=source, reason=reason, alert_id=alert_id,
                request_started_at=request_started_at,
                response_snippet=_snippet(client),
            )
            return _RuleOutcome(rule_name, ok=True, already_present=True)

        # ── Create the host object (first rule that needs it) ────────────────
        ensure_host()

        # ── Append host object name (NOT raw IP) ─────────────────────────────
        logger.debug(
            "SourceNetworks before append on %r: %s",
            rule_name, get_source_networks(rule_elem),
        )
        append_ip_to_rule(host_name, rule_elem)

        # ── Validate and upload ──────────────────────────────────────────────
        validate_rule_xml(rule_elem)
        logger.debug(
            "Firewall rule XML being uploaded to %r:\n%s",
            rule_name, rule_element_to_str(rule_elem),
        )
        client.set_firewall_rule(rule_elem, rule_name)

        # ── Verify the host actually appears in the rule on SFOS ─────────────
        # SFOS can return a success code while silently discarding the change.
        # Re-fetch and confirm so we never report a block that did not happen.
        verify_root = client.get_firewall_rule(rule_name)
        verify_rule = extract_rule_element(verify_root, rule_name)
        verify_networks = get_source_networks(verify_rule)
        if not ip_in_rule(ip, verify_rule):
            raise RuleUpdateError(
                f"SFOS reported success but host {host_name!r} is NOT present in "
                f"rule {rule_name!r} after upload. Current source networks: "
                f"{verify_networks}. The rule was not actually changed."
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
        return _RuleOutcome(rule_name, ok=True)

    except RuleNotFoundError as exc:
        # A rule named in .env that does not exist on the firewall. Surfaced
        # verbatim in the notification because the fix is an .env correction,
        # not a firewall problem.
        detail = str(exc)
        logger.error("Rule not found: %s", detail)
    except InvalidXMLError as exc:
        detail = str(exc)
        logger.error("Invalid XML for rule %r: %s", rule_name, detail)
    except RuleUpdateError as exc:
        detail = str(exc)
        logger.error("Rule %r verification failed: %s", rule_name, detail)
    except FirewallAPIError as exc:
        detail = firewall_exception_message(exc)
        logger.error(
            "Firewall API error on rule %r: %s | last response: %.500s",
            rule_name, exc, client.last_response[:500],
        )
        database.record_firewall_action(
            ip=ip, rule_name=rule_name, result="failed", status="failure",
            detail=detail, source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at, status_code=exc.code,
            response_snippet=_snippet(client),
        )
        return _RuleOutcome(rule_name, ok=False, detail=detail)
    except Exception as exc:
        detail = firewall_exception_message(exc)
        logger.exception(
            "Unexpected exception updating rule %r for %s: %s", rule_name, ip, exc
        )

    database.record_firewall_action(
        ip=ip, rule_name=rule_name, result="failed", status="failure",
        detail=detail, source=source, reason=reason, alert_id=alert_id,
        request_started_at=request_started_at,
        response_snippet=_snippet(client),
    )
    return _RuleOutcome(rule_name, ok=False, detail=detail)


def block_ip(
    ip: str,
    config: AppConfig,
    client: Optional[SophosClient] = None,
    *,
    source: str = "automatic",
    reason: str = "",
    alert_id: Optional[int] = None,
) -> BlockResult:
    """Append *ip* to every configured firewall rule's source-network list.

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
        * ``"duplicate"`` -- IP was already present in *every* configured rule.
        * ``"blocked"``   -- IP was appended to every rule that needed it.

    Raises
    ------
    PartialBlockError
        When at least one rule was updated but at least one failed. Carries
        the succeeded/failed rule names so the notification can name them.
    RuleUpdateError
        When no rule could be updated, or on any pre-rule failure
        (authentication, host creation). ``PartialBlockError`` is a
        subclass, so callers that only catch ``RuleUpdateError`` treat a
        partial block as a failure and queue the retry -- which is exactly
        the intended behaviour.
    """
    rule_names = config.firewall_rule_names
    if not rule_names:
        raise RuleUpdateError(
            "No firewall rules are configured -- set FIREWALL_RULE_NAMES in .env"
        )
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
        _record_all_rules(
            ip, rule_names, result="allowed",
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
    # ── 2. Firewall interaction ──────────────────────────────────────────────
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

        # ── 3. Derive host-object name ───────────────────────────────────────
        # SFOS requires every <Network> reference in a rule to be the NAME
        # of an existing IP Host object.  Raw IPs are rejected (code 501).
        # The object is created lazily -- only once a rule is found that
        # actually needs it -- so an IP already present in every rule costs
        # no host API calls at all. _ensure_host caches across rules, so
        # it is created at most once per block regardless of rule count.
        host_name = make_host_name(ip)
        logger.debug("Host object name for %s -> %r", ip, host_name)
        ensure_host = _HostCreator(client, host_name, ip)

    except FirewallAPIError as exc:
        # Authentication or host creation failed -- no rule was reachable,
        # so this is a total failure rather than a partial one.
        safe_reason = firewall_exception_message(exc)
        logger.error(
            "Firewall API error before any rule was updated: %s | last response: %.500s",
            exc, client.last_response[:500] if client else "",
        )
        _record_all_rules(
            ip, rule_names, result="failed", status="failure", detail=safe_reason,
            source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at, status_code=exc.code,
            response_snippet=_snippet(client),
        )
        _logout(client, own_client)
        raise RuleUpdateError(safe_reason) from exc
    except Exception as exc:
        safe_reason = firewall_exception_message(exc)
        logger.exception("Unexpected exception preparing block for %s: %s", ip, exc)
        _record_all_rules(
            ip, rule_names, result="failed", status="failure", detail=safe_reason,
            source=source, reason=reason, alert_id=alert_id,
            request_started_at=request_started_at,
        )
        _logout(client, own_client)
        raise RuleUpdateError(safe_reason) from exc

    # ── 5. Apply the host to every configured rule ───────────────────────────
    # Every rule is attempted even if an earlier one failed, so one broken
    # or misnamed rule never prevents the IP from being blocked everywhere
    # else it can be.
    try:
        outcomes: list[_RuleOutcome] = [
            _apply_to_rule(
                client=client, ip=ip, host_name=host_name,
                ensure_host=ensure_host, rule_name=rule_name,
                source=source, reason=reason, alert_id=alert_id,
            )
            for rule_name in rule_names
        ]
    finally:
        _logout(client, own_client)

    succeeded = [o.rule_name for o in outcomes if o.ok]
    failed = [(o.rule_name, o.detail) for o in outcomes if not o.ok]

    # ── 6. Roll the per-rule outcomes up into one result ─────────────────────
    if failed and not succeeded:
        message = "; ".join(f"{name!r}: {detail}" for name, detail in failed)
        logger.error("Failed to block %s in every configured rule | %s", ip, message)
        raise RuleUpdateError(
            f"{ip} could not be blocked in any configured rule -- {message}"
        )

    if failed:
        error = PartialBlockError(ip, succeeded, failed)
        logger.error("Partial block | %s", error)
        raise error

    if all(o.already_present for o in outcomes):
        logger.info(
            "IP %s is already present in every configured rule -- no upload needed", ip
        )
        return "duplicate"

    logger.info(
        "Rule(s) %s updated and VERIFIED -- %s blocked via host object %r",
        ", ".join(repr(n) for n in succeeded), ip, host_name,
    )
    return "blocked"
