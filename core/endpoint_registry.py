"""Single database-backed registry for endpoint validation, matching and trust policy.

Trust policy (binary, no ownership truth table)
------------------------------------------------
An endpoint is **TRUSTED** if and only if it matches an *active* record in the
Protected Endpoints database:

* an IP endpoint matches an active ``IP`` record exactly, or falls inside an
  active ``CIDR`` record, or
* a hostname endpoint exactly equals an active ``HOSTNAME`` record (after
  normalization).

Anything that does not match is **UNTRUSTED** -- public and private addresses
are treated identically; there is no separate "Century-owned" / "externally
allowlisted" / "external public" / "unknown" ownership state used for the
blocking decision. The ``category`` column on ``protected_endpoints`` is
retained purely as an administrative label (so the dashboard can still show
*why* an entry is protected); it plays no role in :func:`decide_endpoints`.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any, Optional

from . import database

CENTURY_OWNED = "CENTURY_OWNED"
EXTERNAL_ALLOWLIST = "EXTERNAL_ALLOWLIST"
REGISTRY_UNAVAILABLE_MESSAGE = (
    "Protected endpoint registry is unavailable. Automatic blocking was skipped "
    "to prevent blocking a trusted endpoint."
)
_MASKED = frozenset({"masked", "redacted", "hidden", "unknown", "unavailable", "n/a", "na", "-", "--"})
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I
)
_EMBEDDED_IPV4 = re.compile(
    r"(?<![0-9A-Za-z_./:])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z_./:])"
)
logger = logging.getLogger(__name__)


class RegistryUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class EndpointClassification:
    """Result of classifying a single Origin/Impacted field value.

    ``value_type`` is one of ``MISSING``, ``MASKED``, ``INVALID``, ``IP``,
    ``CIDR`` or ``HOSTNAME``. ``is_trusted`` is the sole signal the decision
    engine uses to determine trust -- it is only ever ``True`` for a ``valid``
    ``IP`` or ``HOSTNAME`` that matched an active Protected Endpoint record.
    """

    input: str
    normalized_value: str
    value_type: str
    validity: str
    is_trusted: bool
    matched_entry_id: Optional[int] = None
    matched_value: Optional[str] = None
    matched_type: Optional[str] = None
    matched_category: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EndpointDecision:
    """Outcome of :func:`decide_endpoints`.

    ``candidates`` holds every ``(side, ip)`` pair approved as a Sophos
    block target -- zero, one, or (when both Origin and Impacted are
    untrusted valid IPs) two. ``review_sides`` lists any side that is an
    untrusted hostname or CIDR: never a block target, but flagged so
    notifications can call out that it still needs manual review even when
    the other side was successfully blocked.
    """

    origin: EndpointClassification
    impacted: EndpointClassification
    candidates: tuple[tuple[str, str], ...]
    review_sides: tuple[str, ...]
    status: str
    reason: str

    @property
    def selected_candidate(self) -> Optional[str]:
        """First (or only) block-target IP -- convenience for single-candidate callers."""
        return self.candidates[0][1] if self.candidates else None

    @property
    def selected_side(self) -> Optional[str]:
        return self.candidates[0][0] if self.candidates else None


def normalize_hostname(value: str) -> str:
    return value.strip().lower().rstrip(".")


def clean_parsed_endpoint(value: str) -> str:
    """Remove only a whitespace-separated trailing numeric event count.

    SOC fields may append values such as `` (1)`` or `` (25)``. Parentheses
    elsewhere remain untouched so malformed or literal endpoint text is not
    silently rewritten.
    """
    return re.sub(r"\s+\(\d+\)$", "", value.strip())


def _embedded_ip_candidates(value: str) -> list[str]:
    """Return the distinct valid IPs embedded in a composite endpoint field.

    Values such as ``pm7-itlab 192.168.10.249`` occur in SOC fields.  An IP
    is accepted only as a separately delimited value.  Repeated occurrences
    of the same IP are collapsed; multiple different IPs remain ambiguous.
    """
    candidates: list[str] = []

    def add(candidate: str) -> None:
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            return
        if normalized not in candidates:
            candidates.append(normalized)

    for match in _EMBEDDED_IPV4.finditer(value):
        add(match.group(0))

    # IPv6 has several valid compressed forms, so the standard library is
    # used to validate delimited tokens instead of duplicating its grammar.
    for token in value.split():
        candidate = token.strip("[](){}<>,;'\"")
        if candidate.lower().startswith(("ip=", "ip:")):
            candidate = candidate[3:]
        if ":" in candidate:
            add(candidate)
    return candidates


def infer_value_type(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Endpoint value is required.")
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "CIDR"
        except ValueError as exc:
            raise ValueError("Invalid CIDR range.") from exc
    try:
        ipaddress.ip_address(raw)
        return "IP"
    except ValueError:
        hostname = normalize_hostname(raw)
        if "*" in hostname or not _HOSTNAME.fullmatch(hostname):
            raise ValueError("Invalid hostname.")
        return "HOSTNAME"


def normalize_value(value: str, value_type: Optional[str] = None) -> tuple[str, str]:
    kind = (value_type or infer_value_type(value)).strip().upper()
    raw = value.strip()
    if not raw:
        raise ValueError("Endpoint value is required.")
    if kind == "IP":
        if "/" in raw:
            raise ValueError("Invalid IP address.")
        try:
            return str(ipaddress.ip_address(raw)), kind
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc
    if kind == "CIDR":
        if "/" not in raw:
            raise ValueError("Invalid CIDR range.")
        try:
            return str(ipaddress.ip_network(raw, strict=False)), kind
        except ValueError as exc:
            raise ValueError("Invalid CIDR range.") from exc
    if kind == "HOSTNAME":
        hostname = normalize_hostname(raw)
        if "*" in hostname or not _HOSTNAME.fullmatch(hostname):
            raise ValueError("Invalid hostname.")
        return hostname, kind
    raise ValueError("Entry type must be IP, CIDR, or HOSTNAME.")


class ProtectedEndpointRegistry:
    def get_active_endpoints(self) -> list[dict[str, Any]]:
        try:
            entries = database.list_protected_endpoints(active_only=True)
        except Exception as exc:
            raise RegistryUnavailable(REGISTRY_UNAVAILABLE_MESSAGE) from exc
        if not entries:
            raise RegistryUnavailable(REGISTRY_UNAVAILABLE_MESSAGE)
        return entries

    def validate_endpoint(self, value: str, value_type: Optional[str] = None) -> dict[str, str]:
        normalized, kind = normalize_value(value, value_type)
        return {"normalized_value": normalized, "value_type": kind}

    def normalize_endpoint(self, value: str, value_type: Optional[str] = None) -> str:
        return normalize_value(value, value_type)[0]

    def match_endpoint(self, value: str) -> Optional[dict[str, Any]]:
        """Return the first active Protected Endpoint record matching *value*.

        * ``IP`` values match an active ``IP`` record exactly, or an active
          ``CIDR`` record that contains the address.
        * Hostnames match an active ``HOSTNAME`` record exactly (after
          normalization). No wildcard/subdomain matching is performed.

        A raw ``CIDR`` value (i.e. the endpoint field itself is a network,
        not a single address) never matches -- there is no "exact CIDR
        match" trust mechanism, only "IP inside a trusted CIDR".
        """
        raw = clean_parsed_endpoint(value)
        if not raw:
            return None
        entries = self.get_active_endpoints()
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            address = None
        hostname = normalize_hostname(raw) if address is None else ""
        for entry in entries:
            try:
                if entry["value_type"] == "IP" and address is not None:
                    matched = address == ipaddress.ip_address(entry["normalized_value"])
                elif entry["value_type"] == "CIDR" and address is not None:
                    network = ipaddress.ip_network(entry["normalized_value"], strict=False)
                    matched = address.version == network.version and address in network
                elif entry["value_type"] == "HOSTNAME" and address is None:
                    matched = hostname == entry["normalized_value"]
                else:
                    matched = False
            except ValueError:
                matched = False
            if matched:
                return entry
        return None

    def classify_endpoint(self, value: Optional[str]) -> EndpointClassification:
        raw = (value or "").strip()
        if not raw:
            return self._plain(raw, "", "MISSING", "missing", "Endpoint is missing")
        cleaned = clean_parsed_endpoint(raw)
        lower = cleaned.lower()
        if lower in _MASKED or "*" in cleaned or re.fullmatch(r"(?:x{1,3}\.){3}x{1,3}", lower):
            return self._plain(raw, lower, "MASKED", "masked", "Endpoint is masked")
        try:
            address = ipaddress.ip_address(cleaned)
        except ValueError:
            address = None
        if address is None:
            embedded_ips = _embedded_ip_candidates(cleaned)
            if len(embedded_ips) > 1:
                return self._plain(
                    raw, cleaned, "INVALID", "invalid",
                    "Multiple different IP addresses found in endpoint field",
                )
            if embedded_ips:
                cleaned = embedded_ips[0]
                address = ipaddress.ip_address(cleaned)
        if address is not None:
            normalized = str(address)
            match = self.match_endpoint(normalized)
            if match:
                return self._matched(raw, normalized, "IP", match)
            return EndpointClassification(
                raw, normalized, "IP", "valid", False,
                reason="Valid IP address is not a trusted Protected Endpoint",
            )
        if "/" in cleaned or re.fullmatch(r"[0-9a-fA-F:.]+", cleaned):
            try:
                network = ipaddress.ip_network(cleaned, strict=False)
            except ValueError:
                return self._plain(raw, lower, "INVALID", "invalid", "Malformed IP or CIDR endpoint")
            # A CIDR value can never be trusted (no "exact CIDR match" trust
            # mechanism) and can never be a block target (only a single IP
            # may be sent to Sophos) -- it is always routed to manual review.
            return EndpointClassification(
                raw, str(network), "CIDR", "valid", False,
                reason="A CIDR range cannot establish trust or be selected as a block target",
            )
        hostname = normalize_hostname(cleaned)
        if not _HOSTNAME.fullmatch(hostname):
            return self._plain(raw, hostname, "INVALID", "invalid", "Malformed endpoint")
        match = self.match_endpoint(hostname)
        if match:
            return self._matched(raw, hostname, "HOSTNAME", match)
        return EndpointClassification(
            raw, hostname, "HOSTNAME", "valid", False,
            reason="Hostname is not a trusted Protected Endpoint",
        )

    def is_trusted(self, value: str) -> bool:
        return self.classify_endpoint(value).is_trusted

    @staticmethod
    def _plain(raw, normalized, kind, validity, reason):
        return EndpointClassification(raw, normalized, kind, validity, False, reason=reason)

    @staticmethod
    def _matched(raw, normalized, kind, match):
        result = EndpointClassification(
            raw, normalized, kind, "valid", True,
            int(match["id"]), match["value"], match["value_type"], match["category"],
            "Matched an active Protected Endpoint record",
        )
        logger.debug(
            "Endpoint %s is TRUSTED because it matched %s %s, protected endpoint record ID %s",
            normalized, match["value_type"], match["value"], match["id"],
            extra={"technical": True},
        )
        try:
            database.record_endpoint_audit(
                "CLASSIFIED", endpoint_id=int(match["id"]), endpoint_value=normalized,
                category=match["category"],
                new_data={"matched_value": match["value"], "matched_type": match["value_type"]},
            )
        except Exception:
            logger.debug("Could not record endpoint classification audit", exc_info=True,
                         extra={"technical": True})
        return result


registry = ProtectedEndpointRegistry()

_INVALID_TYPES = frozenset({"MISSING", "MASKED", "INVALID"})


def _category(item: EndpointClassification) -> str:
    """Classify one endpoint independently of the other side.

    One of:
      * ``"trusted"``         -- matched an active Protected Endpoint.
      * ``"untrusted_ip"``    -- a valid, untrusted IP; the only category
        ever eligible as a Sophos block target.
      * ``"untrusted_nonip"`` -- a syntactically valid but untrusted
        HOSTNAME or CIDR; never a block target, but flagged for review.
      * ``"invalid"``         -- missing, masked, or malformed.
    """
    if item.is_trusted:
        return "trusted"
    if item.value_type == "IP":
        return "untrusted_ip"
    if item.value_type in ("HOSTNAME", "CIDR"):
        return "untrusted_nonip"
    return "invalid"


# Single source of truth for the Origin/Impacted blocking policy. Each side
# is classified independently (see `_category`) into one of 4 categories,
# so the pair fully determines the outcome -- there are no other branches,
# special cases, or precedence rules layered on top of this table.
#
# Values are (status, reason, block_sides) where block_sides is the subset
# of {"origin", "impacted"} approved as Sophos block targets. Only a
# category of "untrusted_ip" is ever included in block_sides -- a trusted
# endpoint, an untrusted hostname/CIDR, and an invalid value are never sent
# to Sophos.
_T, _I, _N, _X = "trusted", "untrusted_ip", "untrusted_nonip", "invalid"

_DECISION_TABLE: dict[tuple[str, str], tuple[str, str, frozenset[str]]] = {
    (_T, _T): ("both_trusted",
               "Both Origin and Impacted are trusted Protected Endpoints",
               frozenset()),
    (_T, _I): ("approved_for_blocking",
               "Origin is trusted; Impacted is untrusted",
               frozenset({"impacted"})),
    (_I, _T): ("approved_for_blocking",
               "Impacted is trusted; Origin is untrusted",
               frozenset({"origin"})),
    (_I, _I): ("approved_for_blocking",
               "Neither Origin nor Impacted is a trusted Protected Endpoint; "
               "both are untrusted valid IPs and will be blocked",
               frozenset({"origin", "impacted"})),
    (_T, _N): ("untrusted_target_not_ip",
               "Untrusted Impacted endpoint is not a valid IP and cannot be blocked",
               frozenset()),
    (_N, _T): ("untrusted_target_not_ip",
               "Untrusted Origin endpoint is not a valid IP and cannot be blocked",
               frozenset()),
    (_N, _I): ("approved_for_blocking",
               "Impacted is an untrusted valid IP and will be blocked; "
               "Origin is an untrusted hostname/CIDR and requires manual review",
               frozenset({"impacted"})),
    (_I, _N): ("approved_for_blocking",
               "Origin is an untrusted valid IP and will be blocked; "
               "Impacted is an untrusted hostname/CIDR and requires manual review",
               frozenset({"origin"})),
    (_N, _N): ("both_untrusted",
               "Neither Origin nor Impacted is a trusted Protected Endpoint, "
               "and neither is a valid IP that can be blocked",
               frozenset()),
    (_X, _I): ("approved_for_blocking",
               "Origin endpoint is missing, masked or malformed; "
               "Impacted is an untrusted valid IP and will be blocked",
               frozenset({"impacted"})),
    (_I, _X): ("approved_for_blocking",
               "Impacted endpoint is missing, masked or malformed; "
               "Origin is an untrusted valid IP and will be blocked",
               frozenset({"origin"})),
    (_X, _T): ("incomplete_or_invalid_endpoint",
               "Missing, masked, malformed or invalid endpoint", frozenset()),
    (_T, _X): ("incomplete_or_invalid_endpoint",
               "Missing, masked, malformed or invalid endpoint", frozenset()),
    (_X, _N): ("incomplete_or_invalid_endpoint",
               "Missing, masked, malformed or invalid endpoint", frozenset()),
    (_N, _X): ("incomplete_or_invalid_endpoint",
               "Missing, masked, malformed or invalid endpoint", frozenset()),
    (_X, _X): ("incomplete_or_invalid_endpoint",
               "Missing, masked, malformed or invalid endpoint", frozenset()),
}


def decide_endpoints(origin_value: Optional[str], impacted_value: Optional[str]) -> EndpointDecision:
    """Origin/Impacted blocking decision, driven entirely by ``_DECISION_TABLE``.

    Origin and Impacted are classified independently; a value present in
    the Protected Endpoints registry is always TRUSTED and never blocked.
    Only a validated, untrusted IP address is ever selected as a block
    target -- a hostname, CIDR, or missing/masked/malformed value is never
    sent to Sophos, regardless of the other side's trust state.
    """
    origin = registry.classify_endpoint(origin_value)
    impacted = registry.classify_endpoint(impacted_value)
    origin_cat = _category(origin)
    impacted_cat = _category(impacted)
    status, reason, block_sides = _DECISION_TABLE[(origin_cat, impacted_cat)]

    candidates: list[tuple[str, str]] = []
    seen_ips: set[str] = set()
    for side, classification in (("origin", origin), ("impacted", impacted)):
        if side in block_sides and classification.normalized_value not in seen_ips:
            candidates.append((side, classification.normalized_value))
            seen_ips.add(classification.normalized_value)

    review_sides = tuple(
        side for side, cat in (("origin", origin_cat), ("impacted", impacted_cat))
        if cat == "untrusted_nonip"
    )

    return EndpointDecision(origin, impacted, tuple(candidates), review_sides, status, reason)
