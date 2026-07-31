"""Single database-backed registry for endpoint validation, matching and policy."""
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
    "to prevent blocking a Century-owned or trusted endpoint."
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
    input: str
    normalized_value: str
    value_type: str
    validity: str
    ownership: str
    is_century_owned: bool
    is_external_allowlisted: bool
    is_protected: bool
    is_external_public: bool
    matched_entry_id: Optional[int] = None
    matched_value: Optional[str] = None
    matched_type: Optional[str] = None
    matched_category: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EndpointDecision:
    origin: EndpointClassification
    impacted: EndpointClassification
    selected_candidate: Optional[str]
    selected_side: Optional[str]
    status: str
    reason: str


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


def _public(address: ipaddress._BaseAddress) -> bool:
    return bool(address.is_global and not address.is_private and not address.is_loopback
                and not address.is_link_local and not address.is_multicast
                and not address.is_reserved and not address.is_unspecified)


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

    def match_endpoint(self, value: str, category: str = "") -> Optional[dict[str, Any]]:
        raw = clean_parsed_endpoint(value)
        if not raw:
            return None
        entries = self.get_active_endpoints()
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            address = None
        hostname = normalize_hostname(raw) if address is None else ""
        matches: list[dict[str, Any]] = []
        for entry in entries:
            if category and entry["category"] != category:
                continue
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
                matches.append(entry)
        if not matches:
            return None
        if category:
            return matches[0]
        # Ownership is stronger than external allowlisting. This also makes
        # legacy IP/CIDR overlaps deterministic and fail-safe.
        return next((entry for entry in matches if entry["category"] == CENTURY_OWNED), matches[0])

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
                return self._matched(raw, normalized, "IP", match, _public(address))
            return EndpointClassification(
                raw, normalized, "IP", "valid", "external_public" if _public(address) else "unknown",
                False, False, False, _public(address), reason=(
                    "Valid unprotected external public IP" if _public(address)
                    else "IP is private, loopback, link-local, multicast, reserved or unspecified"
                ),
            )
        if "/" in cleaned or re.fullmatch(r"[0-9a-fA-F:.]+", cleaned):
            try:
                network = ipaddress.ip_network(cleaned, strict=False)
            except ValueError:
                return self._plain(raw, lower, "INVALID", "invalid", "Malformed IP or CIDR endpoint")
            normalized = str(network)
            exact = next((e for e in self.get_active_endpoints()
                          if e["value_type"] == "CIDR" and e["normalized_value"] == normalized), None)
            return self._matched(raw, normalized, "CIDR", exact, False) if exact else self._plain(
                raw, normalized, "CIDR", "valid", "CIDR is not a blockable endpoint")
        hostname = normalize_hostname(cleaned)
        if not _HOSTNAME.fullmatch(hostname):
            return self._plain(raw, hostname, "INVALID", "invalid", "Malformed endpoint")
        match = self.match_endpoint(hostname)
        return self._matched(raw, hostname, "HOSTNAME", match, False) if match else self._plain(
            raw, hostname, "HOSTNAME", "valid", "Hostname ownership could not be verified")

    def is_century_owned(self, value: str) -> bool:
        return self.classify_endpoint(value).is_century_owned

    def is_external_allowlisted(self, value: str) -> bool:
        return self.classify_endpoint(value).is_external_allowlisted

    def is_protected(self, value: str) -> bool:
        return self.classify_endpoint(value).is_protected

    @staticmethod
    def _plain(raw, normalized, kind, validity, reason):
        return EndpointClassification(raw, normalized, kind, validity, "unknown",
                                      False, False, False, False, reason=reason)

    @staticmethod
    def _matched(raw, normalized, kind, match, is_public):
        category = match["category"]
        result = EndpointClassification(
            raw, normalized, kind, "valid",
            "century_owned" if category == CENTURY_OWNED else "external_allowlist",
            category == CENTURY_OWNED, category == EXTERNAL_ALLOWLIST, True, is_public,
            int(match["id"]), match["value"], match["value_type"], category,
            "Matched protected endpoint registry",
        )
        logger.debug(
            "Endpoint %s classified as %s because it matched %s %s, protected endpoint record ID %s",
            normalized, category, match["value_type"], match["value"], match["id"],
            extra={"technical": True},
        )
        try:
            database.record_endpoint_audit(
                "CLASSIFIED", endpoint_id=int(match["id"]), endpoint_value=normalized,
                category=category, new_data={"matched_value": match["value"], "matched_type": match["value_type"]},
            )
        except Exception:
            logger.debug("Could not record endpoint classification audit", exc_info=True,
                         extra={"technical": True})
        return result


registry = ProtectedEndpointRegistry()


def decide_endpoints(origin_value: Optional[str], impacted_value: Optional[str]) -> EndpointDecision:
    origin = registry.classify_endpoint(origin_value)
    impacted = registry.classify_endpoint(impacted_value)
    invalid = {"MISSING", "MASKED", "INVALID"}
    if origin.value_type in invalid or impacted.value_type in invalid:
        return EndpointDecision(origin, impacted, None, None, "incomplete_or_invalid_endpoint",
                                "Missing, masked, malformed or invalid endpoint")
    if origin.normalized_value == impacted.normalized_value:
        return EndpointDecision(origin, impacted, None, None, "same_endpoint",
                                "Origin and Impacted endpoints are identical")
    if origin.is_external_allowlisted or impacted.is_external_allowlisted:
        return EndpointDecision(origin, impacted, None, None, "allowlisted",
                                "An endpoint is protected by the external allowlist")
    if origin.is_century_owned and impacted.is_century_owned:
        return EndpointDecision(origin, impacted, None, None, "century_to_century",
                                "Both endpoints belong to Century")
    if origin.is_century_owned and impacted.is_external_public:
        return EndpointDecision(origin, impacted, impacted.normalized_value, "impacted",
                                "approved_for_blocking", "Origin belongs to Century")
    if origin.is_external_public and impacted.is_century_owned:
        return EndpointDecision(origin, impacted, origin.normalized_value, "origin",
                                "approved_for_blocking", "Impacted endpoint belongs to Century")
    if origin.is_external_public and impacted.is_external_public:
        return EndpointDecision(origin, impacted, None, None, "ambiguous_external_pair",
                                "Neither endpoint belongs to Century")
    return EndpointDecision(origin, impacted, None, None, "unknown_endpoint_review",
                            "Endpoint ownership could not be verified")
