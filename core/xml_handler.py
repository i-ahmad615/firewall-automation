"""Firewall rule XML parsing and manipulation.

Single responsibility: take a raw SFOS GET response, find the target rule,
read its current source-network list, append a new IP, and validate the
resulting element before it is handed back to the caller for upload.

No network I/O here -- pure XML logic only.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import List

logger = logging.getLogger(__name__)

# SFOS requires every <Network> element in a rule to be the NAME of an IP Host
# object — raw IP addresses are rejected with code 501.  We derive a stable,
# predictable name from the attacker IP so duplicate detection is reliable.
_HOST_NAME_PREFIX = "blocked-"


def make_host_name(ip: str) -> str:
    """Return the SFOS IP host object name for the given attacker IP address.

    Example: ``"69.5.169.189"`` → ``"blocked-69-5-169-189"``
    """
    return f"{_HOST_NAME_PREFIX}{ip.strip().replace('.', '-')}"


# Ordered list of container tag names to probe when looking for source networks.
# SFOS may use different tags across firmware versions.
_SOURCE_CONTAINER_TAGS: tuple[str, ...] = (
    "SourceNetworks",
    "SourceNetwork",
    "SourceHosts",
)

# Tag name for individual entries inside a source-network container
_NETWORK_TAG = "Network"


class RuleNotFoundError(Exception):
    """Raised when the target rule is absent from the SFOS response."""


class InvalidXMLError(Exception):
    """Raised when rule XML is structurally invalid or cannot be validated."""


# ──────────────────────────────────────────────────────────────────────────────
# Extraction helpers
# ──────────────────────────────────────────────────────────────────────────────

def extract_rule_element(response_root: ET.Element, rule_name: str) -> ET.Element:
    """Return the ``<FirewallRule>`` element whose ``<Name>`` matches *rule_name*.

    Parameters
    ----------
    response_root:
        The ``<Response>`` root element returned by :meth:`SophosClient.get_firewall_rule`.
    rule_name:
        Exact name of the firewall rule as configured in SFOS.

    Raises
    ------
    RuleNotFoundError
        If no matching ``<FirewallRule>`` element is found.
    """
    for rule in response_root.findall(".//FirewallRule"):
        name_text = (rule.findtext("Name") or "").strip()
        if name_text == rule_name:
            logger.debug("Located FirewallRule element for %r", rule_name)
            return rule
    raise RuleNotFoundError(
        f"Firewall rule {rule_name!r} not found in SFOS response. "
        "Verify that FIREWALL_RULE_NAME in .env matches the exact rule name in SFOS."
    )


def get_source_networks(rule_element: ET.Element) -> List[str]:
    """Return the ordered list of current source network values in *rule_element*."""
    networks: list[str] = []
    for tag in _SOURCE_CONTAINER_TAGS:
        for container in rule_element.findall(f".//{tag}"):
            for child in container:
                text = (child.text or "").strip()
                if text:
                    networks.append(text)
    logger.debug("Current source networks in rule: %s", networks)
    return networks


def ip_in_rule(ip: str, rule_element: ET.Element) -> bool:
    """Return True if *ip* is already represented in the rule's source networks.

    Checks for both the raw IP string (legacy/other firmware) and the derived
    IP host object name (``blocked-X-X-X-X``) that this system creates.
    """
    networks = get_source_networks(rule_element)
    return ip.strip() in networks or make_host_name(ip) in networks


# ──────────────────────────────────────────────────────────────────────────────
# Mutation helpers
# ──────────────────────────────────────────────────────────────────────────────

def append_ip_to_rule(ip: str, rule_element: ET.Element) -> ET.Element:
    """Append *ip* to the rule's source-network list."""
    ip = ip.strip()

    # Prefer SourceNetworks directly under NetworkPolicy (Sophos standard layout)
    policy = rule_element.find("NetworkPolicy")
    if policy is not None:
        for tag in _SOURCE_CONTAINER_TAGS:
            container = policy.find(tag)
            if container is not None:
                existing = [(child.text or "").strip() for child in container]
                if ip in existing:
                    logger.info("IP %s is already in <%s> -- skipping append", ip, tag)
                    return rule_element
                network_elem = ET.SubElement(container, _NETWORK_TAG)
                network_elem.text = ip
                logger.info("Appended %s to NetworkPolicy/%s", ip, tag)
                return rule_element

    # Fallback: search anywhere in the rule (older/alternate SFOS layouts)
    for tag in _SOURCE_CONTAINER_TAGS:
        container = rule_element.find(f".//{tag}")
        if container is not None:
            existing = [(child.text or "").strip() for child in container]
            if ip in existing:
                logger.info("IP %s is already in <%s> -- skipping append", ip, tag)
                return rule_element
            network_elem = ET.SubElement(container, _NETWORK_TAG)
            network_elem.text = ip
            logger.info("Appended %s to <%s> (fallback path)", ip, tag)
            return rule_element

    # Create SourceNetworks under NetworkPolicy if missing
    if policy is not None:
        container = ET.SubElement(policy, "SourceNetworks")
        network_elem = ET.SubElement(container, _NETWORK_TAG)
        network_elem.text = ip
        logger.info("Created NetworkPolicy/SourceNetworks and added %s", ip)
        return rule_element

    raise InvalidXMLError(
        f"Cannot find or create a SourceNetworks container in rule XML. "
        f"Tried tags: {_SOURCE_CONTAINER_TAGS}. "
        f"Rule snippet: {ET.tostring(rule_element, encoding='unicode')[:500]}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────────────

def validate_rule_xml(rule_element: ET.Element) -> None:
    """Raise InvalidXMLError if *rule_element* fails structural validation.

    Checks performed
    ----------------
    * The element can be serialised and re-parsed without error.
    * ``<Name>`` is present and non-empty.
    """
    try:
        xml_str = ET.tostring(rule_element, encoding="unicode")
        ET.fromstring(xml_str)
    except ET.ParseError as exc:
        raise InvalidXMLError(
            f"Rule XML failed re-parse validation: {exc}"
        ) from exc

    name = (rule_element.findtext("Name") or "").strip()
    if not name:
        raise InvalidXMLError(
            "Rule XML is missing a non-empty <Name> element."
        )

    logger.debug("Rule XML validated successfully for rule %r", name)


def rule_element_to_str(rule_element: ET.Element) -> str:
    """Return the element serialised as a compact unicode string (for logging)."""
    return ET.tostring(rule_element, encoding="unicode")
