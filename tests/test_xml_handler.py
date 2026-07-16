"""Tests for core/xml_handler.py

Covers: extract_rule_element, get_source_networks, ip_in_rule,
        append_ip_to_rule, validate_rule_xml.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
import pytest

from core.xml_handler import (
    RuleNotFoundError,
    InvalidXMLError,
    extract_rule_element,
    get_source_networks,
    ip_in_rule,
    append_ip_to_rule,
    make_host_name,
    validate_rule_xml,
    rule_element_to_str,
)


# ──────────────────────────────────────────────────────────────────────────────
# Fixture helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_rule(name: str, networks: list[str]) -> ET.Element:
    """Return a minimal FirewallRule element."""
    networks_xml = "".join(f"<Network>{n}</Network>" for n in networks)
    return ET.fromstring(
        f"<FirewallRule>"
        f"  <Name>{name}</Name>"
        f"  <Status>Enable</Status>"
        f"  <NetworkPolicy>"
        f"    <Action>Reject</Action>"
        f"    <SourceNetworks>{networks_xml}</SourceNetworks>"
        f"  </NetworkPolicy>"
        f"</FirewallRule>"
    )


def _wrap_in_response(*rules: ET.Element) -> ET.Element:
    root = ET.Element("Response")
    for rule in rules:
        root.append(rule)
    return root


# ──────────────────────────────────────────────────────────────────────────────
# extract_rule_element
# ──────────────────────────────────────────────────────────────────────────────

class TestExtractRuleElement:
    def test_finds_correct_rule(self) -> None:
        response = _wrap_in_response(_make_rule("Block IP", ["1.1.1.1"]))
        rule = extract_rule_element(response, "Block IP")
        assert rule.findtext("Name") == "Block IP"

    def test_finds_rule_among_multiple(self) -> None:
        response = _wrap_in_response(
            _make_rule("Allow All", []),
            _make_rule("Block IP", ["2.2.2.2"]),
        )
        rule = extract_rule_element(response, "Block IP")
        assert rule.findtext("Name") == "Block IP"

    def test_raises_when_rule_absent(self) -> None:
        response = _wrap_in_response(_make_rule("Other Rule", []))
        with pytest.raises(RuleNotFoundError, match="Block IP"):
            extract_rule_element(response, "Block IP")

    def test_raises_on_empty_response(self) -> None:
        with pytest.raises(RuleNotFoundError):
            extract_rule_element(ET.Element("Response"), "Block IP")

    def test_invalid_rule_id_raises(self) -> None:
        """A non-existent rule name is treated as a missing rule."""
        response = _wrap_in_response(_make_rule("Block IP", []))
        with pytest.raises(RuleNotFoundError):
            extract_rule_element(response, "NonExistentRule")


# ──────────────────────────────────────────────────────────────────────────────
# get_source_networks
# ──────────────────────────────────────────────────────────────────────────────

class TestGetSourceNetworks:
    def test_returns_all_existing_ips(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        assert set(get_source_networks(rule)) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    def test_returns_empty_list_when_no_networks(self) -> None:
        rule = _make_rule("Block IP", [])
        assert get_source_networks(rule) == []

    def test_preserves_order(self) -> None:
        rule = _make_rule("Block IP", ["a.b.c.d", "e.f.g.h", "i.j.k.l"])
        result = get_source_networks(rule)
        assert result == ["a.b.c.d", "e.f.g.h", "i.j.k.l"]


# ──────────────────────────────────────────────────────────────────────────────
# ip_in_rule
# ──────────────────────────────────────────────────────────────────────────────

class TestIpInRule:
    def test_returns_true_for_raw_ip_present(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1", "2.2.2.2"])
        assert ip_in_rule("1.1.1.1", rule) is True

    def test_returns_true_for_host_name_variant(self) -> None:
        # Rule already contains the derived host object name from a previous run
        rule = _make_rule("Block IP", ["blocked-1-1-1-1"])
        assert ip_in_rule("1.1.1.1", rule) is True

    def test_returns_false_when_absent(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1"])
        assert ip_in_rule("9.9.9.9", rule) is False

    def test_returns_false_for_empty_rule(self) -> None:
        rule = _make_rule("Block IP", [])
        assert ip_in_rule("1.1.1.1", rule) is False


class TestMakeHostName:
    def test_dotted_ip_becomes_dashed(self) -> None:
        assert make_host_name("69.5.169.189") == "blocked-69-5-169-189"

    def test_strips_whitespace(self) -> None:
        assert make_host_name("  1.2.3.4  ") == "blocked-1-2-3-4"

    def test_prefix_is_blocked(self) -> None:
        assert make_host_name("10.0.0.1").startswith("blocked-")


# ──────────────────────────────────────────────────────────────────────────────
# append_ip_to_rule
# ──────────────────────────────────────────────────────────────────────────────

class TestAppendIpToRule:
    def test_new_ip_is_appended(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1", "2.2.2.2"])
        append_ip_to_rule("3.3.3.3", rule)
        assert "3.3.3.3" in get_source_networks(rule)

    def test_existing_ips_are_preserved(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1", "2.2.2.2"])
        append_ip_to_rule("3.3.3.3", rule)
        networks = get_source_networks(rule)
        assert "1.1.1.1" in networks
        assert "2.2.2.2" in networks

    def test_no_duplicate_added(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1", "2.2.2.2"])
        append_ip_to_rule("1.1.1.1", rule)  # already present
        assert get_source_networks(rule).count("1.1.1.1") == 1

    def test_ordering_preserved(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1", "2.2.2.2"])
        append_ip_to_rule("3.3.3.3", rule)
        networks = get_source_networks(rule)
        assert networks.index("1.1.1.1") < networks.index("2.2.2.2")
        assert networks.index("2.2.2.2") < networks.index("3.3.3.3")

    def test_creates_container_when_absent(self) -> None:
        """If no SourceNetworks element exists, one is created."""
        rule = ET.fromstring(
            "<FirewallRule>"
            "  <Name>Block IP</Name>"
            "  <NetworkPolicy><Action>Reject</Action></NetworkPolicy>"
            "</FirewallRule>"
        )
        append_ip_to_rule("5.5.5.5", rule)
        assert "5.5.5.5" in get_source_networks(rule)

    def test_raises_when_no_container_or_policy(self) -> None:
        rule = ET.fromstring("<FirewallRule><Name>Block IP</Name></FirewallRule>")
        with pytest.raises(InvalidXMLError):
            append_ip_to_rule("1.2.3.4", rule)

    def test_xml_still_valid_after_append(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1"])
        append_ip_to_rule("2.2.2.2", rule)
        validate_rule_xml(rule)  # must not raise


# ──────────────────────────────────────────────────────────────────────────────
# validate_rule_xml
# ──────────────────────────────────────────────────────────────────────────────

class TestValidateRuleXml:
    def test_valid_rule_does_not_raise(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1"])
        validate_rule_xml(rule)

    def test_missing_name_raises(self) -> None:
        rule = ET.fromstring("<FirewallRule><Status>Enable</Status></FirewallRule>")
        with pytest.raises(InvalidXMLError, match="Name"):
            validate_rule_xml(rule)

    def test_empty_name_raises(self) -> None:
        rule = ET.fromstring("<FirewallRule><Name>   </Name></FirewallRule>")
        with pytest.raises(InvalidXMLError, match="Name"):
            validate_rule_xml(rule)


# ──────────────────────────────────────────────────────────────────────────────
# rule_element_to_str
# ──────────────────────────────────────────────────────────────────────────────

class TestRuleElementToStr:
    def test_returns_string(self) -> None:
        rule = _make_rule("Block IP", ["1.1.1.1"])
        result = rule_element_to_str(rule)
        assert isinstance(result, str)
        assert "Block IP" in result
