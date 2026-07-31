"""Protected Endpoint Registry validation, matching, API, migration and safety."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from core import database
from core.endpoint_registry import (
    EXTERNAL_ALLOWLIST, CENTURY_OWNED, RegistryUnavailable,
    clean_parsed_endpoint, decide_endpoints, infer_value_type, normalize_value, registry,
)
from core.rule_updater import RuleUpdateError, block_ip
from core.manual_actions import retry_now
from core.legacy_endpoint_migration import run_legacy_endpoint_migration
from web.routes.allowed_ips import (
    ActiveBody, EndpointBody, ImportBody, api_add_allowed_ip,
    api_edit_allowed_ip, api_export_endpoints, api_import_endpoints,
    api_list_allowed_ips, api_remove_allowed_ip, api_set_endpoint_active,
)


def _request():
    config = SimpleNamespace(admin_password="", admin_username="admin")
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=config)))


def _add(value, category=CENTURY_OWNED, *, active=True, description=""):
    normalized, kind = normalize_value(value)
    return database.add_protected_endpoint(
        value, normalized, kind, category, description, active=active
    )


@pytest.mark.parametrize("value,kind,normalized", [
    ("192.168.10.5", "IP", "192.168.10.5"),
    ("2001:0db8::1", "IP", "2001:db8::1"),
    ("192.168.10.8/24", "CIDR", "192.168.10.0/24"),
    ("2001:db8:abcd::1/48", "CIDR", "2001:db8:abcd::/48"),
    (" Data-Center.Century. ", "HOSTNAME", "data-center.century"),
])
def test_validation_and_normalization(value, kind, normalized):
    assert infer_value_type(value) == kind
    assert normalize_value(value) == (normalized, kind)


@pytest.mark.parametrize("value,kind,message", [
    ("", None, "required"), ("999.1.1.1", "IP", "Invalid IP"),
    ("10.0.0.0/99", "CIDR", "Invalid CIDR"),
    ("bad_host!", "HOSTNAME", "Invalid hostname"),
])
def test_invalid_values(value, kind, message):
    with pytest.raises(ValueError, match=message):
        normalize_value(value, kind)


def test_exact_ip_cidr_and_hostname_matching():
    _add("192.168.40.25")
    _add("63.51.20.0/24")
    _add("Data-Center.Century.")
    _add("9.9.9.0/24", EXTERNAL_ALLOWLIST)
    assert registry.classify_endpoint("192.168.40.25").is_century_owned
    assert registry.classify_endpoint("63.51.20.99").matched_type == "CIDR"
    assert not registry.classify_endpoint("63.51.21.1").is_century_owned
    assert registry.classify_endpoint("DATA-CENTER.CENTURY.").is_century_owned
    assert not registry.classify_endpoint("sub.data-center.century").is_protected
    assert registry.classify_endpoint("9.9.9.9").is_external_allowlisted


def test_century_ownership_wins_over_overlapping_external_allowlist():
    _add("192.168.20.0/24", CENTURY_OWNED)
    _add("192.168.20.221", EXTERNAL_ALLOWLIST)
    item = registry.classify_endpoint("192.168.20.221")
    assert item.is_century_owned
    assert not item.is_external_allowlisted


@pytest.mark.parametrize("value,expected", [
    ("110.38.160.195", "110.38.160.195"),
    ("110.38.160.195 (1)", "110.38.160.195"),
    ("110.38.160.195 (25)", "110.38.160.195"),
    ("data-center.century.abc", "data-center.century.abc"),
    ("data-center.century.abc (2)", "data-center.century.abc"),
])
def test_optional_trailing_event_count_is_removed(value, expected):
    _add("192.168.250.0/24")
    item = registry.classify_endpoint(value)
    assert item.input == value
    assert item.normalized_value == expected
    assert clean_parsed_endpoint(value) == expected


def test_parentheses_inside_endpoint_are_not_removed():
    assert clean_parsed_endpoint("data-(2)-center.century") == "data-(2)-center.century"
    assert clean_parsed_endpoint("data-center.century(2)") == "data-center.century(2)"


def test_origin_and_impacted_counts_use_cleaned_values_for_decision():
    _add("data-center.century.abc", CENTURY_OWNED)
    inbound = decide_endpoints("110.38.160.195 (25)", "data-center.century.abc (2)")
    assert inbound.origin.input == "110.38.160.195 (25)"
    assert inbound.impacted.input == "data-center.century.abc (2)"
    assert inbound.selected_candidate == "110.38.160.195"
    assert inbound.selected_side == "origin"


def test_disabled_endpoint_does_not_match_and_unknown_hostname_stays_unknown():
    _add("192.168.250.0/24")
    _add("mail.century", active=False)
    item = registry.classify_endpoint("mail.century")
    assert not item.is_protected
    assert item.ownership == "unknown"
    assert not item.is_external_public


def test_decision_table_and_external_allowlist_separation():
    _add("192.168.20.0/24")
    _add("9.9.9.9", EXTERNAL_ALLOWLIST)
    outbound = decide_endpoints("192.168.20.5", "8.8.8.8")
    inbound = decide_endpoints("8.8.8.8", "192.168.20.5")
    assert (outbound.selected_side, outbound.selected_candidate) == ("impacted", "8.8.8.8")
    assert (inbound.selected_side, inbound.selected_candidate) == ("origin", "8.8.8.8")
    assert decide_endpoints("192.168.20.5", "192.168.20.6").status == "century_to_century"
    assert decide_endpoints("8.8.8.8", "1.1.1.1").status == "ambiguous_external_pair"
    assert decide_endpoints("192.168.20.5", "9.9.9.9").status == "allowlisted"
    assert not registry.classify_endpoint("9.9.9.9").is_century_owned


@pytest.mark.parametrize("origin,impacted,status", [
    ("", "8.8.8.8", "incomplete_or_invalid_endpoint"),
    ("8.8.8.8", "", "incomplete_or_invalid_endpoint"),
    ("masked", "8.8.8.8", "incomplete_or_invalid_endpoint"),
    ("8.8.8.8", "8.8.8.8", "same_endpoint"),
    ("unknown.example", "8.8.8.8", "unknown_endpoint_review"),
])
def test_non_blocking_decisions(origin, impacted, status):
    _add("192.168.250.0/24")
    assert decide_endpoints(origin, impacted).status == status


def test_api_crud_filter_conflict_and_audit():
    request = _request()
    created = api_add_allowed_ip(request, EndpointBody(
        value="10.0.0.0/8", value_type="CIDR", category=CENTURY_OWNED,
        description="Private estate",
    ))["endpoint"]
    assert created["normalized_value"] == "10.0.0.0/8"
    with pytest.raises(HTTPException, match="already exists"):
        api_add_allowed_ip(request, EndpointBody(
            value="10.0.0.1/8", value_type="CIDR", category=CENTURY_OWNED
        ))
    with pytest.raises(HTTPException, match="another category"):
        api_add_allowed_ip(request, EndpointBody(
            value="10.0.0.0/8", value_type="CIDR", category=EXTERNAL_ALLOWLIST
        ))
    edited = api_edit_allowed_ip(request, created["id"], EndpointBody(
        value="10.0.0.0/8", value_type="CIDR", category=CENTURY_OWNED,
        description="Updated", is_active=True,
    ))["endpoint"]
    assert edited["description"] == "Updated"
    assert len(api_list_allowed_ips(request, search="Updated", category=CENTURY_OWNED,
                                    value_type="CIDR")["endpoints"]) == 1
    assert api_set_endpoint_active(request, created["id"], ActiveBody(is_active=False))["endpoint"]["is_active"] == 0
    assert api_set_endpoint_active(request, created["id"], ActiveBody(is_active=True))["endpoint"]["is_active"] == 1
    assert api_remove_allowed_ip(request, created["id"])["deleted"] == created["id"]
    actions = {row["action"] for row in database.list_endpoint_audit(created["id"])}
    assert {"ADDED", "EDITED", "DISABLED", "ENABLED", "DELETED"} <= actions


def test_import_export_reports_individual_failures():
    request = _request()
    content = "Value,Category,Description,Active status\n8.8.8.8,EXTERNAL_ALLOWLIST,DNS,true\ninvalid!,CENTURY_OWNED,Bad,true\n8.8.8.8,CENTURY_OWNED,Conflict,true\n"
    summary = api_import_endpoints(request, ImportBody(format="csv", content=content))
    assert summary["imported"] == 1
    assert summary["invalid"] == 1
    assert summary["conflicts"] == 1
    assert len(summary["errors"]) == 2
    csv_response = api_export_endpoints(request, "csv")
    json_response = api_export_endpoints(request, "json")
    assert b"normalized_value" in csv_response.body
    assert json.loads(json_response.body)[0]["value"] == "8.8.8.8"
    actions = {row["action"] for row in database.list_endpoint_audit()}
    assert {"IMPORTED", "EXPORTED"} <= actions


def test_final_firewall_guard_blocks_protected_before_client_use(monkeypatch):
    _add("8.8.8.8", EXTERNAL_ALLOWLIST)
    client = MagicMock()
    config = SimpleNamespace(firewall_rule_name="Block IP")
    assert block_ip("8.8.8.8", config, client=client) == "allowed"
    client.get_firewall_rule.assert_not_called()


def test_retry_for_protected_endpoint_stops_without_firewall_use():
    _add("8.8.4.4", EXTERNAL_ALLOWLIST)
    database.reserve_pending_block("8.8.4.4", "old timeout")
    outcome = retry_now("8.8.4.4", SimpleNamespace(firewall_rule_name="Block IP"))
    assert outcome.result == "allowed"
    assert database.get_pending_block("8.8.4.4") is None


def test_registry_database_failure_is_fail_closed(monkeypatch):
    monkeypatch.setattr(database, "list_protected_endpoints", MagicMock(side_effect=RuntimeError("db down")))
    with pytest.raises(RegistryUnavailable):
        registry.classify_endpoint("8.8.8.8")
    with pytest.raises(RuleUpdateError, match="registry is unavailable"):
        block_ip("8.8.8.8", SimpleNamespace(firewall_rule_name="Block IP"), client=MagicMock())


def test_empty_registry_is_fail_closed():
    with pytest.raises(RegistryUnavailable):
        registry.classify_endpoint("8.8.8.8")
    with pytest.raises(RuleUpdateError, match="registry is unavailable"):
        block_ip("8.8.8.8", SimpleNamespace(firewall_rule_name="Block IP"), client=MagicMock())


def test_one_time_migration_retains_sources_and_is_idempotent(tmp_path, monkeypatch):
    from core import legacy_endpoint_migration as migration
    env = tmp_path / ".env"
    env.write_text("CENTURY_IP_RANGES=63.51.20.0/24\nPROTECTED_INTERNAL_NETWORKS=192.168.40.0/24\n", encoding="utf-8")
    allowed = tmp_path / "allowed_ips.txt"
    allowed.write_text("9.9.9.0/24\ninvalid!\n", encoding="utf-8")
    monkeypatch.setattr(migration, "ROOT", tmp_path)
    monkeypatch.setattr(migration, "LEGACY_FILES", (allowed,))
    report = run_legacy_endpoint_migration()
    assert report["imported_century_owned"] == 2
    assert report["imported_external_allowlist"] == 1
    assert report["invalid"] == 1
    assert env.exists() and allowed.exists()
    env.write_text("CENTURY_IP_RANGES=8.8.8.0/24\n", encoding="utf-8")
    assert run_legacy_endpoint_migration()["already_applied"] == 1
    assert database.get_protected_endpoint_by_normalized("8.8.8.0/24") is None
