"""Binary trusted-vs-untrusted blocking policy.

Covers the 5 decision rules, the 3 TRUSTED matching mechanisms (exact IP,
IP-in-CIDR, exact hostname), the "no public/private distinction" and
"never send a hostname/CIDR to Sophos" requirements, the final Sophos guard
(re-checked at block time, applied identically to live/startup/retry/manual
flows), and retry-target selection (Origin *or* Impacted, never assumed).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core import database
from core.endpoint_registry import (
    CENTURY_OWNED, EXTERNAL_ALLOWLIST, decide_endpoints, normalize_value, registry,
)
from core.retry_actions import retry_now
from core.rule_updater import RuleUpdateError, block_ip


def _add(value: str, category: str = CENTURY_OWNED, *, active: bool = True) -> int:
    normalized, kind = normalize_value(value)
    return database.add_protected_endpoint(value, normalized, kind, category, active=active)


def _mock_client(existing_ips: list[str] | None = None) -> MagicMock:
    networks_xml = "".join(f"<Network>{ip}</Network>" for ip in (existing_ips or []))
    response = ET.fromstring(
        f"<Response><FirewallRule><Name>Block IP</Name><NetworkPolicy>"
        f"<SourceNetworks>{networks_xml}</SourceNetworks></NetworkPolicy></FirewallRule></Response>"
    )
    client = MagicMock()
    client.last_response = ""
    client.get_firewall_rule.return_value = response
    client.set_firewall_rule.return_value = ET.fromstring("<Response/>")
    client.create_ip_host.return_value = None
    return client


_CONFIG = SimpleNamespace(firewall_rule_name="Block IP")


# ──────────────────────────────────────────────────────────────────────────────
# TRUSTED matching mechanisms
# ──────────────────────────────────────────────────────────────────────────────

class TestTrustedMatching:
    def test_exact_ip_match_is_trusted(self):
        _add("203.0.113.9")
        assert registry.classify_endpoint("203.0.113.9").is_trusted

    def test_ip_inside_trusted_cidr_is_trusted(self):
        _add("198.51.100.0/24")
        item = registry.classify_endpoint("198.51.100.77")
        assert item.is_trusted
        assert item.matched_type == "CIDR"

    def test_ip_outside_trusted_cidr_is_untrusted(self):
        _add("198.51.100.0/24")
        assert not registry.classify_endpoint("198.51.101.1").is_trusted

    def test_exact_normalized_hostname_match_is_trusted(self):
        _add("App-Server.Century.")
        assert registry.classify_endpoint("app-server.century").is_trusted

    def test_subdomain_of_trusted_hostname_is_not_trusted(self):
        """No wildcard/subdomain matching -- only an exact hostname match trusts."""
        _add("app-server.century")
        assert not registry.classify_endpoint("east.app-server.century").is_trusted

    def test_unregistered_ip_is_untrusted_regardless_of_public_or_private(self):
        _add("198.51.100.0/24")
        assert not registry.classify_endpoint("8.8.8.8").is_trusted       # public
        assert not registry.classify_endpoint("192.168.5.5").is_trusted   # private


# ──────────────────────────────────────────────────────────────────────────────
# The 4 main decision combinations
# ──────────────────────────────────────────────────────────────────────────────

class TestFourMainCombinations:
    def test_case1_trusted_origin_untrusted_impacted_blocks_impacted(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("192.168.20.5", "203.0.113.50")
        assert decision.status == "approved_for_blocking"
        assert decision.selected_side == "impacted"
        assert decision.selected_candidate == "203.0.113.50"

    def test_case2_untrusted_origin_trusted_impacted_blocks_origin(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("203.0.113.50", "192.168.20.5")
        assert decision.status == "approved_for_blocking"
        assert decision.selected_side == "origin"
        assert decision.selected_candidate == "203.0.113.50"

    def test_case3_both_trusted_blocks_neither(self):
        _add("192.168.20.0/24")
        _add("192.168.30.0/24")
        decision = decide_endpoints("192.168.20.5", "192.168.30.5")
        assert decision.status == "both_trusted"
        assert decision.selected_candidate is None
        assert decision.selected_side is None

    def test_case4_both_untrusted_valid_ips_blocks_both(self):
        """Under the per-side independent trust policy, two untrusted valid
        IPs are both approved for blocking (see the full 16-row truth table
        in TestFullTruthTable)."""
        _add("192.168.250.0/24")  # unrelated entry so the registry isn't empty
        decision = decide_endpoints("203.0.113.50", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert set(decision.candidates) == {("origin", "203.0.113.50"), ("impacted", "8.8.8.8")}


# ──────────────────────────────────────────────────────────────────────────────
# Rule 5: review-required edge cases (never block)
# ──────────────────────────────────────────────────────────────────────────────

class TestReviewRequiredEdgeCases:
    def test_missing_endpoint_paired_with_trusted_is_reviewed(self):
        _add("192.168.20.0/24")
        assert decide_endpoints("", "192.168.20.5").status == "incomplete_or_invalid_endpoint"

    def test_masked_endpoint_paired_with_trusted_is_reviewed(self):
        _add("192.168.20.0/24")
        assert decide_endpoints("masked", "192.168.20.5").status == "incomplete_or_invalid_endpoint"

    def test_malformed_endpoint_paired_with_trusted_is_reviewed(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("not an ip and not a hostname !!", "192.168.20.5")
        assert decision.status == "incomplete_or_invalid_endpoint"

    def test_invalid_endpoint_paired_with_untrusted_ip_still_blocks_the_valid_ip(self):
        """A missing/masked/malformed value on one side no longer blanks out
        the whole decision -- if the other side is an untrusted valid IP,
        it is still blocked (see the full truth table)."""
        _add("192.168.250.0/24")  # unrelated entry so the registry isn't empty
        decision = decide_endpoints("", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("impacted", "8.8.8.8"),)

    def test_identical_untrusted_ips_are_deduplicated_into_one_block_candidate(self):
        """Both sides are the same untrusted valid IP -- approved for
        blocking, but attempted only once, not twice."""
        _add("192.168.250.0/24")
        decision = decide_endpoints("8.8.8.8", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("origin", "8.8.8.8"),)

    def test_cidr_endpoint_is_never_a_block_target_but_does_not_suppress_the_other_side(self):
        """A CIDR value is grouped with hostnames for policy purposes --
        never trusted, never a Sophos target -- but it does not prevent
        blocking a genuinely untrusted valid IP on the other side."""
        _add("192.168.20.0/24")
        decision = decide_endpoints("192.168.20.0/24", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("impacted", "8.8.8.8"),)
        assert decision.review_sides == ("origin",)

    def test_hostname_only_untrusted_target_is_reviewed_not_blocked(self):
        """Trusted Origin + untrusted Impacted -- but Impacted is a hostname,
        not a valid IP, so it can never be sent to Sophos as a block target."""
        _add("192.168.20.0/24")
        decision = decide_endpoints("192.168.20.5", "unregistered-host.example")
        assert decision.status == "untrusted_target_not_ip"
        assert decision.selected_candidate is None


# ──────────────────────────────────────────────────────────────────────────────
# The full 16-row Origin x Impacted truth table (4 categories per side:
# trusted / untrusted valid IP / untrusted hostname-or-CIDR / invalid).
# One test per row -- this table is the single source of truth for the
# blocking policy, so every combination is exercised directly.
# ──────────────────────────────────────────────────────────────────────────────

class TestFullTruthTable:
    def test_row1_trusted_trusted_blocks_neither(self):
        _add("192.168.20.0/24")
        _add("192.168.30.0/24")
        decision = decide_endpoints("192.168.20.5", "192.168.30.5")
        assert decision.status == "both_trusted"
        assert decision.candidates == ()
        assert decision.review_sides == ()

    def test_row2_trusted_untrusted_ip_blocks_impacted(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("192.168.20.5", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("impacted", "8.8.8.8"),)
        assert decision.review_sides == ()

    def test_row3_untrusted_ip_trusted_blocks_origin(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("8.8.8.8", "192.168.20.5")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("origin", "8.8.8.8"),)
        assert decision.review_sides == ()

    def test_row4_untrusted_ip_untrusted_ip_blocks_both(self):
        _add("192.168.250.0/24")  # unrelated entry so the registry isn't empty
        decision = decide_endpoints("8.8.8.8", "1.1.1.1")
        assert decision.status == "approved_for_blocking"
        assert set(decision.candidates) == {("origin", "8.8.8.8"), ("impacted", "1.1.1.1")}
        assert decision.review_sides == ()

    def test_row5_trusted_untrusted_hostname_blocks_neither(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("192.168.20.5", "unregistered-host.example")
        assert decision.status == "untrusted_target_not_ip"
        assert decision.candidates == ()
        assert decision.review_sides == ("impacted",)

    def test_row6_untrusted_hostname_trusted_blocks_neither(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("unregistered-host.example", "192.168.20.5")
        assert decision.status == "untrusted_target_not_ip"
        assert decision.candidates == ()
        assert decision.review_sides == ("origin",)

    def test_row7_untrusted_hostname_untrusted_ip_blocks_impacted(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("unregistered-host.example", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("impacted", "8.8.8.8"),)
        assert decision.review_sides == ("origin",)

    def test_row8_untrusted_ip_untrusted_hostname_blocks_origin(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("8.8.8.8", "unregistered-host.example")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("origin", "8.8.8.8"),)
        assert decision.review_sides == ("impacted",)

    def test_row9_untrusted_hostname_untrusted_hostname_blocks_neither(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("unregistered-a.example", "unregistered-b.example")
        assert decision.status == "both_untrusted"
        assert decision.candidates == ()
        assert set(decision.review_sides) == {"origin", "impacted"}

    def test_row10_invalid_untrusted_ip_blocks_impacted(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("", "8.8.8.8")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("impacted", "8.8.8.8"),)

    def test_row11_untrusted_ip_invalid_blocks_origin(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("8.8.8.8", "")
        assert decision.status == "approved_for_blocking"
        assert decision.candidates == (("origin", "8.8.8.8"),)

    def test_row12_invalid_trusted_blocks_neither(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("masked", "192.168.20.5")
        assert decision.status == "incomplete_or_invalid_endpoint"
        assert decision.candidates == ()

    def test_row13_trusted_invalid_blocks_neither(self):
        _add("192.168.20.0/24")
        decision = decide_endpoints("192.168.20.5", "masked")
        assert decision.status == "incomplete_or_invalid_endpoint"
        assert decision.candidates == ()

    def test_row14_invalid_untrusted_hostname_blocks_neither(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("", "unregistered-host.example")
        assert decision.status == "incomplete_or_invalid_endpoint"
        assert decision.candidates == ()

    def test_row15_untrusted_hostname_invalid_blocks_neither(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("unregistered-host.example", "")
        assert decision.status == "incomplete_or_invalid_endpoint"
        assert decision.candidates == ()

    def test_row16_invalid_invalid_blocks_neither(self):
        _add("192.168.250.0/24")
        decision = decide_endpoints("", "masked")
        assert decision.status == "incomplete_or_invalid_endpoint"
        assert decision.candidates == ()


# ──────────────────────────────────────────────────────────────────────────────
# Never send a hostname or CIDR to Sophos; only a valid IP is a block target
# ──────────────────────────────────────────────────────────────────────────────

class TestOnlyValidIpIsBlockTarget:
    def test_trusted_hostname_can_still_authorize_blocking_the_other_side(self):
        """A TRUSTED hostname is a legitimate trust anchor even though it can
        never itself be the block target -- the *other* (untrusted, valid IP)
        side is selected instead."""
        _add("data-center.century")
        decision = decide_endpoints("data-center.century", "203.0.113.9")
        assert decision.status == "approved_for_blocking"
        assert decision.selected_candidate == "203.0.113.9"
        assert decision.selected_side == "impacted"

    def test_selected_candidate_is_never_a_hostname_or_cidr(self):
        _add("192.168.20.0/24")
        for impacted in ("some-unregistered-host.example", "10.0.0.0/24"):
            decision = decide_endpoints("192.168.20.5", impacted)
            assert decision.selected_candidate is None


# ──────────────────────────────────────────────────────────────────────────────
# Private untrusted IPs are just as blockable as public ones
# ──────────────────────────────────────────────────────────────────────────────

class TestPrivateUntrustedIpBlocking:
    def test_decision_selects_private_untrusted_impacted_ip(self):
        _add("203.0.113.0/24")  # Origin's trusted network
        decision = decide_endpoints("203.0.113.5", "10.50.1.7")
        assert decision.status == "approved_for_blocking"
        assert decision.selected_candidate == "10.50.1.7"

    def test_decision_selects_private_untrusted_origin_ip(self):
        _add("203.0.113.0/24")  # Impacted's trusted network
        decision = decide_endpoints("10.50.1.7", "203.0.113.5")
        assert decision.status == "approved_for_blocking"
        assert decision.selected_candidate == "10.50.1.7"

    def test_final_guard_allows_blocking_an_untrusted_private_ip(self):
        _add("192.168.250.0/24")  # unrelated entry so the registry isn't empty
        client = _mock_client()
        result = block_ip("10.50.1.7", _CONFIG, client=client)
        assert result == "blocked"
        client.create_ip_host.assert_called_once_with("blocked-10-50-1-7", "10.50.1.7")

    def test_trusted_private_ip_is_still_protected(self):
        """Private + registered => trusted => never blocked. Public/private
        is irrelevant; only registry membership matters."""
        _add("10.50.1.7")
        client = _mock_client()
        assert block_ip("10.50.1.7", _CONFIG, client=client) == "allowed"
        client.get_firewall_rule.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# Final Sophos guard: re-checked at block time, applied to every flow
# ──────────────────────────────────────────────────────────────────────────────

class TestFinalGuardProtection:
    def test_guard_blocks_ip_that_became_trusted_after_the_decision_was_made(self):
        """Simulates a race: the candidate was UNTRUSTED when decide_endpoints
        ran, but has since been added to Protected Endpoints (e.g. an admin
        marked it trusted) by the time the firewall call actually happens.
        The guard must refuse to block it."""
        _add("192.168.250.0/24")  # keep the registry non-empty
        candidate = "203.0.113.77"
        assert not registry.classify_endpoint(candidate).is_trusted
        _add(candidate, EXTERNAL_ALLOWLIST)  # becomes trusted before block_ip runs
        client = _mock_client()
        assert block_ip(candidate, _CONFIG, client=client) == "allowed"
        client.get_firewall_rule.assert_not_called()

    def test_guard_rejects_hostname_or_cidr_even_if_somehow_selected(self):
        _add("192.168.250.0/24")
        client = _mock_client()
        with pytest.raises(RuleUpdateError, match="valid IP"):
            block_ip("some-host.example", _CONFIG, client=client)
        with pytest.raises(RuleUpdateError, match="valid IP"):
            block_ip("10.0.0.0/24", _CONFIG, client=client)

    @pytest.mark.parametrize("source", ["automatic", "retry_worker", "startup_scan"])
    def test_guard_applies_identically_regardless_of_calling_source(self, source):
        _add("8.8.4.4", EXTERNAL_ALLOWLIST)
        client = _mock_client()
        assert block_ip("8.8.4.4", _CONFIG, client=client, source=source) == "allowed"
        client.get_firewall_rule.assert_not_called()

    def test_guard_applies_on_retry_now(self):
        """retry_now() (the "Retry Now" dashboard action) funnels through the
        same block_ip() guard as automatic retries."""
        _add("192.168.250.0/24")
        candidate = "203.0.113.88"
        database.reserve_pending_block(candidate, "timeout")
        _add(candidate, EXTERNAL_ALLOWLIST)  # trusted before the retry fires
        outcome = retry_now(candidate, _CONFIG)
        assert outcome.result == "allowed"
        assert database.get_pending_block(candidate) is None


# ──────────────────────────────────────────────────────────────────────────────
# Retry-target selection: store the actual candidate, never assume Origin
# ──────────────────────────────────────────────────────────────────────────────

class TestRetryTargetSelection:
    def _failed_alert(self, *, origin_ip: str, selected_candidate: str) -> int:
        return database.record_alert(
            subject="SOC alarm", sender="soc@example.com",
            origin_ip=origin_ip, impacted_ip=selected_candidate,
            selected_candidate=selected_candidate,
            action_taken="failed", processing_status="processing_failed",
            reason="Firewall unavailable",
        )

    def test_self_heal_reserves_the_selected_candidate_not_origin(self):
        """decide_endpoints chose to block Impacted, not Origin -- the retry
        self-heal must reserve the Impacted IP, never the Origin IP."""
        origin_ip, impacted_ip = "192.168.20.5", "203.0.113.200"
        self._failed_alert(origin_ip=origin_ip, selected_candidate=impacted_ip)

        recovered = database.sync_pending_blocks_from_alerts()

        assert recovered == 1
        assert database.get_pending_block(impacted_ip) is not None
        assert database.get_pending_block(origin_ip) is None

    def test_resolve_pending_block_updates_the_alert_by_candidate_not_origin(self):
        origin_ip, impacted_ip = "192.168.20.5", "203.0.113.201"
        alert_id = self._failed_alert(origin_ip=origin_ip, selected_candidate=impacted_ip)
        database.reserve_pending_block(impacted_ip, "timeout", alert_id=alert_id)

        database.resolve_pending_block(impacted_ip, "blocked")

        alert = database.get_alert(alert_id)
        assert alert["processing_status"] == "blocked_successfully"
        assert database.get_pending_block(impacted_ip) is None

    def test_legacy_alerts_without_selected_candidate_fall_back_to_origin(self):
        """Rows recorded before ``selected_candidate`` existed must still be
        recoverable using ``origin_ip``."""
        alert_id = database.record_alert(
            subject="Legacy alarm", sender="soc@example.com",
            origin_ip="203.0.113.202", action_taken="failed",
            processing_status="processing_failed", reason="Firewall unavailable",
        )
        recovered = database.sync_pending_blocks_from_alerts()
        assert recovered == 1
        assert database.get_pending_block("203.0.113.202") is not None
        database.resolve_pending_block("203.0.113.202", "blocked")
        assert database.get_alert(alert_id)["processing_status"] == "blocked_successfully"

    def test_retry_worker_processes_the_stored_candidate_ip(self, monkeypatch):
        """The live retry worker (EmailMonitor._retry_pending_blocks) reads
        only ``pending_blocks.ip`` -- confirms whatever was reserved (the
        actual candidate) is exactly what gets retried."""
        import core.email_monitor as email_monitor_module
        from core.email_monitor import EmailMonitor

        impacted_ip = "203.0.113.203"
        database.reserve_pending_block(impacted_ip, "timeout")
        config = SimpleNamespace(firewall_rule_name="Block IP", poll_interval=60)
        monitor = EmailMonitor.__new__(EmailMonitor)
        monitor._config = config

        called_with = {}

        def _fake_block_ip(ip, cfg, alert_id=None):
            called_with["ip"] = ip
            return "duplicate"  # avoids the notification path entirely

        monkeypatch.setattr(email_monitor_module, "block_ip", _fake_block_ip)
        monitor._retry_pending_blocks()

        assert called_with["ip"] == impacted_ip
