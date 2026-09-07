"""Unit tests for blocking an IP across multiple firewall rules.

Covers: FIREWALL_RULE_NAMES parsing, the success / partial / failed rollup,
per-rule history rows, host-object reuse across rules, and the guarantee
that one failing rule never prevents the others from being updated.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest

from core import database
from core.config import parse_firewall_rule_names
from core.firewall_client import FirewallAPIError
from core.rule_updater import PartialBlockError, RuleUpdateError, block_ip
from core.xml_handler import RuleNotFoundError

_ENV_BASE: dict[str, str] = {
    "FIREWALL_HOST": "192.168.1.1",
    "FIREWALL_PORT": "4444",
    "FIREWALL_USERNAME": "admin",
    "FIREWALL_PASSWORD": "pass",
    "IMAP_HOST": "outlook.office365.com",
    "IMAP_PORT": "993",
    "EMAIL_USERNAME": "user@example.com",
    "EMAIL_PASSWORD": "emailpass",
    "SMTP_HOST": "smtp.office365.com",
    "SMTP_PORT": "587",
    "NOTIFICATION_EMAIL": "security-alerts@example.com",
    "TRUSTED_SENDERS": "alerts@company.com",
    "ALERT_KEYWORDS": "attack",
}

RULE_A = "Block IP"
RULE_B = "Block IP WAN"
RULE_C = "Block IP DMZ"


def _make_config(monkeypatch: pytest.MonkeyPatch, rule_names: str):
    from core.config import load_config

    for key, value in _ENV_BASE.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("FIREWALL_RULE_NAMES", rule_names)
    monkeypatch.delenv("FIREWALL_RULE_NAME", raising=False)
    return load_config()


def _make_legacy_config(monkeypatch: pytest.MonkeyPatch, tmp_path, rule_value: str):
    """Load config from a scratch .env that has ONLY the legacy singular key.

    load_config() reads the project's real .env, which now carries
    FIREWALL_RULE_NAMES -- pointing it at a temporary file is what actually
    isolates the legacy-fallback path under test.
    """
    import core.config as config_module
    from core.config import load_config

    env_path = tmp_path / "legacy.env"
    env_path.write_text(f"FIREWALL_RULE_NAME={rule_value}\n", encoding="utf-8")
    monkeypatch.setattr(config_module, "_ENV_PATH", env_path)
    for key, value in _ENV_BASE.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FIREWALL_RULE_NAMES", raising=False)
    monkeypatch.delenv("FIREWALL_RULE_NAME", raising=False)
    return load_config()


def _rule_response(rule_name: str, existing: list[str]) -> ET.Element:
    networks = "".join(f"<Network>{n}</Network>" for n in existing)
    return ET.fromstring(
        "<Response>"
        "  <FirewallRule>"
        f"    <Name>{rule_name}</Name>"
        "    <Status>Enable</Status>"
        "    <NetworkPolicy>"
        "      <Action>Reject</Action>"
        f"      <SourceNetworks>{networks}</SourceNetworks>"
        "    </NetworkPolicy>"
        "  </FirewallRule>"
        "</Response>"
    )


class _FakeFirewall:
    """In-memory SFOS stand-in that tracks per-rule source networks.

    Mirrors the real fetch/upload/verify cycle closely enough to exercise
    the multi-rule loop: an upload is only visible to the following
    verification fetch if the rule accepted it, and named rules can be made
    to fail in specific ways.
    """

    def __init__(
        self,
        rules: dict[str, list[str]],
        *,
        get_errors: dict[str, Exception] | None = None,
        set_errors: dict[str, Exception] | None = None,
        silently_discard: set[str] | None = None,
    ) -> None:
        self.rules = {name: list(nets) for name, nets in rules.items()}
        self.get_errors = get_errors or {}
        self.set_errors = set_errors or {}
        self.silently_discard = silently_discard or set()
        self.last_response = ""
        self.created_hosts: list[tuple[str, str]] = []
        self.host_exists_calls: list[str] = []
        self.uploaded: list[str] = []
        self._hosts: set[str] = set()

    # -- host object API ---------------------------------------------------
    def ip_host_exists(self, name: str, ip: str = "") -> bool:
        self.host_exists_calls.append(name)
        return name in self._hosts

    def create_ip_host(self, name: str, ip: str) -> None:
        self.created_hosts.append((name, ip))
        self._hosts.add(name)

    # -- rule API ----------------------------------------------------------
    def get_firewall_rule(self, rule_name: str) -> ET.Element:
        if rule_name in self.get_errors:
            raise self.get_errors[rule_name]
        if rule_name not in self.rules:
            raise RuleNotFoundError(
                f"Firewall rule {rule_name!r} does not exist on the firewall."
            )
        return _rule_response(rule_name, self.rules[rule_name])

    def set_firewall_rule(self, rule_element: ET.Element, rule_name: str) -> ET.Element:
        if rule_name in self.set_errors:
            raise self.set_errors[rule_name]
        self.uploaded.append(rule_name)
        if rule_name not in self.silently_discard:
            self.rules[rule_name] = [
                (n.text or "").strip()
                for n in rule_element.findall(".//SourceNetworks/Network")
            ]
        return ET.fromstring("<Response/>")

    def authenticate(self) -> None:
        pass

    def logout(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _seed_registry():
    """Seed the protected-endpoint registry.

    block_ip re-checks the registry at call time and refuses to block when
    it is empty (RegistryUnavailable), so every test needs at least one
    entry present. The scratch database itself comes from the shared
    isolated_registry fixture in conftest.py.
    """
    if database.get_protected_endpoint_by_normalized("192.168.250.0/24") is None:
        database.add_protected_endpoint(
            "192.168.250.0/24", "192.168.250.0/24", "CIDR", "CENTURY_OWNED"
        )
    yield


def _actions_for(ip: str) -> list[dict]:
    return database.list_firewall_actions_for_ip(ip)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

class TestParseFirewallRuleNames:
    def test_single_name_yields_one_entry(self) -> None:
        assert parse_firewall_rule_names("Block IP") == ("Block IP",)

    def test_comma_separated_names_are_split_and_trimmed(self) -> None:
        assert parse_firewall_rule_names(
            " Block IP , Block IP WAN ,Block IP DMZ "
        ) == ("Block IP", "Block IP WAN", "Block IP DMZ")

    def test_order_is_preserved(self) -> None:
        assert parse_firewall_rule_names("Zulu, Alpha, Mike") == ("Zulu", "Alpha", "Mike")

    def test_duplicates_are_removed_keeping_first_position(self) -> None:
        assert parse_firewall_rule_names("A, B, A, C, B") == ("A", "B", "C")

    def test_internal_spaces_and_case_are_preserved_exactly(self) -> None:
        # SFOS rule names are case-sensitive and may contain spaces.
        assert parse_firewall_rule_names("Block IP WAN") == ("Block IP WAN",)

    def test_blank_entries_are_ignored(self) -> None:
        assert parse_firewall_rule_names("A,,  ,B") == ("A", "B")

    def test_empty_raises_when_required(self) -> None:
        with pytest.raises(EnvironmentError, match="FIREWALL_RULE_NAMES"):
            parse_firewall_rule_names("   ")

    def test_empty_returns_empty_tuple_when_not_required(self) -> None:
        assert parse_firewall_rule_names("  ", required=False) == ()

    def test_error_message_names_the_supplied_key(self) -> None:
        with pytest.raises(EnvironmentError, match="FIREWALL_RULE_NAME"):
            parse_firewall_rule_names("", key="FIREWALL_RULE_NAME")


class TestConfigRuleNames:
    def test_multiple_rules_load_into_config(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}, {RULE_C}")
        assert config.firewall_rule_names == (RULE_A, RULE_B, RULE_C)

    def test_legacy_singular_key_still_accepted(self, monkeypatch, tmp_path) -> None:
        """An existing .env carrying only FIREWALL_RULE_NAME keeps working."""
        config = _make_legacy_config(monkeypatch, tmp_path, "Block IP")
        assert config.firewall_rule_names == ("Block IP",)

    def test_legacy_singular_key_accepts_a_comma_separated_list(
        self, monkeypatch, tmp_path
    ) -> None:
        config = _make_legacy_config(monkeypatch, tmp_path, "Block IP, Block IP WAN")
        assert config.firewall_rule_names == ("Block IP", "Block IP WAN")

    def test_plural_key_wins_over_legacy(self, monkeypatch) -> None:
        from core.config import load_config

        for key, value in _ENV_BASE.items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("FIREWALL_RULE_NAMES", "New Rule")
        monkeypatch.setenv("FIREWALL_RULE_NAME", "Old Rule")
        assert load_config().firewall_rule_names == ("New Rule",)

    def test_firewall_rule_name_property_returns_first(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        assert config.firewall_rule_name == RULE_A


# --------------------------------------------------------------------------
# Multi-rule blocking
# --------------------------------------------------------------------------

class TestBlockAcrossMultipleRules:
    def test_ip_is_added_to_every_configured_rule(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}, {RULE_C}")
        fw = _FakeFirewall({RULE_A: [], RULE_B: [], RULE_C: []})

        assert block_ip("8.8.8.8", config, client=fw) == "blocked"

        for rule in (RULE_A, RULE_B, RULE_C):
            assert "blocked-8-8-8-8" in fw.rules[rule], rule
        assert sorted(fw.uploaded) == sorted([RULE_A, RULE_B, RULE_C])

    def test_host_object_is_created_only_once_for_all_rules(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}, {RULE_C}")
        fw = _FakeFirewall({RULE_A: [], RULE_B: [], RULE_C: []})

        block_ip("8.8.8.8", config, client=fw)

        assert fw.created_hosts == [("blocked-8-8-8-8", "8.8.8.8")]

    def test_rules_are_processed_in_configured_order(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_C}, {RULE_A}, {RULE_B}")
        fw = _FakeFirewall({RULE_A: [], RULE_B: [], RULE_C: []})

        block_ip("8.8.8.8", config, client=fw)

        assert fw.uploaded == [RULE_C, RULE_A, RULE_B]

    def test_one_history_row_written_per_rule(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall({RULE_A: [], RULE_B: []})

        block_ip("8.8.8.8", config, client=fw)

        rows = _actions_for("8.8.8.8")
        assert {r["rule_name"] for r in rows} == {RULE_A, RULE_B}
        assert all(r["result"] == "blocked" for r in rows)

    def test_all_rules_already_containing_ip_returns_duplicate(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: ["blocked-8-8-8-8"], RULE_B: ["blocked-8-8-8-8"]}
        )

        assert block_ip("8.8.8.8", config, client=fw) == "duplicate"
        assert fw.uploaded == []
        assert fw.created_hosts == []

    def test_partially_present_ip_only_uploads_the_missing_rule(
        self, monkeypatch
    ) -> None:
        """The property that makes retrying a partial block safe."""
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall({RULE_A: ["blocked-8-8-8-8"], RULE_B: []})

        assert block_ip("8.8.8.8", config, client=fw) == "blocked"
        assert fw.uploaded == [RULE_B]
        assert "blocked-8-8-8-8" in fw.rules[RULE_B]

    def test_single_rule_config_behaves_exactly_as_before(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, RULE_A)
        fw = _FakeFirewall({RULE_A: []})

        assert block_ip("8.8.8.8", config, client=fw) == "blocked"
        assert fw.uploaded == [RULE_A]


# --------------------------------------------------------------------------
# Partial failure
# --------------------------------------------------------------------------

class TestPartialBlock:
    def test_one_failing_rule_raises_partial_block_error(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []},
            set_errors={RULE_B: FirewallAPIError("upload rejected", code="502")},
        )

        with pytest.raises(PartialBlockError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        error = exc_info.value
        assert error.succeeded == [RULE_A]
        assert error.failed_rule_names == [RULE_B]

    def test_partial_block_is_a_rule_update_error(self, monkeypatch) -> None:
        """Callers catching RuleUpdateError must treat partial as a failure."""
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []},
            set_errors={RULE_B: FirewallAPIError("nope", code="502")},
        )

        with pytest.raises(RuleUpdateError):
            block_ip("8.8.8.8", config, client=fw)

    def test_failure_on_first_rule_does_not_stop_later_rules(
        self, monkeypatch
    ) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}, {RULE_C}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: [], RULE_C: []},
            set_errors={RULE_A: FirewallAPIError("nope", code="502")},
        )

        with pytest.raises(PartialBlockError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        assert exc_info.value.succeeded == [RULE_B, RULE_C]
        assert "blocked-8-8-8-8" in fw.rules[RULE_B]
        assert "blocked-8-8-8-8" in fw.rules[RULE_C]

    def test_nonexistent_rule_is_named_in_the_error(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, Typo Rule")
        fw = _FakeFirewall({RULE_A: []})  # "Typo Rule" absent entirely

        with pytest.raises(PartialBlockError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        error = exc_info.value
        assert error.failed_rule_names == ["Typo Rule"]
        assert "Typo Rule" in str(error)
        assert "does not exist" in str(error)

    def test_silently_discarded_upload_counts_as_a_failure(self, monkeypatch) -> None:
        """SFOS can return success while dropping the change; verify catches it."""
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []}, silently_discard={RULE_B}
        )

        with pytest.raises(PartialBlockError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        assert exc_info.value.failed_rule_names == [RULE_B]

    def test_partial_records_both_outcomes_in_history(self, monkeypatch) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []},
            set_errors={RULE_B: FirewallAPIError("nope", code="502")},
        )

        with pytest.raises(PartialBlockError):
            block_ip("8.8.8.8", config, client=fw)

        rows = {r["rule_name"]: r for r in _actions_for("8.8.8.8")}
        assert rows[RULE_A]["result"] == "blocked"
        assert rows[RULE_A]["status"] == "success"
        assert rows[RULE_B]["result"] == "failed"
        assert rows[RULE_B]["status"] == "failure"

    def test_partial_message_names_succeeded_and_failed_rules(
        self, monkeypatch
    ) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []},
            set_errors={RULE_B: FirewallAPIError("nope", code="502")},
        )

        with pytest.raises(PartialBlockError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        message = str(exc_info.value)
        assert "1 of 2" in message
        assert RULE_A in message
        assert RULE_B in message


# --------------------------------------------------------------------------
# Total failure
# --------------------------------------------------------------------------

class TestTotalFailure:
    def test_all_rules_failing_raises_plain_rule_update_error(
        self, monkeypatch
    ) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []},
            set_errors={
                RULE_A: FirewallAPIError("nope", code="502"),
                RULE_B: FirewallAPIError("nope", code="502"),
            },
        )

        with pytest.raises(RuleUpdateError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        assert not isinstance(exc_info.value, PartialBlockError)

    def test_all_rules_failing_records_a_failure_row_per_rule(
        self, monkeypatch
    ) -> None:
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall(
            {RULE_A: [], RULE_B: []},
            set_errors={
                RULE_A: FirewallAPIError("nope", code="502"),
                RULE_B: FirewallAPIError("nope", code="502"),
            },
        )

        with pytest.raises(RuleUpdateError):
            block_ip("8.8.8.8", config, client=fw)

        rows = _actions_for("8.8.8.8")
        assert len(rows) == 2
        assert all(r["result"] == "failed" for r in rows)

    def test_host_creation_failure_is_a_total_failure(self, monkeypatch) -> None:
        """No rule was reachable, so this must not be reported as partial."""
        config = _make_config(monkeypatch, f"{RULE_A}, {RULE_B}")
        fw = _FakeFirewall({RULE_A: [], RULE_B: []})
        fw.create_ip_host = MagicMock(
            side_effect=FirewallAPIError("host creation failed", code="500")
        )

        with pytest.raises(RuleUpdateError) as exc_info:
            block_ip("8.8.8.8", config, client=fw)

        assert not isinstance(exc_info.value, PartialBlockError)
        assert fw.uploaded == []
