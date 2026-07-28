"""Translate raw Python logging records into human-readable SOC events.

Pure functions only -- no I/O. Used by the SQLite log handler and the live
activity feed so the dashboard never shows raw ``INFO``/``DEBUG`` noise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_MODULE_CATEGORY = {
    "__main__": "Application",
    "main": "Application",
    "core.email_client": "Email Service",
    "core.email_monitor": "Alert Processing",
    "core.email_connectivity_monitor": "Connectivity",
    "core.firewall_client": "Firewall Action",
    "core.firewall_monitor": "Connectivity",
    "core.rule_updater": "Firewall Action",
    "core.xml_handler": "Firewall Action",
    "core.manual_actions": "Firewall Action",
    "core.config": "Application",
    "web": "Application",
}

# Ordered (pattern, friendly-template) pairs. First match wins.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"IMAP connecting to"), "Connecting to IMAP server"),
    (re.compile(r"IMAP authenticated successfully"), "Connected to IMAP server"),
    (re.compile(r"IMAP authentication failed"), "IMAP authentication failed"),
    (re.compile(r"IMAP connection failed"), "IMAP connection failed"),
    (re.compile(r"IMAP: no unread messages"), "No new alert emails"),
    (re.compile(r"Email received:"), "Security alert email received"),
    (re.compile(r"ignoring -- sender"), "Email ignored -- untrusted sender"),
    (re.compile(r"ignoring -- classification"), "Email ignored -- classification did not match keywords"),
    (re.compile(r"alert keyword .* matched"), "Alert keyword matched -- processing"),
    (re.compile(r"Origin IP extracted"), "Origin IP extracted from alert"),
    (re.compile(r"could not extract Origin IP"), "Could not extract origin IP from alert"),
    (re.compile(r"is whitelisted"), "Origin IP is on the allow list -- ignored"),
    (re.compile(r"already (in|blocked)"), "Origin IP already blocked (duplicate)"),
    (re.compile(r"Retrying \d+ pending firewall block"), "Retrying previously failed firewall blocks"),
    (re.compile(r"Retry failed for"), "Retry failed -- IP still not blocked"),
    (re.compile(r"Retry succeeded for"), "Retry succeeded -- IP now blocked"),
    (re.compile(r"Firewall connectivity check succeeded"), "Firewall connectivity check passed"),
    (re.compile(r"Firewall connectivity check failed"), "Firewall connectivity check failed"),
    (re.compile(r"Firewall connectivity monitor started"), "Firewall connectivity monitor started"),
    (re.compile(r"Authenticating with SFOS"), "Connecting to firewall API"),
    (re.compile(r"SFOS auth OK"), "Firewall authentication succeeded"),
    (re.compile(r"IP host .* confirmed"), "Firewall host object created"),
    (re.compile(r"Rule .* updated and VERIFIED -- .* unblocked"), "Firewall rule updated -- IP unblocked"),
    (re.compile(r"Rule .* updated and VERIFIED"), "Firewall rule updated successfully"),
    (re.compile(r"Failed to block"), "Firewall update failed"),
    (re.compile(r"is not currently in rule"), "IP was not blocked -- nothing to unblock"),
    (re.compile(r"Could not delete host object"), "Host object left in place (may be used by another rule)"),
    (re.compile(r"Manual block of .* failed with a recoverable"), "Manual block failed -- queued for automatic retry"),
    (re.compile(r"Manual block of .* failed with a non-recoverable"), "Manual block failed"),
    (re.compile(r"SFOS write failure|SFOS API error|FirewallAPIError"), "Firewall API error"),
    (re.compile(r"SMTP notification delivered"), "Notification email sent"),
    (re.compile(r"Notification not sent|SMTP.*failed"), "Notification email failed"),
    (re.compile(r"SMTP connecting"), "Connecting to SMTP server"),
    (re.compile(r"Cycle complete"), "Polling cycle complete"),
    (re.compile(r"Email monitor started"), "Email monitoring service started"),
    (re.compile(r"Configuration loaded"), "Configuration loaded"),
]


@dataclass(frozen=True)
class TranslatedEvent:
    severity: str
    category: str
    message: str
    success: bool  # True = positive/informational, False = failure/error


def category_for_module(module_name: str) -> str:
    for prefix, category in _MODULE_CATEGORY.items():
        if module_name == prefix or module_name.startswith(prefix):
            return category
    return "Application"


def friendly_message(raw_message: str) -> str:
    for pattern, friendly in _PATTERNS:
        if pattern.search(raw_message):
            return friendly
    return raw_message


def translate(
    *,
    level_name: str,
    module_name: str,
    raw_message: str,
    category_name: str = "",
) -> TranslatedEvent:
    severity = level_name.upper()
    success = severity not in ("ERROR", "CRITICAL")
    return TranslatedEvent(
        severity=severity,
        category=category_name or category_for_module(module_name),
        message=friendly_message(raw_message),
        success=success,
    )
