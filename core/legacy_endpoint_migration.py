"""One-time import from legacy endpoint configuration; sources remain backups."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from dotenv import dotenv_values

from . import database
from .endpoint_registry import (
    CENTURY_OWNED, EXTERNAL_ALLOWLIST, infer_value_type, normalize_value,
)

ROOT = Path(__file__).resolve().parent.parent
LEGACY_FILES = (
    ROOT / "config" / "allowed_ips.txt", ROOT / "allowed_ips.txt",
    ROOT / "allowed.txt", ROOT / "config" / "allowedendpoints.txt",
    ROOT / "allowedendpoints.txt",
)
MIGRATION_NAME = "protected_endpoint_registry_v2"


def _split(value: Any) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _read_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def run_legacy_endpoint_migration() -> dict[str, Any]:
    if database.migration_applied(MIGRATION_NAME):
        return {"already_applied": 1, "imported_century_owned": 0,
                "imported_external_allowlist": 0, "duplicates": 0,
                "invalid": 0, "conflicts": 0, "existing_preserved": 0, "sources": {}}
    env = dotenv_values(ROOT / ".env")
    candidates: list[tuple[str, str, str]] = []
    for key in ("CENTURY_IP_RANGES", "PROTECTED_INTERNAL_NETWORKS"):
        candidates.extend((v, CENTURY_OWNED, key) for v in _split(env.get(key)))
    for path in LEGACY_FILES:
        candidates.extend((v, EXTERNAL_ALLOWLIST, str(path)) for v in _read_file(path))
    report: dict[str, Any] = {
        "already_applied": 0, "imported_century_owned": 0,
        "imported_external_allowlist": 0, "duplicates": 0, "invalid": 0,
        "conflicts": 0, "existing_preserved": 0, "sources": {},
    }
    seen: set[tuple[str, str]] = set()
    for value, category, source in candidates:
        try:
            kind = infer_value_type(value)
            normalized, kind = normalize_value(value, kind)
        except ValueError:
            report["invalid"] += 1
            continue
        key = (normalized, category)
        if key in seen:
            report["duplicates"] += 1
            continue
        seen.add(key)
        existing = database.get_protected_endpoint_by_normalized(normalized)
        if existing:
            report["existing_preserved"] += 1
            report["conflicts" if existing["category"] != category else "duplicates"] += 1
            continue
        entry_id = database.add_protected_endpoint(
            value, normalized, kind, category, f"Migrated from {source}", audit_action="MIGRATED"
        )
        if entry_id:
            counter = "imported_century_owned" if category == CENTURY_OWNED else "imported_external_allowlist"
            report[counter] += 1
            report["sources"][str(entry_id)] = source
    database.finish_migration(MIGRATION_NAME, report)
    database.record_endpoint_audit("MIGRATED", endpoint_value="Legacy endpoint sources", new_data=report)
    return report
