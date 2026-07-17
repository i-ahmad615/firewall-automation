"""Safe, structure-preserving reader/writer for the ``.env`` file.

Used by the Settings page so administrators never have to hand-edit
``.env``. Existing comments, blank lines, and key ordering are preserved;
only the values of known keys are changed, and unknown new keys are
appended at the end.
"""
from __future__ import annotations

from pathlib import Path

_LINE_RE_CACHE: dict[str, str] = {}


def read_env_pairs(path: str) -> dict[str, str]:
    """Return ``{KEY: value}`` for every assignment line in *path*."""
    p = Path(path)
    if not p.exists():
        return {}
    pairs: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        pairs[key.strip()] = value.strip()
    return pairs


def write_env_pairs(path: str, updates: dict[str, str]) -> None:
    """Update *path* in place with *updates*, preserving file structure.

    Keys not present in *updates* are left untouched. Keys in *updates*
    that don't yet exist in the file are appended at the end.
    """
    p = Path(path)
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    remaining = dict(updates)
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key, _, _old_value = stripped.partition("=")
        key = key.strip()
        if key in remaining:
            new_lines.append(f"{key}={remaining.pop(key)}")
        else:
            new_lines.append(line)

    if remaining:
        if new_lines and new_lines[-1].strip() != "":
            new_lines.append("")
        new_lines.append("# ── Added via Settings page ──────────────────────────")
        for key, value in remaining.items():
            new_lines.append(f"{key}={value}")

    p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
