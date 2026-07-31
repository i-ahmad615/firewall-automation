"""Shared isolation for the database-backed safety registry."""
from __future__ import annotations

import pytest
from core import database


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path):
    previous = database._db_path
    database.init_db(str(tmp_path / "registry.db"))
    try:
        yield
    finally:
        database._db_path = previous
