"""Alembic helpers: locate the migration tree, run upgrades, report the head."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory


def migrations_dir() -> Path:
    override = os.environ.get("HM_MIGRATIONS_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "migrations"


def alembic_config(database_url: str | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(migrations_dir()))
    if database_url:
        config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


@lru_cache(maxsize=1)
def expected_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)
