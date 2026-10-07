"""Runtime settings, read from environment variables."""

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    database_url: str
    rules_dir: Path


@lru_cache
def get_settings() -> Settings:
    """Settings for this process.

    ``LOG_ANALYZER_DATABASE_URL`` selects the database. The default is an SQLite
    file next to the backend code, so the path does not depend on the directory
    the server or Alembic happens to be started from.

    ``LOG_ANALYZER_RULES_DIR`` is the directory the detection rules are read
    from. The default is ``rules/`` at the top of the repository.
    """
    database = f"sqlite:///{(BACKEND_DIR / 'log_analyzer.db').as_posix()}"
    return Settings(
        database_url=os.environ.get("LOG_ANALYZER_DATABASE_URL", database),
        rules_dir=Path(os.environ.get("LOG_ANALYZER_RULES_DIR", BACKEND_DIR.parent / "rules")),
    )
