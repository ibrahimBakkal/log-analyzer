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
    cors_origins: tuple[str, ...]
    follow: tuple[Path, ...] = ()
    follow_tz: str = "UTC"
    follow_interval: float = 1.0


@lru_cache
def get_settings() -> Settings:
    """Settings for this process.

    ``LOG_ANALYZER_DATABASE_URL`` selects the database. The default is an SQLite
    file next to the backend code, so the path does not depend on the directory
    the server or Alembic happens to be started from.

    ``LOG_ANALYZER_RULES_DIR`` is the directory the detection rules are read
    from. The default is ``rules/`` at the top of the repository.

    ``LOG_ANALYZER_CORS_ORIGINS`` lists, separated by commas, the addresses a
    browser may load the web interface from. The default is the Vite dev server.

    ``LOG_ANALYZER_FOLLOW`` lists, separated by commas, log files to follow as
    they grow (``/var/log/auth.log,/var/log/ufw.log``). ``LOG_ANALYZER_FOLLOW_TZ``
    is the time zone their timestamps are in (default ``UTC``), and
    ``LOG_ANALYZER_FOLLOW_INTERVAL`` the seconds between two looks (default 1).
    """
    origins = os.environ.get(
        "LOG_ANALYZER_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )
    database = f"sqlite:///{(BACKEND_DIR / 'log_analyzer.db').as_posix()}"
    return Settings(
        database_url=os.environ.get("LOG_ANALYZER_DATABASE_URL", database),
        rules_dir=Path(os.environ.get("LOG_ANALYZER_RULES_DIR", BACKEND_DIR.parent / "rules")),
        cors_origins=tuple(origin.strip() for origin in origins.split(",") if origin.strip()),
        follow=tuple(
            Path(path.strip()).expanduser()
            for path in os.environ.get("LOG_ANALYZER_FOLLOW", "").split(",")
            if path.strip()
        ),
        follow_tz=os.environ.get("LOG_ANALYZER_FOLLOW_TZ", "UTC"),
        follow_interval=float(os.environ.get("LOG_ANALYZER_FOLLOW_INTERVAL", "1")),
    )
