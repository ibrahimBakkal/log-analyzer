"""The FastAPI application. Run with ``uvicorn app.main:app``."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, contextmanager
from importlib.metadata import version

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings
from app.db import get_session, session_factory
from app.follow import Follower
from app.live import Hub, on_exit_signal
from app.routers import alerts, events, health, ingest, live, ports, rules, stats, timeline
from app.rules import AlertKeeper, latest_event_id, load_rules

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    app.state.rules = load_rules(settings.rules_dir)
    for error in app.state.rules.errors:
        log.warning("rule file %s was not loaded: %s", error.file, error.message)

    app.state.hub = Hub()
    app.state.alerts = AlertKeeper()
    _check_alerts(app)
    app.state.follower = None
    if settings.follow:
        app.state.follower = Follower(
            settings.follow,
            session_factory=session_factory(),
            rules=lambda: app.state.rules,
            alerts=app.state.alerts,
            hub=app.state.hub,
            tz=settings.follow_tz,
            interval=settings.follow_interval,
        )
        app.state.follower.start()
        log.info("following %s", ", ".join(str(path) for path in settings.follow))
    # Open /stream responses would keep the server from shutting down.
    restore_signals = on_exit_signal(app.state.hub.close)
    try:
        yield
    finally:
        restore_signals()
        if app.state.follower is not None:
            app.state.follower.stop()
        app.state.hub.close()


def _check_alerts(app: FastAPI) -> None:
    """Redo the alerts if the rules are not the ones they were made with.

    Someone who edits a rule file and restarts the server expects the alerts to
    follow. If nothing changed this costs a few small queries.
    """
    # Through the same door requests use, so that whoever swaps the database
    # (the tests do) swaps it for this as well.
    open_session = contextmanager(app.dependency_overrides.get(get_session, get_session))
    try:
        with open_session() as session:
            outcome = app.state.alerts.refresh(
                session, app.state.rules, since=latest_event_id(session)
            )
    except SQLAlchemyError as error:
        # Most likely a database without tables yet; /health says what to do about it.
        log.warning("alerts were not checked against the rules: %s", str(error).splitlines()[0])
        return
    if outcome.created or outcome.updated or outcome.removed:
        log.info(
            "rules have changed since the alerts were made: %d created, %d updated, %d removed",
            outcome.created,
            outcome.updated,
            outcome.removed,
        )


app = FastAPI(
    title="Log Analyzer",
    version=version("log-analyzer"),
    summary="Turns server logs into events and alerts for timeline analysis.",
    lifespan=lifespan,
)
# The web interface is served from another origin; let its pages call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(get_settings().cors_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(timeline.router)
app.include_router(stats.router)
app.include_router(ports.router)
app.include_router(live.router)
