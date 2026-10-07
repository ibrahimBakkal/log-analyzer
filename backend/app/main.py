"""The FastAPI application. Run with ``uvicorn app.main:app``."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version

from fastapi import FastAPI

from app.config import get_settings
from app.routers import alerts, events, health, ingest, rules
from app.rules import load_rules

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.rules = load_rules(get_settings().rules_dir)
    for error in app.state.rules.errors:
        log.warning("rule file %s was not loaded: %s", error.file, error.message)
    yield


app = FastAPI(
    title="Log Analyzer",
    version=version("log-analyzer"),
    summary="Turns server logs into events and alerts for timeline analysis.",
    lifespan=lifespan,
)
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(rules.router)
