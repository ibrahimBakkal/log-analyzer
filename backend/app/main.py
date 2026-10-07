"""The FastAPI application. Run with ``uvicorn app.main:app``."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import alerts, events, health, ingest, rules, stats, timeline
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
