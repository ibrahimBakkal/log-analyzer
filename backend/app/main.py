"""The FastAPI application. Run with ``uvicorn app.main:app``."""

from importlib.metadata import version

from fastapi import FastAPI

from app.routers import events, health, ingest

app = FastAPI(
    title="Log Analyzer",
    version=version("log-analyzer"),
    summary="Turns server logs into events for timeline analysis.",
)
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(events.router)
