"""GET /health: is the service able to answer requests?"""

from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.models import Event
from app.routers import SessionDep

router = APIRouter(tags=["health"])


@router.get("/health")
def health(session: SessionDep) -> dict[str, str]:
    """Report ``ok`` once the database is reachable and its tables exist."""
    try:
        session.execute(select(Event.id).limit(1))
    except SQLAlchemyError:
        raise HTTPException(
            status_code=503,
            detail="database not ready (have the migrations run? `alembic upgrade head`)",
        ) from None
    return {"status": "ok"}
