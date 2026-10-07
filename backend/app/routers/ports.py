"""GET /ports: which destination ports an address connected to, and when."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import case, func, select

from app.enums import Action
from app.models import Event
from app.routers import SessionDep
from app.routers._filters import as_utc
from app.schemas import PortConnection, PortReport, PortStats

router = APIRouter(tags=["ports"])

MAX_PORTS = 500
MAX_CONNECTIONS = 2000


@router.get("/ports")
def port_report(
    session: SessionDep,
    ip: Annotated[str, Query(description="The source address to report on.")],
    start: Annotated[
        datetime | None, Query(description="Only connections from this time on. UTC if no offset.")
    ] = None,
    end: Annotated[
        datetime | None, Query(description="Only connections before this time. UTC if no offset.")
    ] = None,
) -> PortReport:
    """The destination ports one source address tried, from the firewall's packet log.

    `ports` lists the busiest ports first; `connections` lists single packets in
    time order, for plotting when each port was tried. Both are capped; the
    totals are not, and `truncated` says whether `connections` was cut.
    """
    selected = [Event.src_ip == ip, Event.dst_port.is_not(None)]
    if start is not None:
        selected.append(Event.ts >= as_utc(start))
    if end is not None:
        selected.append(Event.ts < as_utc(end))

    blocked = func.coalesce(func.sum(case((Event.action == Action.CONN_BLOCK, 1), else_=0)), 0)
    allowed = func.coalesce(func.sum(case((Event.action == Action.CONN_ALLOW, 1), else_=0)), 0)
    total, total_blocked, total_allowed, distinct = session.execute(
        select(func.count(), blocked, allowed, func.count(func.distinct(Event.dst_port))).where(
            *selected
        )
    ).one()
    per_port = session.execute(
        select(
            Event.dst_port, func.count(), blocked, allowed, func.min(Event.ts), func.max(Event.ts)
        )
        .where(*selected)
        .group_by(Event.dst_port)
        .order_by(func.count().desc(), Event.dst_port)
        .limit(MAX_PORTS)
    ).all()
    connections = session.execute(
        select(Event.ts, Event.dst_port, Event.action)
        .where(*selected)
        .order_by(Event.ts, Event.id)
        .limit(MAX_CONNECTIONS + 1)
    ).all()

    return PortReport(
        ip=ip,
        total=total,
        blocked=total_blocked,
        allowed=total_allowed,
        distinct_ports=distinct,
        ports=[
            PortStats(
                port=port,
                count=count,
                blocked=blocks,
                allowed=allows,
                first_seen=first,
                last_seen=last,
            )
            for port, count, blocks, allows, first, last in per_port
        ],
        connections=[
            PortConnection(ts=ts, port=port, action=action)
            for ts, port, action in connections[:MAX_CONNECTIONS]
        ],
        truncated=len(connections) > MAX_CONNECTIONS,
    )
