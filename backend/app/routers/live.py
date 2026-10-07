"""GET /stream and GET /follow: what is happening right now."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.follow import Follower
from app.live import Hub
from app.schemas import FollowStatus

router = APIRouter(tags=["live"])

KEEP_ALIVE_SECONDS = 15.0
RETRY_MILLISECONDS = 2000  # how long a browser waits before it connects again


def get_hub(request: Request) -> Hub:
    return request.app.state.hub


def get_follower(request: Request) -> Follower | None:
    return request.app.state.follower


HubDep = Annotated[Hub, Depends(get_hub)]
FollowerDep = Annotated[Follower | None, Depends(get_follower)]


def _event(name: str, data: dict[str, Any]) -> str:
    if "following" in data:
        # Written the way GET /follow writes it, times included.
        data = FollowStatus(following=data["following"]).model_dump(mode="json")
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


async def server_sent_events(
    hub: Hub, follower: Follower | None, keep_alive: float = KEEP_ALIVE_SECONDS
) -> AsyncIterator[str]:
    """The messages of one /stream response, until the hub closes or the client leaves."""
    with hub.listen() as mailbox:
        yield f"retry: {RETRY_MILLISECONDS}\n\n"
        yield _event("status", {"following": follower.status() if follower else []})
        while True:
            try:
                message = await asyncio.wait_for(mailbox.get(), keep_alive)
            except TimeoutError:
                # A comment line: keeps proxies from closing a connection that looks dead.
                yield ": keep-alive\n\n"
                continue
            if message is None:
                return
            yield _event(message.event, message.data)


@router.get(
    "/stream",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def stream(hub: HubDep, follower: FollowerDep) -> StreamingResponse:
    """Server-sent events that say when the data has changed.

    A `status` event comes first and whenever a followed file is found, lost or
    replaced; its data is what `GET /follow` returns. An `update` event comes
    after every upload, rule reload and batch of lines read from a followed
    file: `{"reason": "follow" | "ingest" | "rules", "added": <new events>,
    "alerts": <alerts in total>}`. It carries no events; ask the other
    endpoints again.
    """
    return StreamingResponse(
        server_sent_events(hub, follower),
        media_type="text/event-stream",
        # no-cache: an event stream is never to be stored. X-Accel-Buffering: nginx
        # would otherwise hold the events back to send them in larger pieces.
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/follow")
def follow_status(follower: FollowerDep) -> FollowStatus:
    """The files that are being followed, and how that is going."""
    return FollowStatus(following=follower.status() if follower else [])
