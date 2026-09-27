from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any


class EventBroker:
    """In-process fan-out for live UI updates.

    PostgreSQL remains authoritative. This broker intentionally carries only
    transient notifications; reconnecting clients reload persisted records.
    """

    def __init__(self, history_size: int = 200, queue_size: int = 200) -> None:
        self.history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self.queue_size = queue_size
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    async def publish(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        message = {
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data,
        }
        self.history.append(message)
        for queue in tuple(self.subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(message)
        return message

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self.queue_size)
        self.subscribers.add(queue)
        try:
            while True:
                try:
                    yield await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield {
                        "type": "heartbeat",
                        "timestamp": datetime.now(UTC).isoformat(),
                        "data": {},
                    }
        finally:
            self.subscribers.discard(queue)

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(self.history)[-limit:]


live_broker = EventBroker()
