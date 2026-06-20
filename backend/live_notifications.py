from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from queue import Empty, Queue
from threading import Lock
from typing import Any

_EVENT_QUEUE_TIMEOUT_SECONDS = 25


class LiveNotificationHub:
    def __init__(self) -> None:
        self._lock = Lock()
        self._subscribers: dict[int, set[Queue[dict[str, Any] | None]]] = defaultdict(set)

    def subscribe(self, user_id: int) -> Queue[dict[str, Any] | None]:
        queue: Queue[dict[str, Any] | None] = Queue()
        with self._lock:
            self._subscribers[user_id].add(queue)
        return queue

    def unsubscribe(self, user_id: int, queue: Queue[dict[str, Any] | None]) -> None:
        with self._lock:
            queues = self._subscribers.get(user_id)
            if not queues:
                return
            queues.discard(queue)
            if not queues:
                self._subscribers.pop(user_id, None)

    def publish(self, user_id: int, event: dict[str, Any]) -> None:
        payload = dict(event)
        # isoformat() already emits the "+00:00" offset for aware datetimes;
        # appending "Z" produced a malformed "...+00:00Z". Normalize to a single
        # "Z" designator instead.
        payload.setdefault("sent_at", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        with self._lock:
            queues = list(self._subscribers.get(user_id, ()))
        for queue in queues:
            queue.put(payload)


hub = LiveNotificationHub()


def publish_user_event(*, user_id: int, event_type: str, payload: dict[str, Any] | None = None) -> None:
    hub.publish(
        user_id,
        {
            "type": event_type,
            "payload": payload or {},
        },
    )


def queue_generator(user_id: int):
    queue = hub.subscribe(user_id)
    try:
        while True:
            try:
                event = queue.get(timeout=_EVENT_QUEUE_TIMEOUT_SECONDS)
            except Empty:
                yield {
                    "type": "heartbeat",
                    "payload": {},
                }
                continue

            if event is None:
                return
            yield event
    finally:
        hub.unsubscribe(user_id, queue)


def reset_live_notification_hub() -> None:
    global hub
    hub = LiveNotificationHub()
