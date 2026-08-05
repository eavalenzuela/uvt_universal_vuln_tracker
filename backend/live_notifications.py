from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from queue import Empty, Queue
from threading import Lock
from time import monotonic
from typing import Any

_EVENT_QUEUE_TIMEOUT_SECONDS = 25

# Each open stream occupies a worker thread for its lifetime. Browsers cap
# themselves at ~6 connections per origin, so a handful per user is plenty —
# and it stops one client with many tabs from draining the pool for everyone.
#
# The hub is per worker process, so this bounds streams per user *per worker*
# (4 workers x 5 = 20 overall with the shipped Gunicorn settings). Making it
# global would need the same shared backend that cross-worker event delivery
# already wants; the per-process bound is what protects the thread pool, which
# is the point here.
MAX_STREAMS_PER_USER = 5

# Streams are closed after this long so clients reconnect. That reclaims
# threads left behind by connections a proxy dropped without telling us, and
# spreads reconnections rather than having every client re-attach at once
# after a restart.
MAX_STREAM_SECONDS = 30 * 60


class TooManyStreamsError(Exception):
    """Raised when a user already holds the maximum number of open streams."""


class LiveNotificationHub:
    def __init__(self) -> None:
        self._lock = Lock()
        self._subscribers: dict[int, set[Queue[dict[str, Any] | None]]] = defaultdict(set)

    def subscribe(self, user_id: int) -> Queue[dict[str, Any] | None]:
        queue: Queue[dict[str, Any] | None] = Queue()
        with self._lock:
            if len(self._subscribers.get(user_id, ())) >= MAX_STREAMS_PER_USER:
                raise TooManyStreamsError(
                    f"At most {MAX_STREAMS_PER_USER} live notification streams per user"
                )
            self._subscribers[user_id].add(queue)
        return queue

    def stream_count(self, user_id: int) -> int:
        with self._lock:
            return len(self._subscribers.get(user_id, ()))

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
    deadline = monotonic() + MAX_STREAM_SECONDS
    try:
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                # EventSource reconnects on a clean close, so this is
                # transparent to the client.
                return
            try:
                event = queue.get(timeout=min(_EVENT_QUEUE_TIMEOUT_SECONDS, remaining))
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
