import math
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from functools import wraps

from flask import current_app, jsonify, request

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency in local/test environments
    redis = None


_LOCK = threading.Lock()


@dataclass
class RateLimitDecision:
    allowed: bool
    remaining: int
    reset_after: int
    retry_after: int | None = None


class RateLimitStore(ABC):
    @abstractmethod
    def consume(self, key, now, window_seconds, limit):
        raise NotImplementedError

    @abstractmethod
    def clear(self):
        raise NotImplementedError


class MemoryRateLimitStore(RateLimitStore):
    def __init__(self):
        self._hits_by_key = {}
        self._lock = threading.Lock()

    def consume(self, key, now, window_seconds, limit):
        cutoff = now - window_seconds
        with self._lock:
            hits = self._hits_by_key.get(key)
            if hits is None:
                hits = deque()
                self._hits_by_key[key] = hits

            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= limit:
                retry_after = max(1, math.ceil(window_seconds - (now - hits[0])))
                return RateLimitDecision(
                    allowed=False,
                    remaining=0,
                    reset_after=retry_after,
                    retry_after=retry_after,
                )

            hits.append(now)
            remaining = max(0, limit - len(hits))
            reset_after = max(0, math.ceil(window_seconds - (now - hits[0])))
            return RateLimitDecision(allowed=True, remaining=remaining, reset_after=reset_after)

    def clear(self):
        with self._lock:
            self._hits_by_key = {}


class RedisRateLimitStore(RateLimitStore):
    _LUA_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)
if count >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local oldest_score = tonumber(oldest[2])
    local retry_after = math.ceil(window - (now - oldest_score))
    if retry_after < 1 then
        retry_after = 1
    end
    return {0, 0, retry_after}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.max(1, math.ceil(window) + 1))
count = redis.call('ZCARD', key)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local oldest_score = tonumber(oldest[2])
local reset_after = math.ceil(window - (now - oldest_score))
if reset_after < 0 then
    reset_after = 0
end
local remaining = limit - count
if remaining < 0 then
    remaining = 0
end

return {1, remaining, reset_after}
"""

    def __init__(self, redis_url, client=None):
        if client is not None:
            self._client = client
        else:
            if redis is None:
                raise RuntimeError("redis package is not installed")
            self._client = redis.from_url(redis_url, decode_responses=True)

    def consume(self, key, now, window_seconds, limit):
        member = f"{now}:{uuid.uuid4().hex}"
        allowed, remaining, reset_after = self._client.eval(
            self._LUA_SCRIPT,
            1,
            key,
            str(now),
            str(window_seconds),
            str(limit),
            member,
        )
        if int(allowed) == 1:
            return RateLimitDecision(allowed=True, remaining=int(remaining), reset_after=int(reset_after))
        return RateLimitDecision(
            allowed=False,
            remaining=0,
            reset_after=int(reset_after),
            retry_after=int(reset_after),
        )

    def clear(self):
        self._client.flushdb()


def _build_store_from_config():
    backend = (current_app.config.get("RATE_LIMIT_BACKEND") or "memory").lower()
    if backend == "redis":
        redis_url = current_app.config.get("REDIS_URL", "redis://localhost:6379/0")
        client = current_app.config.get("RATE_LIMIT_REDIS_CLIENT")
        try:
            return RedisRateLimitStore(redis_url=redis_url, client=client)
        except Exception as exc:  # pragma: no cover - fallback guard
            current_app.logger.warning("Redis rate limiter unavailable, falling back to memory backend: %s", exc)
    return MemoryRateLimitStore()


def _get_store():
    store = current_app.extensions.get("rate_limiter_store")
    if store is None:
        store = _build_store_from_config()
        current_app.extensions["rate_limiter_store"] = store
    return store


def _to_positive_int(value, default):
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _current_time():
    override = current_app.config.get("RATE_LIMIT_TIME_FUNCTION")
    if callable(override):
        return float(override())
    return time.time()


def _client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def _default_key(identifier=None):
    user = getattr(request, "user", None)
    user_component = f"user:{user.id}" if user is not None else "anon"
    base = f"{_client_ip()}|{user_component}"
    if identifier:
        return f"{identifier}|{base}"
    return base


def rate_limit(limit_config_key, window_config_key, key_func=None, identifier=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_app.config.get("RATE_LIMIT_ENABLED", True):
                return func(*args, **kwargs)

            limit = _to_positive_int(current_app.config.get(limit_config_key), default=60)
            window_seconds = _to_positive_int(current_app.config.get(window_config_key), default=60)
            key_builder = key_func or (lambda: _default_key(identifier=identifier or func.__name__))
            key = key_builder()

            now = _current_time()
            with _LOCK:
                store = _get_store()
                decision = store.consume(key=key, now=now, window_seconds=window_seconds, limit=limit)
                if not decision.allowed:
                    retry_after = decision.retry_after or 1
                    reset_at = int(now + retry_after)
                    response = jsonify(
                        {
                            "error": "Rate limit exceeded",
                            "retry_after_seconds": retry_after,
                        }
                    )
                    response.status_code = 429
                    response.headers["Retry-After"] = str(retry_after)
                    response.headers["X-RateLimit-Limit"] = str(limit)
                    response.headers["X-RateLimit-Remaining"] = "0"
                    response.headers["X-RateLimit-Reset"] = str(reset_at)
                    return response
                remaining = decision.remaining
                reset_at = int(now + decision.reset_after)

            response = func(*args, **kwargs)
            flask_response = current_app.make_response(response)
            flask_response.headers["X-RateLimit-Limit"] = str(limit)
            flask_response.headers["X-RateLimit-Remaining"] = str(remaining)
            flask_response.headers["X-RateLimit-Reset"] = str(reset_at)
            return flask_response

        return wrapper

    return decorator


def clear_rate_limit_state(app):
    with _LOCK:
        store = app.extensions.get("rate_limiter_store")
        if store is not None:
            store.clear()
        app.extensions.pop("rate_limiter_store", None)
