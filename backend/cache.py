"""Simple Redis-backed cache with JSON serialization and TTL.

Falls back to a no-op cache when Redis is unavailable or caching is disabled,
so callers never need to check availability.
"""

from __future__ import annotations

import json
import hashlib
import logging
from functools import wraps
from typing import Any

from flask import current_app

logger = logging.getLogger(__name__)

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None

_client = None


def _get_client():
    """Lazy-init a shared Redis client for caching (DB 3)."""
    global _client
    if _client is not None:
        return _client
    if redis_lib is None:
        return None
    redis_url = current_app.config.get("REDIS_URL", "redis://localhost:6379/0")
    # Use DB 3 for cache (0 = rate limiting, 1 = celery broker, 2 = celery results)
    cache_url = redis_url.rsplit("/", 1)[0] + "/3"
    try:
        _client = redis_lib.from_url(cache_url, decode_responses=True, socket_timeout=2)
        _client.ping()
        return _client
    except Exception:
        logger.debug("Redis cache unavailable, caching disabled", exc_info=True)
        _client = None
        return None


def _cache_key(prefix: str, params: dict) -> str:
    """Build a deterministic cache key from a prefix and parameters."""
    raw = json.dumps(params, sort_keys=True, default=str)
    digest = hashlib.md5(raw.encode()).hexdigest()[:12]
    return f"uvt:cache:{prefix}:{digest}"


def cache_get(prefix: str, params: dict) -> Any | None:
    """Fetch a cached value. Returns None on miss or when cache is unavailable."""
    if not current_app.config.get("CACHE_ENABLED"):
        return None
    client = _get_client()
    if not client:
        return None
    try:
        raw = client.get(_cache_key(prefix, params))
        if raw is not None:
            return json.loads(raw)
    except Exception:
        logger.debug("Cache get failed", exc_info=True)
    return None


def cache_set(prefix: str, params: dict, value: Any, ttl: int = 30) -> None:
    """Store a value in the cache with a TTL in seconds."""
    if not current_app.config.get("CACHE_ENABLED"):
        return
    client = _get_client()
    if not client:
        return
    try:
        client.setex(_cache_key(prefix, params), ttl, json.dumps(value, default=str))
    except Exception:
        logger.debug("Cache set failed", exc_info=True)


def cache_invalidate(prefix: str) -> None:
    """Delete all cache keys matching a prefix pattern."""
    if not current_app.config.get("CACHE_ENABLED"):
        return
    client = _get_client()
    if not client:
        return
    try:
        pattern = f"uvt:cache:{prefix}:*"
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor, match=pattern, count=100)
            if keys:
                client.delete(*keys)
            if cursor == 0:
                break
    except Exception:
        logger.debug("Cache invalidate failed", exc_info=True)


def cached(prefix: str, ttl: int = 30):
    """Decorator that caches a function's return value based on its kwargs."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(**kwargs):
            hit = cache_get(prefix, kwargs)
            if hit is not None:
                return hit
            result = fn(**kwargs)
            cache_set(prefix, kwargs, result, ttl=ttl)
            return result
        return wrapper
    return decorator
