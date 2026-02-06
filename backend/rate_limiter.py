import math
import threading
import time
from collections import deque
from functools import wraps

from flask import current_app, jsonify, request


_LOCK = threading.Lock()


def _get_store():
    store = current_app.extensions.get("rate_limiter_store")
    if store is None:
        store = {}
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
            cutoff = now - window_seconds

            with _LOCK:
                store = _get_store()
                hits = store.get(key)
                if hits is None:
                    hits = deque()
                    store[key] = hits

                while hits and hits[0] <= cutoff:
                    hits.popleft()

                if len(hits) >= limit:
                    retry_after = max(1, math.ceil(window_seconds - (now - hits[0])))
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

                hits.append(now)
                remaining = max(0, limit - len(hits))
                reset_after = max(0, math.ceil(window_seconds - (now - hits[0])))
                reset_at = int(now + reset_after)

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
        app.extensions["rate_limiter_store"] = {}

