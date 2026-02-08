import math

import pytest

from backend.rate_limiter import clear_rate_limit_state, rate_limit


class FakeRedisClient:
    def __init__(self):
        self._hits_by_key = {}

    def eval(self, _script, _num_keys, key, now, window_seconds, limit, _member):
        now = float(now)
        window_seconds = int(window_seconds)
        limit = int(limit)
        cutoff = now - window_seconds
        hits = [hit for hit in self._hits_by_key.get(key, []) if hit > cutoff]
        self._hits_by_key[key] = hits

        if len(hits) >= limit:
            retry_after = max(1, math.ceil(window_seconds - (now - hits[0])))
            return [0, 0, retry_after]

        hits.append(now)
        hits.sort()
        self._hits_by_key[key] = hits
        remaining = max(0, limit - len(hits))
        reset_after = max(0, math.ceil(window_seconds - (now - hits[0])))
        return [1, remaining, reset_after]

    def flushdb(self):
        self._hits_by_key = {}


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_rate_limit_headers_and_retry_behavior_are_consistent_across_backends(app, backend):
    current = [1000.0]

    def fake_now():
        return current[0]

    app.config.update(
        RATE_LIMIT_BACKEND=backend,
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_TIME_FUNCTION=fake_now,
        TEST_LIMIT=2,
        TEST_WINDOW=10,
    )
    if backend == "redis":
        app.config["RATE_LIMIT_REDIS_CLIENT"] = FakeRedisClient()

    endpoint = f"rate_limit_backend_{backend}"

    @rate_limit("TEST_LIMIT", "TEST_WINDOW", identifier=endpoint)
    def limited_route():
        return {"ok": True}

    app.add_url_rule(f"/_test/rate_limit/{backend}", endpoint, limited_route)
    clear_rate_limit_state(app)
    client = app.test_client()

    first = client.get(f"/_test/rate_limit/{backend}")
    assert first.status_code == 200
    assert first.headers["X-RateLimit-Limit"] == "2"
    assert first.headers["X-RateLimit-Remaining"] == "1"
    assert first.headers["X-RateLimit-Reset"] == "1010"

    second = client.get(f"/_test/rate_limit/{backend}")
    assert second.status_code == 200
    assert second.headers["X-RateLimit-Remaining"] == "0"
    assert second.headers["X-RateLimit-Reset"] == "1010"

    blocked = client.get(f"/_test/rate_limit/{backend}")
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "10"
    assert blocked.headers["X-RateLimit-Limit"] == "2"
    assert blocked.headers["X-RateLimit-Remaining"] == "0"
    assert blocked.headers["X-RateLimit-Reset"] == "1010"

    current[0] += 11

    allowed = client.get(f"/_test/rate_limit/{backend}")
    assert allowed.status_code == 200
    assert allowed.headers["X-RateLimit-Remaining"] == "1"
