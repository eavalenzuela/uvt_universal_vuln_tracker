#!/bin/sh
# Bring the database to head, then start the app.
#
# This runs once in the container's main process before Gunicorn forks, so the
# four workers never race each other to migrate. The app refuses to serve if
# the schema is behind anyway (backend/schema_guard.py), so a failure here
# surfaces as a clear 503 rather than as 500s from missing columns.
set -e

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "[uvt] applying database migrations..."
    if ! flask db upgrade; then
        echo "[uvt] migration failed — starting anyway so the schema guard can" >&2
        echo "[uvt] report the reason on /api/health. The API will return 503." >&2
    fi
fi

exec "$@"
