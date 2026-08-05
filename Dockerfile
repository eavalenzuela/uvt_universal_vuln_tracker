FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4 AS backend

WORKDIR /app

# WeasyPrint runtime libs (pango/cairo/gdk-pixbuf) for F17 PDF reports.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        shared-mime-info \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt

COPY backend/ backend/
COPY migrations/ migrations/
COPY docker/entrypoint.sh /usr/local/bin/uvt-entrypoint
RUN chmod +x /usr/local/bin/uvt-entrypoint

RUN useradd --no-log-init --create-home app
USER app

ENV FLASK_APP=backend.uvt_app:create_app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')"

ENTRYPOINT ["/usr/local/bin/uvt-entrypoint"]

# gthread, not the default sync worker.
#
# /api/notifications/stream is a Server-Sent Events endpoint and the frontend
# opens one per authenticated session. A *sync* worker is occupied for the
# whole life of that connection, so with --workers 4 the fourth open tab took
# the entire service offline — including /api/health, which then made Docker
# restart the container in a loop.
#
# gthread gives 4 x 25 = 100 concurrent connections. gevent would scale
# further, but psycopg3 blocks the event loop during queries unless the driver
# is made cooperative too, so threads are the correct trade here: they handle
# blocking I/O natively and need no driver changes. The per-user stream cap in
# backend/live_notifications.py keeps one client from consuming the pool.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--worker-class", "gthread", \
     "--workers", "4", \
     "--threads", "25", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "backend.uvt_app:create_app()"]


FROM nginx:alpine AS frontend

COPY frontend/ /usr/share/nginx/html/
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 5173
