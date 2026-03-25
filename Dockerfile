FROM python:3.12-slim AS backend

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/

ENV FLASK_APP=backend.uvt_app:create_app
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["flask", "run", "--host", "0.0.0.0", "--port", "5000"]


FROM nginx:alpine AS frontend

COPY frontend/ /usr/share/nginx/html/
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 5173
