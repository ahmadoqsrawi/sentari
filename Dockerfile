# Sentari image. The core needs only the stdlib; celery+redis are added so the
# same image can run the distributed worker and dashboard.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY sentari ./sentari

RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir "celery>=5" "redis>=5" "psycopg2-binary>=2.9"

# default: show help. Compose/K8s override command per role (worker/dashboard/scan).
ENTRYPOINT ["sentari"]
CMD ["--help"]
