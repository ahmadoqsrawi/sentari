"""Optional Celery application for distributed/queued scans.

Celery is imported lazily: if it (and a broker like Redis) are not installed,
`app` is None and `HAVE_CELERY` is False: the rest of Sentari is unaffected.
Start a worker with:  celery -A sentari.tasks worker --loglevel=info
"""
from __future__ import annotations

import os

try:
    from celery import Celery
    _HAVE = True
except Exception:  # celery not installed
    Celery = None  # type: ignore
    _HAVE = False

BROKER = (os.getenv("SENTARI_BROKER_URL") or os.getenv("REDIS_URL")
          or "redis://localhost:6379/0")
BACKEND = os.getenv("SENTARI_RESULT_BACKEND") or BROKER


def make_app():
    if not _HAVE:
        return None
    app = Celery("sentari", broker=BROKER, backend=BACKEND)
    app.conf.update(task_serializer="json", result_serializer="json",
                    accept_content=["json"], timezone="UTC", enable_utc=True,
                    task_track_started=True)
    return app


app = make_app()
HAVE_CELERY = _HAVE
