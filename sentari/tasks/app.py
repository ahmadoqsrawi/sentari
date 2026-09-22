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


def _add_schedule(app) -> None:
    """Register a periodic retest when SENTARI_SCHEDULE_TARGET is set.
    SENTARI_SCHEDULE_CRON is a 5-field cron (default: daily at 03:00).
    Run it with: celery -A sentari.tasks beat"""
    if app is None or not os.getenv("SENTARI_SCHEDULE_TARGET"):
        return
    from celery.schedules import crontab
    fields = (os.getenv("SENTARI_SCHEDULE_CRON") or "0 3 * * *").split()
    if len(fields) != 5:
        fields = ["0", "3", "*", "*", "*"]
    minute, hour, dom, mon, dow = fields
    app.conf.beat_schedule = {
        "sentari-scheduled-retest": {
            "task": "sentari.scheduled_retest",
            "schedule": crontab(minute=minute, hour=hour, day_of_month=dom,
                                month_of_year=mon, day_of_week=dow),
        }
    }


app = make_app()
_add_schedule(app)
HAVE_CELERY = _HAVE
