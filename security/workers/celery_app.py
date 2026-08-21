from celery import Celery
from security.config import settings

celery_app = Celery(
    "security_analysis",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "security.workers.tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3000,
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    result_expires=86400,
    task_routes={
        "security.workers.tasks.run_analysis_pipeline": {"queue": "analysis"},
        "security.workers.tasks.build_attack_graph": {"queue": "graph"},
        "security.workers.tasks.generate_regression_test": {"queue": "regression"},
        "security.workers.tasks.assess_severity": {"queue": "severity"},
    },
    beat_schedule={
        "daily-baseline-update": {
            "task": "security.workers.tasks.update_baselines",
            "schedule": 86400.0,
        },
        "hourly-regression-check": {
            "task": "security.workers.tasks.check_regressions",
            "schedule": 3600.0,
        },
    },
)

celery_app.autodiscover_tasks()