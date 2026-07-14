"""Celery application (Spec Section 2.1: async task runner)."""
from celery import Celery

from app.core.config import settings

celery_app = Celery("nabs", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.conf.update(
    task_default_queue="default",
    task_routes={
        "app.workers.tasks.run_security_analysis": {"queue": "high-priority"},
        "app.workers.tasks.recompute_asset_risk": {"queue": "high-priority"},
    },
    beat_schedule={
        # Spec 12.1: mirror the Git repo off-host on a short interval
        "mirror-git-repo": {
            "task": "app.workers.tasks.mirror_git_repository",
            "schedule": 900.0,  # every 15 minutes
        },
        # Nightly scheduled active backups (per-asset cron refinement is Phase 2)
        "nightly-active-backups": {
            "task": "app.workers.tasks.run_scheduled_backups",
            "schedule": 86400.0,
        },
        # Bölüm 12.3: veri saklama penceresi temizliği (günlük)
        "retention-purge": {
            "task": "app.workers.tasks.purge_expired_records",
            "schedule": 86400.0,
        },
        # Up/down izleme: 5 dakikada bir TCP probe
        "asset-reachability": {
            "task": "app.workers.tasks.check_asset_reachability",
            "schedule": 300.0,
        },
        # Config drift / uyumluluk taraması: saatte bir
        "compliance-sweep": {
            "task": "app.workers.tasks.run_compliance_sweep",
            "schedule": 3600.0,
        },
    },
)
celery_app.autodiscover_tasks(["app.workers"])
