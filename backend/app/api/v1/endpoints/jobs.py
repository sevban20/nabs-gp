"""İşlem geçmişi / kuyruk görünürlüğü: filo geneli son yedekleme işleri
(QUEUED / IN_PROGRESS / SUCCESS / FAILED / TIMEOUT) hostname ve hata ile."""
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import Asset, BackupHistory

router = APIRouter()


@router.get("/jobs/recent")
def recent_jobs(response: Response, status: str | None = None,
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                db: Session = Depends(get_db),
                _user: dict = Depends(require_role("viewer"))):
    """Son yedekleme işleri (tüm cihazlar). QUEUED = kuyrukta bekliyor,
    IN_PROGRESS = worker çalıştırıyor, SUCCESS/FAILED = tamamlandı."""
    q = (db.query(BackupHistory, Asset.hostname)
         .outerjoin(Asset, Asset.id == BackupHistory.asset_id))
    if status:
        q = q.filter(BackupHistory.status == status)
    response.headers["X-Total-Count"] = str(q.count())
    rows = (q.order_by(BackupHistory.triggered_at.desc())
            .offset(offset).limit(limit).all())
    return [{
        "id": h.id,
        "hostname": hostname or "—",
        "asset_id": h.asset_id,
        "status": h.status,
        "method_used": h.method_used,
        "triggered_by": h.triggered_by,
        "triggered_at": h.triggered_at.isoformat() if h.triggered_at else None,
        "completed_at": h.completed_at.isoformat() if h.completed_at else None,
        "commit_hash": h.commit_hash,
        "error_log": h.error_log,
    } for h, hostname in rows]


@router.get("/jobs/counts")
def job_counts(db: Session = Depends(get_db),
               _user: dict = Depends(require_role("viewer"))):
    """Aktif kuyruk özeti: bekleyen/çalışan iş sayısı."""
    from sqlalchemy import func
    counts = dict(db.query(BackupHistory.status, func.count())
                  .group_by(BackupHistory.status).all())
    return {
        "queued": counts.get("QUEUED", 0),
        "in_progress": counts.get("IN_PROGRESS", 0),
        "success": counts.get("SUCCESS", 0),
        "failed": counts.get("FAILED", 0) + counts.get("TIMEOUT", 0),
    }
