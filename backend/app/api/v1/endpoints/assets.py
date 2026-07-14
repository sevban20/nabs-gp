"""Asset inventory CRUD + backup trigger + config history/diff."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import Asset, BackupHistory
from app.schemas.schemas import AssetCreate, AssetOut, BackupHistoryOut
from app.services.git_engine import get_git_engine

router = APIRouter()


@router.get("/assets", response_model=list[AssetOut])
def list_assets(response: Response, db: Session = Depends(get_db),
                _user: dict = Depends(require_role("viewer")),
                q: str | None = None,
                status: str | None = Query(None, pattern="^(up|down|risk)$"),
                limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    """Sunucu-taraflı arama + sayfalama (5.000+ cihaz için). Toplam sayı
    X-Total-Count başlığında döner; gövde bounded bir dizidir."""
    query = db.query(Asset)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(
            Asset.hostname.ilike(like), Asset.ip_address.ilike(like),
            Asset.vendor.ilike(like)))
    if status == "up":
        query = query.filter(Asset.is_reachable.is_(True))
    elif status == "down":
        query = query.filter(Asset.is_reachable.is_(False))
    elif status == "risk":
        query = query.filter(Asset.risk_score < 50)

    total = query.count()
    response.headers["X-Total-Count"] = str(total)
    return (query.order_by(Asset.risk_score.asc())
            .offset(offset).limit(limit).all())


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db),
                 _user: dict = Depends(require_role("operator"))):
    if db.query(Asset).filter(Asset.ip_address == payload.ip_address).first():
        raise HTTPException(status_code=409, detail="An asset with this IP already exists.")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db),
              _user: dict = Depends(require_role("viewer"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return asset


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db),
                 _user: dict = Depends(require_role("admin"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    db.delete(asset)
    db.commit()


@router.post("/assets/{asset_id}/backup", status_code=202)
def trigger_backup(asset_id: int, db: Session = Depends(get_db),
                   user: dict = Depends(require_role("operator"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    if asset.backup_method != "ACTIVE_SSH":
        raise HTTPException(status_code=400, detail="Only ACTIVE_SSH assets support on-demand backup.")
    # Kuyruğa alınır alınmaz görünür bir QUEUED kaydı oluştur (İşlem Geçmişi'nde
    # anında görünsün; worker işi alınca IN_PROGRESS -> SUCCESS/FAILED yapacak).
    history = BackupHistory(asset_id=asset.id, status="QUEUED",
                            method_used=asset.backup_method,
                            triggered_by=f"USER_{user['sub'].upper()}")
    db.add(history)
    db.commit()
    db.refresh(history)
    from app.workers.tasks import run_active_backup
    run_active_backup.delay(asset.id, f"USER_{user['sub'].upper()}", history.id)
    return {"status": "queued", "asset_id": asset.id, "job_id": history.id}


@router.get("/assets/{asset_id}/backups", response_model=list[BackupHistoryOut])
def backup_history(asset_id: int, db: Session = Depends(get_db),
                   _user: dict = Depends(require_role("viewer"))):
    return (db.query(BackupHistory).filter(BackupHistory.asset_id == asset_id)
            .order_by(BackupHistory.triggered_at.desc()).limit(50).all())


@router.get("/assets/{asset_id}/config/history")
def config_history(asset_id: int, db: Session = Depends(get_db),
                   _user: dict = Depends(require_role("viewer"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return get_git_engine().get_history(asset.hostname)


@router.get("/assets/{asset_id}/config/diff")
def config_diff(asset_id: int, commit_a: str, commit_b: str,
                db: Session = Depends(get_db), _user: dict = Depends(require_role("viewer"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    try:
        return {"diff": get_git_engine().get_diff(asset.hostname, commit_a, commit_b)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/assets/{asset_id}/config/content")
def config_content(asset_id: int, commit: str | None = None,
                   db: Session = Depends(get_db),
                   _user: dict = Depends(require_role("viewer"))):
    """Cihazın config metni: commit verilmezse en son yedeklenen sürüm,
    verilirse o tarihteki sürüm. GUI'de görüntüleme + indirme için.
    Cihaz arızalanıp değiştirildiğinde bu metni indirip yeni cihaza
    manuel yükleyebilirsiniz (otomatik geri-yazma tasarım gereği kapalı)."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    engine = get_git_engine()
    if commit:
        content = engine.get_content_at_commit(asset.hostname, commit)
    else:
        content = engine.get_current_content(asset.hostname)
        commit = engine.get_latest_commit(asset.hostname)
    if not content:
        raise HTTPException(status_code=404,
                            detail="Bu cihaz için yedeklenmiş config bulunamadı.")
    return {"hostname": asset.hostname, "commit": commit, "content": content}
