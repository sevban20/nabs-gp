"""Config drift & uyumluluk uçları: golden baseline yönetimi, drift
görüntüleme, filo geneli drift listesi ve manuel sweep tetikleme."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import Asset, ConfigBaseline
from app.services.drift import compute_drift, content_hash
from app.services.git_engine import get_git_engine

router = APIRouter()


class BaselineCreate(BaseModel):
    note: str | None = None


@router.post("/assets/{asset_id}/baseline", status_code=201)
def set_baseline(asset_id: int, payload: BaselineCreate, db: Session = Depends(get_db),
                 user: dict = Depends(require_role("operator"))):
    """Cihazın MEVCUT (en son commit'lenmiş) config'ini golden referans
    olarak sabitler. Bundan sonra sapmalar bu noktaya göre ölçülür."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı.")
    engine = get_git_engine()
    commit = engine.get_latest_commit(asset.hostname)
    current = engine.get_current_content(asset.hostname)
    if not commit or not current:
        raise HTTPException(status_code=400,
                            detail="Cihazın henüz yedeklenmiş bir config'i yok; önce yedek alın.")

    baseline = db.query(ConfigBaseline).filter(ConfigBaseline.asset_id == asset_id).first()
    if baseline is None:
        baseline = ConfigBaseline(asset_id=asset_id)
        db.add(baseline)
    baseline.commit_hash = commit
    baseline.content_hash = content_hash(current)
    baseline.note = payload.note
    baseline.set_by = user["sub"]
    baseline.set_at = datetime.now(timezone.utc)
    # Baz alındığında cihaz tanımı gereği sync'tir; açık drift'i temizle
    asset.has_drift = False
    asset.last_drift_check_at = datetime.now(timezone.utc)
    from app.models.models import SecurityAdvisory
    for adv in db.query(SecurityAdvisory).filter(
            SecurityAdvisory.asset_id == asset_id,
            SecurityAdvisory.rule_id == "CONFIG-DRIFT",
            SecurityAdvisory.resolved_at.is_(None)).all():
        adv.resolved_at = datetime.now(timezone.utc)
    db.commit()
    return {"asset_id": asset_id, "commit_hash": commit, "set_by": baseline.set_by}


@router.get("/assets/{asset_id}/drift")
def get_drift(asset_id: int, db: Session = Depends(get_db),
              _user: dict = Depends(require_role("viewer"))):
    """Cihazın golden'a göre anlık drift durumu ve diff'i."""
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı.")
    baseline = db.query(ConfigBaseline).filter(ConfigBaseline.asset_id == asset_id).first()
    if baseline is None:
        return {"has_baseline": False, "in_sync": None, "diff": "",
                "message": "Bu cihaz için golden baseline tanımlı değil."}
    engine = get_git_engine()
    golden = engine.get_content_at_commit(asset.hostname, baseline.commit_hash)
    current = engine.get_current_content(asset.hostname)
    result = compute_drift(golden, current)
    return {"has_baseline": True, "baseline_commit": baseline.commit_hash,
            "baseline_set_at": baseline.set_at.isoformat() if baseline.set_at else None,
            "baseline_note": baseline.note, **result}


@router.delete("/assets/{asset_id}/baseline", status_code=204)
def clear_baseline(asset_id: int, db: Session = Depends(get_db),
                   _user: dict = Depends(require_role("operator"))):
    baseline = db.query(ConfigBaseline).filter(ConfigBaseline.asset_id == asset_id).first()
    if baseline:
        db.delete(baseline)
        asset = db.get(Asset, asset_id)
        if asset:
            asset.has_drift = False
        db.commit()


@router.get("/compliance/drift")
def fleet_drift(db: Session = Depends(get_db),
                _user: dict = Depends(require_role("viewer"))):
    """Filo geneli: baseline'ı olan cihazlar ve drift durumları."""
    baselined = {b.asset_id: b for b in db.query(ConfigBaseline).all()}
    if not baselined:
        return {"total_baselined": 0, "drifted": 0, "assets": []}
    assets = db.query(Asset).filter(Asset.id.in_(baselined.keys())).all()
    rows = [{
        "id": a.id, "hostname": a.hostname, "ip_address": a.ip_address,
        "vendor": a.vendor, "has_drift": a.has_drift,
        "last_drift_check_at": a.last_drift_check_at.isoformat() if a.last_drift_check_at else None,
        "baseline_set_at": baselined[a.id].set_at.isoformat() if baselined[a.id].set_at else None,
    } for a in assets]
    return {"total_baselined": len(rows),
            "drifted": sum(1 for r in rows if r["has_drift"]), "assets": rows}


@router.post("/compliance/sweep", status_code=202)
def trigger_sweep(_user: dict = Depends(require_role("operator"))):
    """Uyumluluk/drift taramasını hemen kuyruğa alır."""
    from app.workers.tasks import run_compliance_sweep
    t = run_compliance_sweep.delay()
    return {"status": "queued", "task_id": str(t)}
