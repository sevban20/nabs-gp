"""Security advisory endpoints: list, resolve, silence.
Resolving/silencing queues a risk-score recompute (Spec Section 6)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import SecurityAdvisory
from app.schemas.schemas import AdvisoryOut

router = APIRouter()


def _queue_risk_recompute(asset_id: int | None) -> None:
    if asset_id is None:
        return
    from app.workers.tasks import recompute_asset_risk
    recompute_asset_risk.delay(asset_id)


@router.get("/advisories", response_model=list[AdvisoryOut])
def list_advisories(response: Response, asset_id: int | None = None, open_only: bool = True,
                    severity: str | None = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
                    limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0),
                    db: Session = Depends(get_db),
                    _user: dict = Depends(require_role("viewer"))):
    q = db.query(SecurityAdvisory)
    if asset_id is not None:
        q = q.filter(SecurityAdvisory.asset_id == asset_id)
    if open_only:
        q = q.filter(SecurityAdvisory.resolved_at.is_(None))
    if severity:
        q = q.filter(SecurityAdvisory.severity == severity)
    response.headers["X-Total-Count"] = str(q.count())
    return (q.order_by(SecurityAdvisory.detected_at.desc())
            .offset(offset).limit(limit).all())


@router.post("/advisories/{advisory_id}/resolve", response_model=AdvisoryOut)
def resolve_advisory(advisory_id: int, db: Session = Depends(get_db),
                     user: dict = Depends(require_role("operator"))):
    adv = db.get(SecurityAdvisory, advisory_id)
    if not adv:
        raise HTTPException(status_code=404, detail="Advisory not found.")
    adv.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(adv)
    _queue_risk_recompute(adv.asset_id)
    return adv


@router.post("/advisories/{advisory_id}/silence", response_model=AdvisoryOut)
def silence_advisory(advisory_id: int, db: Session = Depends(get_db),
                     _user: dict = Depends(require_role("operator"))):
    adv = db.get(SecurityAdvisory, advisory_id)
    if not adv:
        raise HTTPException(status_code=404, detail="Advisory not found.")
    adv.is_silenced = True
    db.commit()
    db.refresh(adv)
    _queue_risk_recompute(adv.asset_id)
    return adv
