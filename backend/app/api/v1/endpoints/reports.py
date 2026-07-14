"""Faz 3 Sprint 23-24: PDF risk raporu ucu."""
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import Asset, SecurityAdvisory
from app.services.reporting import generate_risk_report

router = APIRouter()


@router.get("/reports/risk.pdf")
def risk_report_pdf(db: Session = Depends(get_db),
                    _user: dict = Depends(require_role("viewer"))):
    assets = db.query(Asset).all()
    asset_map = {a.id: a.hostname for a in assets}
    open_advisories = (db.query(SecurityAdvisory)
                       .filter(SecurityAdvisory.resolved_at.is_(None)).all())
    pdf = generate_risk_report(
        assets=[{"hostname": a.hostname, "ip_address": a.ip_address,
                 "vendor": a.vendor, "risk_score": a.risk_score} for a in assets],
        advisories=[{"hostname": asset_map.get(adv.asset_id, "—"),
                     "severity": adv.severity, "title": adv.title,
                     "rule_id": adv.rule_id} for adv in open_advisories],
    )
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": 'attachment; filename="nabs-risk-report.pdf"'})
