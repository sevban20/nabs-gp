"""NMS genel bakış paneli için tek çağrılık özet (net admin odaklı).

Ölçek notu: sayımlar SQL agregasyonuyla (COUNT/GROUP BY) yapılır, tüm
tablo belleğe çekilmez — 5.000+ cihazda da sabit maliyetlidir. Yalnızca
küçük, sınırlı listeler (top-5 risk, son 6 bulgu) satır olarak okunur.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db
from app.models.models import Asset, BackupHistory, RemediationAction, SecurityAdvisory

router = APIRouter()


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db),
                      _user: dict = Depends(require_role("viewer"))):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # Tek sorguda cihaz agregasyonu (COUNT + koşullu toplamlar)
    a = db.query(
        func.count(Asset.id),
        func.coalesce(func.sum(case((Asset.is_reachable.is_(True), 1), else_=0)), 0),
        func.coalesce(func.sum(case((Asset.is_reachable.is_(False), 1), else_=0)), 0),
        func.coalesce(func.sum(case((Asset.is_reachable.is_(None), 1), else_=0)), 0),
        func.coalesce(func.sum(case((Asset.is_active.is_(True), 1), else_=0)), 0),
        func.coalesce(func.avg(Asset.risk_score), 100),
        func.coalesce(func.sum(case((Asset.risk_score >= 80, 1), else_=0)), 0),
        func.coalesce(func.sum(case((Asset.risk_score.between(50, 79), 1), else_=0)), 0),
        func.coalesce(func.sum(case((Asset.risk_score < 50, 1), else_=0)), 0),
    ).one()
    (total, up, down, unknown, active, avg_risk,
     band_good, band_warn, band_bad) = a

    stale = (db.query(func.count(Asset.id)).filter(
        Asset.is_active.is_(True),
        (Asset.last_successful_backup_at.is_(None)) |
        (Asset.last_successful_backup_at < day_ago)).scalar()) or 0

    drifted = (db.query(func.count(Asset.id))
               .filter(Asset.has_drift.is_(True)).scalar()) or 0

    vendor_counts = dict(db.query(Asset.vendor, func.count()).group_by(Asset.vendor).all())

    backups_24h = dict(
        db.query(BackupHistory.status, func.count())
        .filter(BackupHistory.triggered_at >= day_ago)
        .group_by(BackupHistory.status).all())

    adv_by_sev = dict(
        db.query(SecurityAdvisory.severity, func.count())
        .filter(SecurityAdvisory.resolved_at.is_(None))
        .group_by(SecurityAdvisory.severity).all())

    pending_remediations = (db.query(func.count(RemediationAction.id))
                            .filter(RemediationAction.status == "PENDING_APPROVAL").scalar()) or 0

    top_risk = (db.query(Asset).order_by(Asset.risk_score.asc()).limit(5).all())
    recent_advisories = (db.query(SecurityAdvisory)
                         .filter(SecurityAdvisory.resolved_at.is_(None))
                         .order_by(SecurityAdvisory.detected_at.desc()).limit(6).all())
    # Yalnızca gerekli asset id -> hostname eşlemesi (küçük küme)
    adv_asset_ids = {adv.asset_id for adv in recent_advisories if adv.asset_id}
    host_by_id = {}
    if adv_asset_ids:
        host_by_id = dict(db.query(Asset.id, Asset.hostname)
                          .filter(Asset.id.in_(adv_asset_ids)).all())

    return {
        "generated_at": now.isoformat(),
        "assets": {"total": total, "up": up, "down": down, "unknown": unknown, "active": active},
        "risk": {"average": round(avg_risk or 100),
                 "bands": {"good": band_good, "warn": band_warn, "bad": band_bad}},
        "backups_24h": {
            "success": backups_24h.get("SUCCESS", 0),
            "failed": backups_24h.get("FAILED", 0) + backups_24h.get("TIMEOUT", 0),
            "in_progress": backups_24h.get("IN_PROGRESS", 0),
            "stale_assets": stale,
        },
        "advisories": {
            "critical": adv_by_sev.get("CRITICAL", 0), "high": adv_by_sev.get("HIGH", 0),
            "medium": adv_by_sev.get("MEDIUM", 0), "low": adv_by_sev.get("LOW", 0),
            "info": adv_by_sev.get("INFO", 0), "total": sum(adv_by_sev.values()),
        },
        "pending_remediations": pending_remediations,
        "drifted_assets": drifted,
        "vendors": vendor_counts,
        "top_risk_assets": [
            {"id": x.id, "hostname": x.hostname, "ip_address": x.ip_address,
             "vendor": x.vendor, "risk_score": x.risk_score,
             "is_reachable": x.is_reachable} for x in top_risk],
        "recent_advisories": [
            {"id": adv.id, "hostname": host_by_id.get(adv.asset_id, "—"),
             "title": adv.title, "severity": adv.severity, "rule_id": adv.rule_id,
             "detected_at": adv.detected_at.isoformat() if adv.detected_at else None}
            for adv in recent_advisories],
    }
