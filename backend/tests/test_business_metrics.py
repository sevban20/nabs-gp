"""İş metrikleri collector testi (Prometheus scrape simülasyonu)."""
from datetime import datetime, timedelta, timezone

import pytest

from app.core.business_metrics import NabsBusinessCollector
from app.core.database import Base, SessionLocal, engine
from app.models.models import Asset, BackupHistory, SecurityAdvisory


@pytest.fixture(scope="module", autouse=True)
def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(Asset).filter(Asset.hostname == "BM-UP-01").first():
        up = Asset(hostname="BM-UP-01", ip_address="10.99.0.1", vendor="cisco_ios",
                   backup_method="ACTIVE_SSH", is_reachable=True, risk_score=72,
                   last_successful_backup_at=datetime.now(timezone.utc))
        down = Asset(hostname="BM-DOWN-01", ip_address="10.99.0.2", vendor="fortinet",
                     backup_method="PASSIVE_SFTP", is_reachable=False, risk_score=40)
        db.add_all([up, down])
        db.commit()
        db.add_all([
            BackupHistory(asset_id=up.id, status="SUCCESS", method_used="ACTIVE_SSH",
                          triggered_by="TEST"),
            BackupHistory(asset_id=down.id, status="FAILED", method_used="PASSIVE_SFTP",
                          triggered_by="TEST",
                          triggered_at=datetime.now(timezone.utc) - timedelta(hours=1)),
            SecurityAdvisory(asset_id=down.id, rule_id="BM-1", title="t", description="d",
                             severity="CRITICAL", finding_source="STATIC_RULE_ENGINE"),
        ])
        db.commit()
    db.close()
    yield


def _scrape() -> dict:
    metrics = {}
    for family in NabsBusinessCollector().collect():
        for sample in family.samples:
            metrics[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return metrics


def test_asset_counts():
    m = _scrape()
    assert m[("nabs_assets_total", ())] >= 2
    assert m[("nabs_assets_by_vendor", (("vendor", "cisco_ios"),))] >= 1


def test_up_down_counts_and_per_asset():
    m = _scrape()
    assert m[("nabs_assets_reachable_total", ())] >= 1
    assert m[("nabs_assets_unreachable_total", ())] >= 1
    assert m[("nabs_asset_reachable",
              (("hostname", "BM-DOWN-01"), ("ip", "10.99.0.2")))] == 0


def test_backup_24h_and_stale():
    m = _scrape()
    assert m[("nabs_backups_24h_total", (("status", "SUCCESS"),))] >= 1
    assert m[("nabs_backups_24h_total", (("status", "FAILED"),))] >= 1
    # BM-DOWN-01 hiç başarılı yedek almamış -> bayat sayılır
    assert m[("nabs_assets_backup_stale_total", ())] >= 1


def test_risk_and_advisories():
    m = _scrape()
    assert m[("nabs_asset_risk_score", (("hostname", "BM-UP-01"),))] == 72
    assert m[("nabs_advisories_open", (("severity", "CRITICAL"),))] >= 1


def test_collector_survives_db_failure(monkeypatch):
    """Şema hazır değilken (migration öncesi) collect() uygulamayı
    düşürmemeli — kayıt anındaki çökmenin regresyon testi."""
    import app.core.business_metrics as bm

    def boom(self):
        raise RuntimeError("column assets.is_reachable does not exist")

    monkeypatch.setattr(bm.NabsBusinessCollector, "_collect_from_db", boom)
    assert list(bm.NabsBusinessCollector().collect()) == []
