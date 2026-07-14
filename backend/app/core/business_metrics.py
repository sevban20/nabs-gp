"""İş metrikleri: NABS-GP'ye özgü Prometheus metrikleri.

Custom collector her scrape'te (varsayılan 15 sn) DB'den güncel değerleri
okur — ayrı bir sayaç senkronizasyonu gerekmez, restart'ta sıfırlanma
sorunu olmaz. Tablolar küçük olduğu için sorgu maliyeti ihmal edilebilir.

Metrikler:
  nabs_assets_total                     — kayıtlı varlık sayısı
  nabs_assets_by_vendor{vendor}         — vendor kırılımı
  nabs_assets_reachable_total           — up (son TCP probe başarılı)
  nabs_assets_unreachable_total         — down
  nabs_asset_reachable{hostname,ip}     — cihaz bazında 1/0
  nabs_asset_risk_score{hostname}       — cihaz bazında risk (100=iyi)
  nabs_backups_24h_total{status}        — son 24 saat yedek sonuçları
  nabs_assets_backup_stale_total        — 24 saattir başarılı yedeği olmayan aktif varlık
  nabs_advisories_open{severity}        — açık bulgu sayısı
  nabs_remediations_by_status{status}   — onay akışı durumları
"""
from datetime import datetime, timedelta, timezone

from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector
from sqlalchemy import func


class NabsBusinessCollector(Collector):
    def collect(self):
        """DB hatası metrik toplama sırasında uygulamayı ASLA düşürmemeli:
        prometheus_client, register() anında da collect() çağırır — şema
        henüz migrate edilmemişse boş dön, hatayı logla."""
        import logging
        try:
            yield from self._collect_from_db()
        except Exception:
            logging.getLogger("nabs.metrics").exception(
                "İş metrikleri toplanamadı (DB hazır olmayabilir); boş dönülüyor")

    def _collect_from_db(self):
        from app.core.database import SessionLocal
        from app.models.models import Asset, BackupHistory, RemediationAction, SecurityAdvisory

        db = SessionLocal()
        try:
            assets = db.query(Asset).all()

            total = GaugeMetricFamily(
                "nabs_assets_total", "Kayıtlı varlık sayısı")
            total.add_metric([], len(assets))
            yield total

            by_vendor = GaugeMetricFamily(
                "nabs_assets_by_vendor", "Vendor kırılımı", labels=["vendor"])
            vendor_counts: dict[str, int] = {}
            for a in assets:
                vendor_counts[a.vendor] = vendor_counts.get(a.vendor, 0) + 1
            for vendor, count in vendor_counts.items():
                by_vendor.add_metric([vendor], count)
            yield by_vendor

            up = sum(1 for a in assets if a.is_reachable is True)
            down = sum(1 for a in assets if a.is_reachable is False)
            g_up = GaugeMetricFamily("nabs_assets_reachable_total",
                                     "Erişilebilir (up) varlıklar")
            g_up.add_metric([], up)
            yield g_up
            g_down = GaugeMetricFamily("nabs_assets_unreachable_total",
                                       "Erişilemeyen (down) varlıklar")
            g_down.add_metric([], down)
            yield g_down

            per_asset = GaugeMetricFamily(
                "nabs_asset_reachable", "Cihaz bazında up/down (1/0)",
                labels=["hostname", "ip"])
            risk = GaugeMetricFamily(
                "nabs_asset_risk_score", "Cihaz risk skoru (100=sıkılaştırılmış)",
                labels=["hostname"])
            for a in assets:
                if a.is_reachable is not None:
                    per_asset.add_metric([a.hostname, a.ip_address],
                                         1 if a.is_reachable else 0)
                risk.add_metric([a.hostname], a.risk_score)
            yield per_asset
            yield risk

            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            backups = GaugeMetricFamily(
                "nabs_backups_24h_total", "Son 24 saat yedekleme sonuçları",
                labels=["status"])
            rows = (db.query(BackupHistory.status, func.count())
                    .filter(BackupHistory.triggered_at >= cutoff)
                    .group_by(BackupHistory.status).all())
            seen = {status: count for status, count in rows}
            for status in ("SUCCESS", "FAILED", "TIMEOUT", "IN_PROGRESS"):
                backups.add_metric([status], seen.get(status, 0))
            yield backups

            stale = GaugeMetricFamily(
                "nabs_assets_backup_stale_total",
                "24 saattir başarılı yedeği olmayan aktif varlıklar")
            stale_count = sum(
                1 for a in assets if a.is_active and
                (a.last_successful_backup_at is None or
                 _as_utc(a.last_successful_backup_at) < cutoff))
            stale.add_metric([], stale_count)
            yield stale

            advisories = GaugeMetricFamily(
                "nabs_advisories_open", "Açık güvenlik bulguları",
                labels=["severity"])
            adv_rows = (db.query(SecurityAdvisory.severity, func.count())
                        .filter(SecurityAdvisory.resolved_at.is_(None))
                        .group_by(SecurityAdvisory.severity).all())
            adv_seen = {sev: count for sev, count in adv_rows}
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                advisories.add_metric([sev], adv_seen.get(sev, 0))
            yield advisories

            remediations = GaugeMetricFamily(
                "nabs_remediations_by_status", "Onay akışı durum dağılımı",
                labels=["status"])
            rem_rows = (db.query(RemediationAction.status, func.count())
                        .group_by(RemediationAction.status).all())
            for status, count in rem_rows:
                remediations.add_metric([status], count)
            yield remediations
        finally:
            db.close()


def _as_utc(dt: datetime) -> datetime:
    """SQLite naive datetime döndürebilir; karşılaştırma için UTC varsay."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def register_business_metrics() -> bool:
    from prometheus_client import REGISTRY
    try:
        REGISTRY.register(NabsBusinessCollector())
        return True
    except ValueError:
        return False  # zaten kayıtlı (test/reload durumları)
