"""SQLAlchemy ORM models mirroring db/init.sql (Spec Section 3 + 8)."""
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, Uuid, func,
)
from sqlalchemy.orm import Mapped, mapped_column

# Uuid(as_uuid=False): Postgres'in native UUID kolonundan da SQLite'ın TEXT
# kolonundan da her zaman str döner. Aksi halde Postgres'te uuid.UUID objesi
# Pydantic'in str beklentisine çarpar -> ResponseValidationError (500).
_UUID_STR = Uuid(as_uuid=False)

from app.core.database import Base


class NetworkZone(Base):
    __tablename__ = "network_zones"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("network_zones.id", ondelete="CASCADE"))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[str] = mapped_column(_UUID_STR, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    secret_encrypted: Mapped[str | None] = mapped_column(Text)
    ssh_key_private: Mapped[str | None] = mapped_column(Text)
    passphrase_encrypted: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (CheckConstraint("risk_score >= 0 AND risk_score <= 100"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[str] = mapped_column(_UUID_STR, unique=True, default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    vendor: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(64))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("network_zones.id", ondelete="SET NULL"))
    credential_id: Mapped[str | None] = mapped_column(
        _UUID_STR, ForeignKey("credentials.id", ondelete="SET NULL"))
    backup_method: Mapped[str] = mapped_column(String(32), nullable=False)
    cron_schedule: Mapped[str] = mapped_column(String(64), default="0 2 * * *")
    risk_score: Mapped[int] = mapped_column(Integer, default=100)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Erişilebilirlik (up/down): 5 dk'da bir TCP probe ile güncellenir
    is_reachable: Mapped[bool | None] = mapped_column(Boolean)
    last_reachability_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_successful_backup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Config drift: golden referanstan sapma durumu
    has_drift: Mapped[bool] = mapped_column(Boolean, default=False)
    last_drift_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class BackupHistory(Base):
    __tablename__ = "backup_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    method_used: Mapped[str] = mapped_column(String(32), nullable=False)
    commit_hash: Mapped[str | None] = mapped_column(String(64))
    config_size_bytes: Mapped[int | None] = mapped_column(Integer)
    lines_added: Mapped[int] = mapped_column(Integer, default=0)
    lines_deleted: Mapped[int] = mapped_column(Integer, default=0)
    error_log: Mapped[str | None] = mapped_column(Text)
    triggered_by: Mapped[str] = mapped_column(String(128), nullable=False)


class SecurityAdvisory(Base):
    __tablename__ = "security_advisories"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_silenced: Mapped[bool] = mapped_column(Boolean, default=False)
    finding_source: Mapped[str] = mapped_column(String(64), nullable=False)


class RemediationAction(Base):
    __tablename__ = "remediation_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_advisories.id", ondelete="CASCADE")
    )
    generated_commands: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING_APPROVAL")
    requested_by: Mapped[str | None] = mapped_column(String(128))
    approved_by: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    maintenance_window: Mapped[str | None] = mapped_column(String(255))  # TSTZRANGE in Postgres
    rollback_commands: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text)  # Faz 5: TOTP MFA (AKTİF)
    # Kayıt sırasında üretilen ama henüz doğrulanmamış secret. MFA yalnızca
    # kullanıcı geçerli bir kod girip aktifleştirdiğinde zorunlu olur.
    mfa_pending_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiKey(Base):
    """Faz 6+: harici entegrasyonlar için API anahtarı. Anahtarın kendisi
    saklanmaz; yalnızca SHA-256 özeti tutulur (parola gibi). İstemci
    X-API-Key başlığıyla kimliklenir."""
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # gösterim için ilk 8 char
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AppSetting(Base):
    """Uygulama-içi operasyonel ayarlar (admin panelinden yönetilir).
    Bootstrap secret'ları (master key, JWT, DB) BURADA DEĞİL — onlar env/Vault'ta.
    Değer yoksa env değişkenine, o da yoksa registry default'una düşülür."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    """Faz 2 Sprint 15-16: immutable kullanıcı denetim izi.
    Append-only: uygulama katmanında UPDATE/DELETE yolu yoktur."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ConfigBaseline(Base):
    """Bir cihazın 'golden' (onaylanmış referans) konfigürasyonu. Drift
    tespiti mevcut config'i bu referansla karşılaştırır. Cihaz başına tek
    baseline (asset_id unique)."""
    __tablename__ = "config_baselines"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), unique=True)
    commit_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    set_by: Mapped[str | None] = mapped_column(String(128))
    set_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TopologyLink(Base):
    """LLDP/CDP komşuluk kenarı — ağ haritasının bir bağlantısı.
    source_device envanterdeki cihaz, remote_device komşu (envanterde
    olmayabilir). Toplama her çalıştığında ilgili kaynak için tazelenir."""
    __tablename__ = "topology_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_device: Mapped[str] = mapped_column(String(255), nullable=False)
    remote_device: Mapped[str] = mapped_column(String(255), nullable=False)
    remote_ip: Mapped[str | None] = mapped_column(String(64))
    local_interface: Mapped[str | None] = mapped_column(String(128))
    remote_interface: Mapped[str | None] = mapped_column(String(128))
    platform: Mapped[str | None] = mapped_column(String(255))
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # CDP/LLDP
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DiscoveredHost(Base):
    """L2 keşifle (ARP + MAC tablosu + komşuluk) bulunan uç cihaz. Envanterde
    olmayabilir; network admin inceleyip onboard edebilir. (mac, seen_on_device)
    çifti benzersiz — aynı MAC farklı switch'lerde görülebilir."""
    __tablename__ = "discovered_hosts"
    __table_args__ = (UniqueConstraint("mac", "seen_on_device", name="uq_disc_mac_device"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    oui_vendor: Mapped[str | None] = mapped_column(String(64))
    seen_on_device: Mapped[str] = mapped_column(String(255), nullable=False)
    seen_on_interface: Mapped[str | None] = mapped_column(String(128))
    vlan: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # ARP/MAC_TABLE/LLDP/CDP
    is_onboarded: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RagChunk(Base):
    """Faz 4 Sprint 29-30: RAG bağlamı (CIS benchmark parçaları).
    Postgres'te pgvector kolonu; taşınabilirlik için embedding JSON metni
    olarak da saklanır (SQLite fallback)."""
    __tablename__ = "rag_chunks"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)
    embedding_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
