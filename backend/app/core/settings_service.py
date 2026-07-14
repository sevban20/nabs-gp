"""Operasyonel ayar registry'si ve çözümleyici.

Öncelik: DB (admin override) → ortam değişkeni → registry default.
Sadece OPERASYONEL ayarlar buradadır; bootstrap secret'ları (NABS_MASTER_KEY,
JWT_SECRET, DATABASE_URL) asla — onlar env/Vault'ta kalır (tavuk-yumurta).

secret=True olan ayarlar API yanıtında maskelenir (değer yerine 'is_set').
"""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SettingDef:
    key: str
    group: str
    label: str
    type: str = "text"          # text | int | bool | enum
    secret: bool = False
    default: str | None = None
    options: tuple[str, ...] = ()
    help: str = ""


REGISTRY: list[SettingDef] = [
    # Bildirimler
    SettingDef("SLACK_WEBHOOK_URL", "Bildirimler", "Slack Webhook URL", secret=True,
               help="CRITICAL/HIGH bulgular buraya gönderilir. Boşsa Slack atlanır."),
    SettingDef("TEAMS_WEBHOOK_URL", "Bildirimler", "Teams Webhook URL", secret=True),
    SettingDef("SYSLOG_HOST", "Bildirimler", "Syslog sunucu"),
    SettingDef("SYSLOG_PORT", "Bildirimler", "Syslog port", type="int", default="514"),
    # Veri saklama
    SettingDef("DATA_RETENTION_DAYS", "Saklama", "Veri saklama (gün)", type="int",
               default="365", help="Bu süreden eski backup geçmişi/çözülmüş bulgular silinir."),
    SettingDef("DB_BACKUP_RETENTION_DAYS", "Saklama", "DB yedek saklama (gün)", type="int",
               default="14"),
    # Güvenlik
    SettingDef("LOGIN_RATE_LIMIT", "Güvenlik", "Login deneme limiti", type="int", default="10"),
    SettingDef("LOGIN_RATE_WINDOW", "Güvenlik", "Login pencere (sn)", type="int", default="300"),
    # Drift
    SettingDef("DRIFT_SEVERITY", "Drift", "Drift bulgu önemi", type="enum", default="MEDIUM",
               options=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
    # Yerel LLM
    SettingDef("OLLAMA_ENDPOINT", "AI (Ollama)", "Ollama generate URL",
               default="http://host.docker.internal:11434/api/generate"),
    SettingDef("OLLAMA_MODEL", "AI (Ollama)", "Ollama modeli", default="llama3:8b-instruct"),
    SettingDef("OLLAMA_EMBED_ENDPOINT", "AI (Ollama)", "Ollama embeddings URL",
               default="http://host.docker.internal:11434/api/embeddings"),
    SettingDef("OLLAMA_EMBED_MODEL", "AI (Ollama)", "Embedding modeli", default="nomic-embed-text"),
    # LDAP (opsiyonel)
    SettingDef("LDAP_URL", "LDAP", "LDAP sunucu URL", help="Boşsa LDAP devre dışı."),
    SettingDef("LDAP_BIND_TEMPLATE", "LDAP", "Bind şablonu",
               default="uid={username},ou=people,dc=corp,dc=local"),
    SettingDef("LDAP_DEFAULT_ROLE", "LDAP", "Varsayılan rol", type="enum",
               default="viewer", options=("viewer", "operator", "approver", "admin")),
]

_BY_KEY = {s.key: s for s in REGISTRY}


def get_setting(key: str, default: str | None = None) -> str | None:
    """DB override → ortam değişkeni → registry default → argüman default."""
    definition = _BY_KEY.get(key)
    # DB override
    try:
        from app.core.database import SessionLocal
        from app.models.models import AppSetting
        db = SessionLocal()
        try:
            row = db.get(AppSetting, key)
            if row and row.value not in (None, ""):
                return row.value
        finally:
            db.close()
    except Exception:
        pass  # DB henüz hazır değilse env/default'a düş
    env = os.getenv(key)
    if env not in (None, ""):
        return env
    if default is not None:
        return default
    return definition.default if definition else None


def get_int(key: str, default: int) -> int:
    val = get_setting(key)
    try:
        return int(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def list_settings_masked() -> list[dict]:
    """Registry + geçerli değerler; secret'lar maskeli (is_set)."""
    from app.core.database import SessionLocal
    from app.models.models import AppSetting
    db = SessionLocal()
    try:
        overrides = {r.key: r.value for r in db.query(AppSetting).all()}
    finally:
        db.close()

    out = []
    for s in REGISTRY:
        current = overrides.get(s.key)
        env_val = os.getenv(s.key)
        effective = current if current not in (None, "") else \
            (env_val if env_val not in (None, "") else s.default)
        item = {
            "key": s.key, "group": s.group, "label": s.label, "type": s.type,
            "secret": s.secret, "options": list(s.options), "help": s.help,
            "source": "db" if current not in (None, "") else
                      ("env" if env_val not in (None, "") else "default"),
        }
        if s.secret:
            item["is_set"] = effective not in (None, "")
            item["value"] = None
        else:
            item["value"] = effective
        out.append(item)
    return out


def update_settings(updates: dict, updated_by: str) -> int:
    """Ayarları toplu günceller. Bilinmeyen anahtar atlanır. Boş string =
    override'ı sil (env/default'a geri dön)."""
    from datetime import datetime, timezone

    from app.core.database import SessionLocal
    from app.models.models import AppSetting
    db = SessionLocal()
    changed = 0
    try:
        for key, value in updates.items():
            if key not in _BY_KEY:
                continue
            row = db.get(AppSetting, key)
            if value in (None, ""):
                if row:
                    db.delete(row)
                    changed += 1
                continue
            if row is None:
                row = AppSetting(key=key)
                db.add(row)
            row.value = str(value)
            row.updated_by = updated_by
            row.updated_at = datetime.now(timezone.utc)
            changed += 1
        db.commit()
        return changed
    finally:
        db.close()
