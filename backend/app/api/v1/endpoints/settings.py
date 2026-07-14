"""Admin operasyonel ayar uçları. Bootstrap secret'ları (master key, JWT,
DB) burada YÖNETİLMEZ — onlar env/Vault'ta kalır."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.auth import require_role
from app.core.settings_service import list_settings_masked, update_settings

router = APIRouter()


class SettingsUpdate(BaseModel):
    values: dict[str, str | int | None]


@router.get("/settings")
def get_settings(_admin: dict = Depends(require_role("admin"))):
    """Tüm operasyonel ayarlar (secret'lar maskeli). Her ayarın kaynağı
    (db/env/default) ve grubu döner."""
    return {"settings": list_settings_masked()}


@router.put("/settings")
def put_settings(payload: SettingsUpdate, admin: dict = Depends(require_role("admin"))):
    """Ayarları toplu günceller. Boş değer = override'ı sil (env/default'a dön)."""
    changed = update_settings(payload.values, admin["sub"])
    return {"changed": changed}
