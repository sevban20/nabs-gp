"""Harici entegrasyon için API anahtarı yönetimi (admin).

Ham anahtar yalnızca üretim anında bir kez döner; DB'de sadece SHA-256
özeti saklanır. İstemciler X-API-Key başlığıyla kimliklenir."""
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import hash_api_key, require_role
from app.core.database import get_db
from app.models.models import ApiKey

router = APIRouter()


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    role: str = Field(default="viewer", pattern="^(viewer|operator|approver|admin)$")


@router.get("/apikeys")
def list_api_keys(db: Session = Depends(get_db),
                  _admin: dict = Depends(require_role("admin"))):
    rows = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
    return [{
        "id": r.id, "name": r.name, "prefix": r.prefix, "role": r.role,
        "is_active": r.is_active,
        "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]


@router.post("/apikeys", status_code=201)
def create_api_key(payload: ApiKeyCreate, db: Session = Depends(get_db),
                   admin: dict = Depends(require_role("admin"))):
    raw = "nabs_" + secrets.token_urlsafe(32)
    row = ApiKey(name=payload.name, prefix=raw[:12], key_hash=hash_api_key(raw),
                 role=payload.role, created_by=admin["sub"])
    db.add(row)
    db.commit()
    db.refresh(row)
    # Ham anahtar SADECE burada döner; bir daha gösterilemez.
    return {"id": row.id, "name": row.name, "role": row.role, "api_key": raw,
            "note": "Bu anahtarı güvenli saklayın; bir daha gösterilmeyecek."}


@router.delete("/apikeys/{key_id}", status_code=204)
def revoke_api_key(key_id: int, db: Session = Depends(get_db),
                   _admin: dict = Depends(require_role("admin"))):
    row = db.get(ApiKey, key_id)
    if not row:
        raise HTTPException(status_code=404, detail="API anahtarı bulunamadı.")
    row.is_active = False
    db.commit()
