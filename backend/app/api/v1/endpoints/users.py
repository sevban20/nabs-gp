"""Admin kullanıcı yönetimi: listeleme, rol/aktiflik değişimi, parola
sıfırlama, silme. Kilitlenmeyi önleyen korumalar: son aktif admin
düşürülemez/pasifleştirilemez/silinemez; admin kendini pasifleştiremez/silemez."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import hash_password, require_role
from app.core.database import get_db
from app.models.models import User

router = APIRouter()


class UserPatch(BaseModel):
    role: str | None = Field(default=None, pattern="^(viewer|operator|approver|admin)$")
    is_active: bool | None = None


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=8)


def _active_admin_count(db: Session, exclude_id: int | None = None) -> int:
    q = db.query(func.count(User.id)).filter(User.role == "admin", User.is_active.is_(True))
    if exclude_id is not None:
        q = q.filter(User.id != exclude_id)
    return q.scalar() or 0


@router.get("/users")
def list_users(db: Session = Depends(get_db), _admin: dict = Depends(require_role("admin"))):
    rows = db.query(User).order_by(User.username.asc()).all()
    return [{
        "id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active,
        "mfa_enabled": bool(u.mfa_secret_encrypted),
        "created_at": u.created_at.isoformat() if u.created_at else None,
    } for u in rows]


@router.post("/users/{user_id}/mfa/reset")
def reset_user_mfa(user_id: int, db: Session = Depends(get_db),
                   _admin: dict = Depends(require_role("admin"))):
    """Bir kullanıcının MFA kaydını siler (kilitlenme kurtarma).
    Tüm adminler kilitliyse: docker exec nabs-api python -m app.cli reset-mfa <kullanıcı>"""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
    user.mfa_secret_encrypted = None
    user.mfa_pending_secret_encrypted = None
    db.commit()
    return {"status": "reset", "username": user.username}


@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserPatch, db: Session = Depends(get_db),
                admin: dict = Depends(require_role("admin"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")

    # Son aktif admin'i düşürme/pasifleştirme koruması
    demoting = payload.role is not None and payload.role != "admin" and user.role == "admin"
    deactivating = payload.is_active is False and user.is_active
    if (demoting or deactivating) and user.role == "admin" and _active_admin_count(db, user.id) == 0:
        raise HTTPException(status_code=400,
                            detail="Son aktif admin düşürülemez/pasifleştirilemez.")
    if deactivating and user.username == admin["sub"]:
        raise HTTPException(status_code=400, detail="Kendinizi pasifleştiremezsiniz.")

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role,
            "is_active": user.is_active}


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, payload: PasswordReset, db: Session = Depends(get_db),
                   _admin: dict = Depends(require_role("admin"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"status": "ok", "username": user.username}


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db),
                admin: dict = Depends(require_role("admin"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")
    if user.username == admin["sub"]:
        raise HTTPException(status_code=400, detail="Kendinizi silemezsiniz.")
    if user.role == "admin" and user.is_active and _active_admin_count(db, user.id) == 0:
        raise HTTPException(status_code=400, detail="Son aktif admin silinemez.")
    db.delete(user)
    db.commit()
