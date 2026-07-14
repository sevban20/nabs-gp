"""API Authentication & Authorization (Spec Section 7).

Baseline JWT scheme, mandatory from Phase 1. Role checks (viewer /
operator / approver / admin) are enforced at the dependency level,
not only in the UI. Fail-fast if JWT_SECRET is unset (Section 4.1
principle).
"""
from datetime import datetime, timedelta, timezone

import hashlib

import bcrypt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from app.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)

ROLE_HIERARCHY = {"viewer": 0, "operator": 1, "approver": 2, "admin": 3}


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()

# passlib yerine doğrudan bcrypt: passlib bakımsız ve bcrypt>=4.1 ile
# kırılıyor (500'lerin klasik nedeni). Eski passlib $2b$ hash'leri
# bcrypt.checkpw ile uyumludur, mevcut kullanıcılar etkilenmez.


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode())
    except ValueError:
        return False


def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def get_current_user(token: str = Depends(oauth2_scheme),
                     x_api_key: str | None = Header(default=None)) -> dict:
    """İki kimlik yöntemi: Bearer JWT (kullanıcı) veya X-API-Key (entegrasyon).
    Böylece harici sistemler de rol-korumalı uçları kullanabilir."""
    if x_api_key:
        principal = _resolve_api_key(x_api_key)
        if principal:
            return principal
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid API key")
    if token:
        try:
            return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid or expired token")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated")


def _resolve_api_key(raw_key: str) -> dict | None:
    from datetime import datetime, timezone

    from app.core.database import SessionLocal
    from app.models.models import ApiKey

    db = SessionLocal()
    try:
        row = db.query(ApiKey).filter(
            ApiKey.key_hash == hash_api_key(raw_key), ApiKey.is_active.is_(True)).first()
        if not row:
            return None
        row.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return {"sub": f"apikey:{row.name}", "role": row.role, "auth": "api_key"}
    finally:
        db.close()


def require_role(minimum_role: str):
    """Dependency factory: require_role('operator') rejects viewers."""

    def checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "viewer")
        if ROLE_HIERARCHY.get(user_role, -1) < ROLE_HIERARCHY[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum_role}' or higher.",
            )
        return user

    return checker
