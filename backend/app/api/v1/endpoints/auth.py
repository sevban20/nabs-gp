"""Auth uçları: token (lokal + opsiyonel LDAP + opsiyonel TOTP MFA),
kullanıcı yönetimi (admin) ve MFA kaydı (Faz 5 Sprint 39-40)."""
import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.auth import (
    create_access_token, get_current_user, hash_password, require_role, verify_password,
)
from app.core.crypto import get_crypto, get_crypto_or_http
from app.core.database import get_db
from app.core.ldap_auth import ldap_authenticate, ldap_enabled
from app.core.ratelimit import check_rate_limit
from app.models.models import User
from app.schemas.schemas import Token, UserCreate

router = APIRouter()


def _rate_limits() -> tuple[int, int]:
    """Login sınırı — admin ayarından (DB→env→default) canlı okunur."""
    from app.core.settings_service import get_int
    return get_int("LOGIN_RATE_LIMIT", 10), get_int("LOGIN_RATE_WINDOW", 300)


def _verify_totp(user: User, otp: str | None) -> bool:
    if not user.mfa_secret_encrypted:
        return True  # MFA bu kullanıcı için etkin değil
    if not otp:
        return False
    import pyotp
    secret = get_crypto().decrypt(user.mfa_secret_encrypted)
    return pyotp.TOTP(secret).verify(otp, valid_window=1)


@router.post("/auth/token", response_model=Token)
def login(request: Request, username: str = Form(...), password: str = Form(...),
          otp: str | None = Form(None), db: Session = Depends(get_db)):
    # IP + kullanıcı bazlı brute-force sınırı (admin ayarından canlı)
    max_attempts, window = _rate_limits()
    client_ip = request.client.host if request.client else "unknown"
    for key in (f"login:ip:{client_ip}", f"login:user:{username}"):
        if not check_rate_limit(key, max_attempts, window):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Çok fazla giriş denemesi. Lütfen birkaç dakika sonra tekrar deneyin.")

    user = db.query(User).filter(User.username == username).first()

    # 1) Lokal doğrulama
    if user and user.is_active and verify_password(password, user.password_hash):
        if not _verify_totp(user, otp):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="MFA kodu gerekli veya geçersiz.")
        return Token(access_token=create_access_token(user.username, user.role))

    # 2) Opsiyonel LDAP katmanı (Faz-1 JWT temeli üzerine; Spec Bölüm 7)
    if ldap_enabled():
        role = ldap_authenticate(username, password)
        if role:
            if user is None:  # ilk LDAP girişinde yerel gölge kayıt
                user = User(username=username,
                            password_hash=hash_password("!ldap-managed!"), role=role)
                db.add(user)
                db.commit()
            return Token(access_token=create_access_token(username, user.role))

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Incorrect username or password")


@router.post("/auth/mfa/enroll")
def enroll_mfa(current: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """TOTP MFA kaydı: secret üretir, şifreli saklar, provisioning URI döner."""
    import pyotp
    user = db.query(User).filter(User.username == current["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = get_crypto_or_http().encrypt(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="NABS-GP")
    return {"otpauth_uri": uri, "secret": secret,
            "note": "Secret'ı authenticator uygulamanıza ekleyin; bir daha gösterilmez."}


@router.post("/auth/users", status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                _admin: dict = Depends(require_role("admin"))):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already exists.")
    user = User(username=payload.username,
                password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}
