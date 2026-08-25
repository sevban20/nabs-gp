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


def _qr_svg(data: str) -> str | None:
    """otpauth URI'sini QR olarak SVG döndürür. Kütüphane yoksa None —
    arayüz o durumda secret'ı elle girilecek şekilde gösterir."""
    try:
        import io  # noqa: PLC0415

        import qrcode  # noqa: PLC0415
        import qrcode.image.svg  # noqa: PLC0415

        img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


@router.post("/auth/mfa/enroll")
def enroll_mfa(current: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """TOTP MFA kaydını BAŞLATIR — henüz zorunlu kılmaz.

    Secret 'pending' olarak saklanır; kullanıcı /auth/mfa/activate ile geçerli
    bir kod girene kadar giriş akışı değişmez. Aksi hâlde authenticator'a
    ekleme adımı başarısız olduğunda hesap kilitlenir (yaşanmış bir vaka).
    """
    import pyotp
    user = db.query(User).filter(User.username == current["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.mfa_secret_encrypted:
        raise HTTPException(status_code=409, detail="MFA bu hesapta zaten aktif.")

    secret = pyotp.random_base32()
    user.mfa_pending_secret_encrypted = get_crypto_or_http().encrypt(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="NABS-GP")
    return {
        "otpauth_uri": uri,
        "secret": secret,
        # 4'erli gruplar: elle girişte okunabilir olsun
        "secret_grouped": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
        "qr_svg": _qr_svg(uri),
        "status": "pending",
        "note": ("QR'ı okutun ya da secret'ı elle girin, sonra uygulamadaki 6 haneli "
                 "kodu doğrulayın. Doğrulanana kadar MFA zorunlu olmaz."),
    }


@router.post("/auth/mfa/activate")
def activate_mfa(otp: str = Form(...), current: dict = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    """Bekleyen secret'ı doğrular ve MFA'yı aktifleştirir."""
    import pyotp
    user = db.query(User).filter(User.username == current["sub"]).first()
    if not user or not user.mfa_pending_secret_encrypted:
        raise HTTPException(status_code=400, detail="Bekleyen bir MFA kaydı yok.")

    secret = get_crypto().decrypt(user.mfa_pending_secret_encrypted)
    if not pyotp.TOTP(secret).verify(otp, valid_window=1):
        raise HTTPException(status_code=400,
                            detail="Kod doğrulanamadı. Saat senkronunu ve kodu kontrol edin.")

    user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
    user.mfa_pending_secret_encrypted = None
    db.commit()
    return {"status": "active", "detail": "MFA etkinleştirildi."}


@router.post("/auth/mfa/disable")
def disable_mfa(otp: str = Form(...), current: dict = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """Kendi hesabında MFA'yı kapatır — geçerli bir kod ister."""
    import pyotp
    user = db.query(User).filter(User.username == current["sub"]).first()
    if not user or not user.mfa_secret_encrypted:
        raise HTTPException(status_code=400, detail="MFA bu hesapta aktif değil.")
    secret = get_crypto().decrypt(user.mfa_secret_encrypted)
    if not pyotp.TOTP(secret).verify(otp, valid_window=1):
        raise HTTPException(status_code=400, detail="Kod doğrulanamadı.")
    user.mfa_secret_encrypted = None
    user.mfa_pending_secret_encrypted = None
    db.commit()
    return {"status": "disabled"}


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
