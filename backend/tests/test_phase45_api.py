"""Faz 2/4/5 API testleri: audit izi, MFA, keşif ucu, PDF ucu."""
import re
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import AuditLog, User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for username, role in [("p45_viewer", "viewer"), ("p45_op", "operator"),
                           ("p45_admin", "admin"), ("p45_mfa", "operator"),
                           ("p45_mfa2", "operator")]:
        if not db.query(User).filter(User.username == username).first():
            db.add(User(username=username, password_hash=hash_password("Passw0rd!x"), role=role))
    db.commit()
    db.close()
    yield


def _token(username: str) -> dict:
    r = client.post("/api/v1/auth/token",
                    data={"username": username, "password": "Passw0rd!x"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_write_requests_are_audited():
    before = _count_audit()
    client.post("/api/v1/assets", headers=_token("p45_viewer"), json={})  # 403/422 fark etmez
    assert _count_audit() > before
    db = SessionLocal()
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    db.close()
    assert last.username == "p45_viewer"
    assert last.method == "POST"


def _count_audit() -> int:
    db = SessionLocal()
    n = db.query(AuditLog).count()
    db.close()
    return n


def test_mfa_two_step_enrollment_does_not_lock_out():
    """MFA kaydı İKİ ADIMLIDIR ve doğrulanana kadar zorunlu OLMAZ.

    Regresyon koruması: eski davranışta enroll çağrısı MFA'yı anında zorunlu
    kılıyordu. Kullanıcı secret'ı authenticator'a ekleyemezse (QR yok, secret
    yanlış alana yapıştırıldı vb.) hesap kalıcı olarak kilitleniyordu.
    """
    import pyotp
    headers = _token("p45_mfa")
    creds = {"username": "p45_mfa", "password": "Passw0rd!x"}

    # 1) Kayıt başlatılır: secret + QR döner, durum 'pending'
    r = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert r.status_code == 200
    body = r.json()
    secret = body["secret"]
    assert body["status"] == "pending"
    assert len(secret) >= 16                      # authenticator'lar kısa secret'ı reddeder
    assert re.fullmatch(r"[A-Z2-7]+=*", secret)   # geçerli base32
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert body["secret_grouped"].replace(" ", "") == secret

    # 2) KRİTİK: doğrulanmadan giriş HÂLÂ çalışır — kilitlenme yok
    assert client.post("/api/v1/auth/token", data=creds).status_code == 200

    # 3) Yanlış kod aktifleştirmez
    assert client.post("/api/v1/auth/mfa/activate", headers=headers,
                       data={"otp": "000000"}).status_code == 400
    assert client.post("/api/v1/auth/token", data=creds).status_code == 200

    # 4) Doğru kod ile aktifleşir
    otp = pyotp.TOTP(secret).now()
    assert client.post("/api/v1/auth/mfa/activate", headers=headers,
                       data={"otp": otp}).status_code == 200

    # 5) Artık OTP zorunlu
    assert client.post("/api/v1/auth/token", data=creds).status_code == 401
    r = client.post("/api/v1/auth/token",
                    data={**creds, "otp": pyotp.TOTP(secret).now()})
    assert r.status_code == 200

    # 6) Geçerli kodla kapatılabilir; sonrasında OTP istenmez
    h2 = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.post("/api/v1/auth/mfa/disable", headers=h2,
                       data={"otp": pyotp.TOTP(secret).now()}).status_code == 200
    assert client.post("/api/v1/auth/token", data=creds).status_code == 200


def test_discovery_rejects_bad_and_huge_cidr():
    headers = _token("p45_op")
    assert client.post("/api/v1/discovery/scan", headers=headers,
                       json={"cidr": "not-a-cidr"}).status_code == 400
    assert client.post("/api/v1/discovery/scan", headers=headers,
                       json={"cidr": "10.0.0.0/8"}).status_code == 400


def test_discovery_requires_operator():
    r = client.post("/api/v1/discovery/scan", headers=_token("p45_viewer"),
                    json={"cidr": "192.0.2.0/30"})
    assert r.status_code == 403


def test_risk_report_pdf_endpoint():
    r = client.get("/api/v1/reports/risk.pdf", headers=_token("p45_viewer"))
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")


def test_health_reports_metrics_flag():
    r = client.get("/health")
    assert r.status_code == 200
    assert "metrics" in r.json()


def test_login_signals_mfa_requirement_to_client():
    """MFA gerektiğinde istemcinin OTP alanını açabilmesi için 401 yanıtı
    X-MFA-Required başlığını taşımalı ve detail mesajı korunmalı.

    Regresyon koruması: arayüz sunucunun mesajını atıp sabit "parola hatalı"
    gösteriyordu; OTP alanı hiç açılmıyor ve MFA'lı kullanıcı giremiyordu.
    """
    import pyotp
    headers = _token("p45_mfa2")
    creds = {"username": "p45_mfa2", "password": "Passw0rd!x"}

    secret = client.post("/api/v1/auth/mfa/enroll", headers=headers).json()["secret"]
    client.post("/api/v1/auth/mfa/activate", headers=headers,
                data={"otp": pyotp.TOTP(secret).now()})

    r = client.post("/api/v1/auth/token", data=creds)
    assert r.status_code == 401
    assert r.headers.get("X-MFA-Required") == "1"
    assert "MFA" in r.json()["detail"]

    # Yanlış parola MFA işareti TAŞIMAMALI (aksi hâlde istemci gereksiz OTP ister)
    r2 = client.post("/api/v1/auth/token",
                     data={"username": "p45_mfa2", "password": "yanlis"})
    assert r2.status_code == 401
    assert r2.headers.get("X-MFA-Required") is None


def test_mfa_enroll_is_idempotent_while_pending():
    """Beklemede kayıt varken enroll AYNI secret'ı döndürmeli.
    Aksi hâlde kullanıcının okuttuğu QR sessizce geçersizleşir."""
    headers = _token("p45_op")
    first = client.post("/api/v1/auth/mfa/enroll", headers=headers).json()
    second = client.post("/api/v1/auth/mfa/enroll", headers=headers).json()
    assert first["secret"] == second["secret"]
    assert second["status"] == "pending"
