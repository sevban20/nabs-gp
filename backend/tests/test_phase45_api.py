"""Faz 2/4/5 API testleri: audit izi, MFA, keşif ucu, PDF ucu."""
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
                           ("p45_admin", "admin"), ("p45_mfa", "operator")]:
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


def test_mfa_enroll_and_enforce():
    import pyotp
    headers = _token("p45_mfa")
    r = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert r.status_code == 200
    secret = r.json()["secret"]
    # OTP olmadan giriş reddedilir
    r = client.post("/api/v1/auth/token",
                    data={"username": "p45_mfa", "password": "Passw0rd!x"})
    assert r.status_code == 401
    # Doğru OTP ile giriş başarılı
    otp = pyotp.TOTP(secret).now()
    r = client.post("/api/v1/auth/token",
                    data={"username": "p45_mfa", "password": "Passw0rd!x", "otp": otp})
    assert r.status_code == 200


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
