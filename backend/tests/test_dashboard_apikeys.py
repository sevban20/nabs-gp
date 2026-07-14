"""Dashboard özet endpoint'i ve API key entegrasyon akışı testleri."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import Asset, User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("dash_admin", "admin"), ("dash_viewer", "viewer")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    if not db.query(Asset).filter(Asset.hostname == "DASH-SW-1").first():
        db.add(Asset(hostname="DASH-SW-1", ip_address="10.50.0.1", vendor="cisco_ios",
                     backup_method="ACTIVE_SSH", is_reachable=True, risk_score=45))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_dashboard_summary_shape():
    r = client.get("/api/v1/dashboard/summary", headers=_token("dash_viewer"))
    assert r.status_code == 200
    d = r.json()
    for key in ("assets", "risk", "backups_24h", "advisories", "vendors",
                "top_risk_assets", "recent_advisories"):
        assert key in d
    assert d["assets"]["total"] >= 1
    assert d["assets"]["up"] >= 1


def test_apikey_create_requires_admin():
    assert client.post("/api/v1/apikeys", headers=_token("dash_viewer"),
                       json={"name": "x", "role": "viewer"}).status_code == 403


def test_apikey_full_lifecycle_and_auth():
    # 1) admin anahtar üretir
    r = client.post("/api/v1/apikeys", headers=_token("dash_admin"),
                    json={"name": "SIEM", "role": "viewer"})
    assert r.status_code == 201
    raw = r.json()["api_key"]
    assert raw.startswith("nabs_")

    # 2) anahtar JWT olmadan korumalı uca erişebilir
    r = client.get("/api/v1/assets", headers={"X-API-Key": raw})
    assert r.status_code == 200

    # 3) viewer rollü anahtar yazma yapamaz (rol sınırı korunur)
    r = client.post("/api/v1/assets", headers={"X-API-Key": raw},
                    json={"hostname": "x", "ip_address": "10.50.9.9",
                          "vendor": "cisco_ios", "backup_method": "ACTIVE_SSH"})
    assert r.status_code == 403

    # 4) geçersiz anahtar reddedilir
    assert client.get("/api/v1/assets", headers={"X-API-Key": "nabs_bogus"}).status_code == 401

    # 5) iptal sonrası çalışmaz
    key_id = [k for k in client.get("/api/v1/apikeys", headers=_token("dash_admin")).json()
              if k["name"] == "SIEM"][0]["id"]
    assert client.delete(f"/api/v1/apikeys/{key_id}",
                         headers=_token("dash_admin")).status_code == 204
    assert client.get("/api/v1/assets", headers={"X-API-Key": raw}).status_code == 401


def test_no_auth_still_rejected():
    assert client.get("/api/v1/assets").status_code == 401
