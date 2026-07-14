"""Config görüntüleme/indirme: /assets/{id}/config/content (son + tarihsel)."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import Asset, User
from app.services.git_engine import get_git_engine

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(User).filter(User.username == "cfg_viewer").first():
        db.add(User(username="cfg_viewer", password_hash=hash_password("Passw0rd!x"),
                    role="viewer"))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _asset(hostname, ip):
    db = SessionLocal()
    a = db.query(Asset).filter(Asset.hostname == hostname).first()
    if not a:
        a = Asset(hostname=hostname, ip_address=ip, vendor="cisco_ios",
                  backup_method="PASSIVE_SFTP")
        db.add(a); db.commit()
    aid = a.id
    db.close()
    return aid


def test_latest_and_historical_content():
    aid = _asset("CFG-SW-1", "10.90.0.1")
    engine_ = get_git_engine()
    c1 = engine_.save_and_commit("CFG-SW-1", "hostname CFG-SW-1\nline v1\n", "TEST")
    engine_.save_and_commit("CFG-SW-1", "hostname CFG-SW-1\nline v2\n", "TEST")

    # son sürüm
    r = client.get(f"/api/v1/assets/{aid}/config/content", headers=_token("cfg_viewer"))
    assert r.status_code == 200
    assert "line v2" in r.json()["content"]

    # tarihsel (ilk commit)
    r = client.get(f"/api/v1/assets/{aid}/config/content?commit={c1}",
                   headers=_token("cfg_viewer"))
    assert r.status_code == 200
    assert "line v1" in r.json()["content"] and "line v2" not in r.json()["content"]


def test_content_404_when_no_backup():
    aid = _asset("CFG-NONE", "10.90.0.2")
    r = client.get(f"/api/v1/assets/{aid}/config/content", headers=_token("cfg_viewer"))
    assert r.status_code == 404
