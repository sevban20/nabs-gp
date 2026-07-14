"""Config drift: pure compute_drift + baseline/drift uçları + advisory
yaşam döngüsü (drift oluş → advisory aç → düzel → advisory kapat)."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import Asset, SecurityAdvisory, User
from app.services.drift import compute_drift, content_hash, normalize
from app.services.git_engine import get_git_engine

client = TestClient(app)


# ---- pure fonksiyon testleri ----

def test_normalize_ignores_blank_and_trailing_ws():
    assert normalize("a  \n\n b \n") == ["a", " b"]


def test_compute_drift_in_sync():
    cfg = "hostname X\nip ssh version 2\n"
    r = compute_drift(cfg, cfg)
    assert r["in_sync"] is True and r["added"] == 0 and r["removed"] == 0


def test_compute_drift_detects_changes():
    golden = "hostname X\nip ssh version 2\nsnmp-server community public\n"
    current = "hostname X\nip ssh version 2\nno ip http server\n"
    r = compute_drift(golden, current)
    assert r["in_sync"] is False
    assert r["added"] >= 1 and r["removed"] >= 1
    assert "no ip http server" in r["diff"]


def test_content_hash_stable_under_whitespace():
    assert content_hash("a\nb\n") == content_hash("a  \n\nb\n")


# ---- API + advisory yaşam döngüsü ----

@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("df_op", "operator"), ("df_viewer", "viewer")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_asset(hostname, ip):
    db = SessionLocal()
    a = db.query(Asset).filter(Asset.hostname == hostname).first()
    if not a:
        a = Asset(hostname=hostname, ip_address=ip, vendor="cisco_ios",
                  backup_method="PASSIVE_SFTP")
        db.add(a)
        db.commit()
    aid = a.id
    db.close()
    return aid


def test_baseline_requires_backup_first():
    aid = _make_asset("DRIFT-NOBACKUP", "10.70.0.1")
    r = client.post(f"/api/v1/assets/{aid}/baseline", headers=_token("df_op"), json={})
    assert r.status_code == 400  # henüz config yok


def test_full_drift_lifecycle():
    from app.workers.tasks import evaluate_drift

    aid = _make_asset("DRIFT-SW-1", "10.70.0.2")
    engine_ = get_git_engine()
    # 1) ilk config commit'le
    engine_.save_and_commit("DRIFT-SW-1", "hostname DRIFT-SW-1\nip ssh version 2\n", "TEST")

    # 2) golden baz al
    r = client.post(f"/api/v1/assets/{aid}/baseline", headers=_token("df_op"),
                    json={"note": "ilk onaylı"})
    assert r.status_code == 201

    # 3) drift durumu = senkron
    d = client.get(f"/api/v1/assets/{aid}/drift", headers=_token("df_viewer")).json()
    assert d["has_baseline"] is True and d["in_sync"] is True

    # 4) config değiş → yeni commit → drift değerlendir
    engine_.save_and_commit("DRIFT-SW-1",
                            "hostname DRIFT-SW-1\nip ssh version 2\nsnmp-server community public\n",
                            "TEST")
    db = SessionLocal()
    asset = db.get(Asset, aid)
    evaluate_drift(db, asset, engine_.get_current_content("DRIFT-SW-1"))
    db.refresh(asset)
    assert asset.has_drift is True
    # drift advisory açılmış olmalı
    open_drift = db.query(SecurityAdvisory).filter(
        SecurityAdvisory.asset_id == aid, SecurityAdvisory.rule_id == "CONFIG-DRIFT",
        SecurityAdvisory.resolved_at.is_(None)).count()
    assert open_drift == 1
    db.close()

    # 5) drift endpoint diff gösterir
    d = client.get(f"/api/v1/assets/{aid}/drift", headers=_token("df_viewer")).json()
    assert d["in_sync"] is False and "snmp-server community public" in d["diff"]

    # 6) mevcudu golden al → senkron, advisory kapanır
    r = client.post(f"/api/v1/assets/{aid}/baseline", headers=_token("df_op"), json={})
    assert r.status_code == 201
    db = SessionLocal()
    asset = db.get(Asset, aid)
    assert asset.has_drift is False
    still_open = db.query(SecurityAdvisory).filter(
        SecurityAdvisory.asset_id == aid, SecurityAdvisory.rule_id == "CONFIG-DRIFT",
        SecurityAdvisory.resolved_at.is_(None)).count()
    assert still_open == 0
    db.close()


def test_drift_advisory_resolves_when_back_in_sync():
    from app.workers.tasks import evaluate_drift

    aid = _make_asset("DRIFT-SW-2", "10.70.0.3")
    engine_ = get_git_engine()
    engine_.save_and_commit("DRIFT-SW-2", "hostname DRIFT-SW-2\nline A\n", "TEST")
    client.post(f"/api/v1/assets/{aid}/baseline", headers=_token("df_op"), json={})

    db = SessionLocal()
    asset = db.get(Asset, aid)
    # sap
    evaluate_drift(db, asset, "hostname DRIFT-SW-2\nline A\nline B\n")
    db.refresh(asset)
    assert asset.has_drift is True
    # geri dön (golden ile aynı)
    evaluate_drift(db, asset, "hostname DRIFT-SW-2\nline A\n")
    db.refresh(asset)
    assert asset.has_drift is False
    db.close()


def test_fleet_drift_endpoint():
    r = client.get("/api/v1/compliance/drift", headers=_token("df_viewer"))
    assert r.status_code == 200
    assert "total_baselined" in r.json()
