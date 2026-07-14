"""İşlem geçmişi / kuyruk görünürlüğü: backup tetikleyince anında QUEUED
kaydı oluşmalı ve /jobs uçlarında görünmeli."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import Asset, BackupHistory, User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("jb_op", "operator"), ("jb_viewer", "viewer")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    db.commit()
    db.close()
    yield


@pytest.fixture(autouse=True)
def no_celery(monkeypatch):
    import app.workers.tasks as tasks
    for t in ("run_active_backup", "run_security_analysis", "recompute_asset_risk"):
        monkeypatch.setattr(getattr(tasks, t), "delay", lambda *a, **k: None)


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_ssh_asset(hostname, ip):
    db = SessionLocal()
    a = db.query(Asset).filter(Asset.hostname == hostname).first()
    if not a:
        a = Asset(hostname=hostname, ip_address=ip, vendor="cisco_ios",
                  backup_method="ACTIVE_SSH")
        db.add(a)
        db.commit()
    aid = a.id
    db.close()
    return aid


def test_trigger_backup_creates_queued_job():
    aid = _make_ssh_asset("JOB-SW-1", "10.80.0.1")
    r = client.post(f"/api/v1/assets/{aid}/backup", headers=_token("jb_op"))
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "queued" and "job_id" in body

    # QUEUED kaydı DB'de ve /jobs/recent'ta görünmeli
    db = SessionLocal()
    h = db.get(BackupHistory, body["job_id"])
    assert h.status == "QUEUED" and h.asset_id == aid
    db.close()

    jobs = client.get("/api/v1/jobs/recent", headers=_token("jb_viewer")).json()
    assert any(j["id"] == body["job_id"] and j["hostname"] == "JOB-SW-1" for j in jobs)


def test_jobs_counts_reflect_queued():
    aid = _make_ssh_asset("JOB-SW-2", "10.80.0.2")
    client.post(f"/api/v1/assets/{aid}/backup", headers=_token("jb_op"))
    counts = client.get("/api/v1/jobs/counts", headers=_token("jb_viewer")).json()
    assert counts["queued"] >= 1


def test_jobs_status_filter():
    r = client.get("/api/v1/jobs/recent?status=QUEUED", headers=_token("jb_viewer"))
    assert r.status_code == 200
    assert all(j["status"] == "QUEUED" for j in r.json())


def test_task_updates_queued_row_not_duplicate(monkeypatch):
    """run_active_backup, history_id verilince yeni satır açmayıp mevcut
    QUEUED kaydını günceller (çift kayıt olmaz)."""
    import app.workers.tasks as tasks

    aid = _make_ssh_asset("JOB-SW-3", "10.80.0.3")
    db = SessionLocal()
    h = BackupHistory(asset_id=aid, status="QUEUED", method_used="ACTIVE_SSH",
                      triggered_by="TEST")
    db.add(h)
    db.commit()
    hid = h.id
    before = db.query(BackupHistory).filter(BackupHistory.asset_id == aid).count()
    db.close()

    # SSH çekimini mock'la (gerçek cihaz yok)
    monkeypatch.setattr(tasks, "_fetch_config_over_ssh",
                        lambda **k: "hostname JOB-SW-3\nip ssh version 2\n")
    # kimlik bilgisi ekle
    from app.core.crypto import get_crypto
    from app.models.models import Credential
    db = SessionLocal()
    cred = Credential(name="c", username="u",
                      password_encrypted=get_crypto().encrypt("p"))
    db.add(cred)
    db.commit()
    asset = db.get(Asset, aid)
    asset.credential_id = cred.id
    db.commit()
    db.close()

    tasks.run_active_backup.run(aid, "TEST", hid)

    db = SessionLocal()
    after = db.query(BackupHistory).filter(BackupHistory.asset_id == aid).count()
    h = db.get(BackupHistory, hid)
    db.close()
    assert after == before  # yeni satır açılmadı
    assert h.status == "SUCCESS"
