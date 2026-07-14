"""GUI'nin kullandığı kullanıcı yönetimi akışının API testleri
(500 regresyonuna karşı) + eski-DB migration testi."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app.core.auth import hash_password, verify_password
from app.core.database import Base, SessionLocal, engine
from app.core.migrations import run_startup_migrations
from app.main import app
from app.models.models import User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(User).filter(User.username == "um_admin").first():
        db.add(User(username="um_admin", password_hash=hash_password("Passw0rd!x"),
                    role="admin"))
        db.commit()
    db.close()
    yield


def _token(username: str) -> dict:
    r = client.post("/api/v1/auth/token",
                    data={"username": username, "password": "Passw0rd!x"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_admin_creates_user_then_user_logs_in():
    r = client.post("/api/v1/auth/users", headers=_token("um_admin"),
                    json={"username": "um_yeni", "password": "Passw0rd!x",
                          "role": "operator"})
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "operator"
    assert _token("um_yeni")  # yeni kullanıcı giriş yapabiliyor


def test_duplicate_username_409():
    headers = _token("um_admin")
    client.post("/api/v1/auth/users", headers=headers,
                json={"username": "um_dup", "password": "Passw0rd!x", "role": "viewer"})
    r = client.post("/api/v1/auth/users", headers=headers,
                    json={"username": "um_dup", "password": "Passw0rd!x", "role": "viewer"})
    assert r.status_code == 409


def test_weak_password_422():
    r = client.post("/api/v1/auth/users", headers=_token("um_admin"),
                    json={"username": "um_weak", "password": "kisa", "role": "viewer"})
    assert r.status_code == 422


def test_invalid_role_422():
    r = client.post("/api/v1/auth/users", headers=_token("um_admin"),
                    json={"username": "um_rol", "password": "Passw0rd!x", "role": "root"})
    assert r.status_code == 422


def test_bcrypt_hash_roundtrip_and_legacy_format():
    h = hash_password("Passw0rd!x")
    assert h.startswith("$2")  # passlib'in ürettiği eski hash'lerle aynı format
    assert verify_password("Passw0rd!x", h)
    assert not verify_password("yanlis", h)
    assert not verify_password("x", "bozuk-hash")


def test_migration_adds_missing_column(tmp_path):
    """Eski şemalı DB (mfa kolonu yok) yeni kodla açıldığında migration
    kolonu eklemeli — GUI'deki 500'ün kök nedeni buydu."""
    old = create_engine(f"sqlite:///{tmp_path}/old.db")
    with old.begin() as conn:
        conn.execute(text(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(100), "
            "password_hash TEXT, role VARCHAR(32), is_active BOOLEAN, "
            "created_at TIMESTAMP)"))
    run_startup_migrations(old)
    with old.connect() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(users)"))]
    assert "mfa_secret_encrypted" in cols
    run_startup_migrations(old)  # idempotent: ikinci çağrı hata üretmez
