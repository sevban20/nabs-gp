"""NABS_MASTER_KEY eksikse credential ekleme 500 yerine anlaşılır 503
dönmeli (regresyon: fail-closed RuntimeError -> Unhandled 500)."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(User).filter(User.username == "cc_op").first():
        db.add(User(username="cc_op", password_hash=hash_password("Passw0rd!x"), role="operator"))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_credential_create_returns_503_when_master_key_missing(monkeypatch):
    import app.api.v1.endpoints.credentials as cred_mod

    def boom():
        raise RuntimeError("NABS_MASTER_KEY is not set in 'production' mode.")

    # get_crypto_or_http gerçek get_crypto'yu çağırır; onu patchleyelim
    monkeypatch.setattr("app.core.crypto.get_crypto", boom)
    r = client.post("/api/v1/credentials", headers=_token("cc_op"),
                    json={"name": "sw1", "username": "admin", "password": "S3cret!"})
    assert r.status_code == 503
    assert "NABS_MASTER_KEY" in r.json()["detail"]


def test_credential_create_ok_with_key():
    """Anahtar mevcutken (conftest ayarlar) normal 201."""
    r = client.post("/api/v1/credentials", headers=_token("cc_op"),
                    json={"name": "sw-ok", "username": "netadmin", "password": "S3cret!"})
    assert r.status_code == 201
    assert "S3cret!" not in r.text  # şifreli, sızmaz
