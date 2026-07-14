"""Admin kullanıcı yönetimi + sistem durumu uçları (prod öncesi doğrulama)."""
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
    for u, r in [("um2_admin", "admin"), ("um2_admin2", "admin"), ("um2_viewer", "viewer")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _uid(username):
    return [u for u in client.get("/api/v1/users", headers=_token("um2_admin")).json()
            if u["username"] == username][0]["id"]


def test_list_users_admin_only():
    assert client.get("/api/v1/users", headers=_token("um2_viewer")).status_code == 403
    r = client.get("/api/v1/users", headers=_token("um2_admin"))
    assert r.status_code == 200 and any(u["username"] == "um2_viewer" for u in r.json())


def test_change_role_and_activate():
    vid = _uid("um2_viewer")
    r = client.patch(f"/api/v1/users/{vid}", headers=_token("um2_admin"),
                     json={"role": "operator"})
    assert r.status_code == 200 and r.json()["role"] == "operator"
    r = client.patch(f"/api/v1/users/{vid}", headers=_token("um2_admin"),
                     json={"is_active": False})
    assert r.json()["is_active"] is False
    # geri al
    client.patch(f"/api/v1/users/{vid}", headers=_token("um2_admin"),
                 json={"role": "viewer", "is_active": True})


def test_reset_password_then_login():
    vid = _uid("um2_viewer")
    r = client.post(f"/api/v1/users/{vid}/reset-password", headers=_token("um2_admin"),
                    json={"new_password": "YeniParola1!"})
    assert r.status_code == 200
    login = client.post("/api/v1/auth/token",
                        data={"username": "um2_viewer", "password": "YeniParola1!"})
    assert login.status_code == 200


def test_cannot_deactivate_self():
    aid = _uid("um2_admin")
    r = client.patch(f"/api/v1/users/{aid}", headers=_token("um2_admin"),
                     json={"is_active": False})
    assert r.status_code == 400


def test_cannot_remove_last_admin(monkeypatch):
    # Paylaşılan test DB'sinde birden çok admin olduğundan "son admin"i
    # deterministik test etmek için sayacı 0'a zorluyoruz (koruma tetiklenmeli).
    import app.api.v1.endpoints.users as users_mod
    monkeypatch.setattr(users_mod, "_active_admin_count", lambda db, exclude_id=None: 0)
    a2 = _uid("um2_admin2")
    r = client.patch(f"/api/v1/users/{a2}", headers=_token("um2_admin"),
                     json={"role": "viewer"})
    assert r.status_code == 400  # son aktif admin düşürülemez
    r = client.delete(f"/api/v1/users/{a2}", headers=_token("um2_admin"))
    assert r.status_code == 400  # son aktif admin silinemez


def test_secret_status_shows_env_source():
    r = client.get("/api/v1/system/secret-status", headers=_token("um2_admin"))
    assert r.status_code == 200
    body = r.json()
    assert body["vault_enabled"] is False  # testte Vault yok
    names = {s["name"]: s for s in body["secrets"]}
    assert names["NABS_MASTER_KEY"]["is_set"] is True
    assert names["NABS_MASTER_KEY"]["source"] == "env"


def test_tls_status_requires_target():
    r = client.get("/api/v1/system/tls-status", headers=_token("um2_admin"))
    assert r.status_code == 400  # host yok ve NABS_DOMAIN yok


def test_tls_status_unreachable_returns_reachable_false():
    r = client.get("/api/v1/system/tls-status?host=127.0.0.1&port=1",
                   headers=_token("um2_admin"))
    assert r.status_code == 200 and r.json()["reachable"] is False


def test_ldap_test_reports_not_configured():
    r = client.post("/api/v1/system/ldap-test", headers=_token("um2_admin"), json={})
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "yapılandırılmamış" in r.json()["reason"]
