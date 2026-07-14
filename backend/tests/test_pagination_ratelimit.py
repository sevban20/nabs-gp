"""P1: sayfalama/arama, dashboard SQL agregasyonu ve login rate-limit."""
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
    for u, r in [("pg_admin", "admin"), ("pg_viewer", "viewer")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    # arama/filtre için çeşitli cihazlar
    seed = [
        ("PG-CORE-01", "10.60.0.1", "cisco_ios", True, 30),
        ("PG-ACCESS-02", "10.60.0.2", "aruba_aoscx", False, 95),
        ("PG-EDGE-03", "10.60.0.3", "huawei_vrp", True, 60),
    ]
    for h, ip, v, up, risk in seed:
        if not db.query(Asset).filter(Asset.hostname == h).first():
            db.add(Asset(hostname=h, ip_address=ip, vendor=v, backup_method="ACTIVE_SSH",
                         is_reachable=up, risk_score=risk))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_assets_pagination_headers():
    r = client.get("/api/v1/assets?limit=2", headers=_token("pg_viewer"))
    assert r.status_code == 200
    assert "x-total-count" in {k.lower() for k in r.headers}
    assert len(r.json()) <= 2


def test_assets_search_by_hostname():
    r = client.get("/api/v1/assets?q=CORE-01", headers=_token("pg_viewer"))
    hosts = [a["hostname"] for a in r.json()]
    assert "PG-CORE-01" in hosts
    assert "PG-ACCESS-02" not in hosts


def test_assets_status_filter():
    down = client.get("/api/v1/assets?status=down", headers=_token("pg_viewer")).json()
    assert all(a["is_reachable"] is False for a in down)
    risky = client.get("/api/v1/assets?status=risk", headers=_token("pg_viewer")).json()
    assert all(a["risk_score"] < 50 for a in risky)


def test_assets_limit_bounds():
    assert client.get("/api/v1/assets?limit=0", headers=_token("pg_viewer")).status_code == 422
    assert client.get("/api/v1/assets?limit=9999", headers=_token("pg_viewer")).status_code == 422


def test_dashboard_summary_still_works_with_sql_aggregation():
    d = client.get("/api/v1/dashboard/summary", headers=_token("pg_viewer")).json()
    assert d["assets"]["total"] >= 3
    assert d["assets"]["down"] >= 1
    assert d["risk"]["bands"]["good"] >= 1  # PG-ACCESS-02 risk 95
    assert d["risk"]["bands"]["bad"] >= 1   # PG-CORE-01 risk 30
    assert "aruba_aoscx" in d["vendors"]


def test_login_rate_limit_returns_429(monkeypatch):
    # Küçük eşikle hızlı tetikle (artık ayardan okunuyor)
    import app.api.v1.endpoints.auth as auth_mod
    monkeypatch.setattr(auth_mod, "_rate_limits", lambda: (3, 300))
    got_429 = False
    for _ in range(6):
        r = client.post("/api/v1/auth/token",
                        data={"username": "rl_user", "password": "wrong"})
        if r.status_code == 429:
            got_429 = True
            break
    assert got_429


def test_ratelimit_helper_unit():
    from app.core.ratelimit import check_rate_limit
    key = "unit-test-key-xyz"
    allowed = [check_rate_limit(key, 3, 60) for _ in range(5)]
    assert allowed[:3] == [True, True, True]
    assert allowed[3] is False and allowed[4] is False
