"""Admin operasyonel ayarlar: registry, DB override, secret maskeleme,
canlı etki (drift severity)."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.core.settings_service import get_setting, update_settings
from app.main import app
from app.models.models import User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("set_admin", "admin"), ("set_op", "operator")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_settings_requires_admin():
    assert client.get("/api/v1/settings", headers=_token("set_op")).status_code == 403


def test_settings_list_has_groups_and_masks_secrets():
    body = client.get("/api/v1/settings", headers=_token("set_admin")).json()
    items = {s["key"]: s for s in body["settings"]}
    assert "SLACK_WEBHOOK_URL" in items and items["SLACK_WEBHOOK_URL"]["secret"] is True
    # secret'lar value döndürmez, is_set döner
    assert "value" in items["SLACK_WEBHOOK_URL"] and items["SLACK_WEBHOOK_URL"]["value"] is None
    assert "is_set" in items["SLACK_WEBHOOK_URL"]
    # gruplar dolu
    assert items["DATA_RETENTION_DAYS"]["group"] == "Saklama"


def test_update_and_resolve_setting():
    r = client.put("/api/v1/settings", headers=_token("set_admin"),
                   json={"values": {"DRIFT_SEVERITY": "HIGH", "DATA_RETENTION_DAYS": "90"}})
    assert r.status_code == 200 and r.json()["changed"] == 2
    # DB override çözümleniyor
    assert get_setting("DRIFT_SEVERITY") == "HIGH"
    assert get_setting("DATA_RETENTION_DAYS") == "90"


def test_empty_value_clears_override():
    update_settings({"DRIFT_SEVERITY": "LOW"}, "tester")
    assert get_setting("DRIFT_SEVERITY") == "LOW"
    update_settings({"DRIFT_SEVERITY": ""}, "tester")  # sil → default'a dön
    assert get_setting("DRIFT_SEVERITY", "MEDIUM") in ("MEDIUM", None)


def test_unknown_key_ignored():
    n = update_settings({"NOT_A_REAL_KEY": "x"}, "tester")
    assert n == 0


def test_secret_masked_but_settable():
    client.put("/api/v1/settings", headers=_token("set_admin"),
               json={"values": {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/xxx"}})
    body = client.get("/api/v1/settings", headers=_token("set_admin")).json()
    slack = [s for s in body["settings"] if s["key"] == "SLACK_WEBHOOK_URL"][0]
    assert slack["value"] is None and slack["is_set"] is True and slack["source"] == "db"
    # dahili çözümleme gerçek değeri görür
    assert get_setting("SLACK_WEBHOOK_URL") == "https://hooks.slack.com/xxx"
