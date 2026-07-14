"""API integration tests: JWT auth (Section 7), webhook security
(Section 5), remediation state machine (Section 8)."""
import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import SecurityAdvisory, User

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for username, role in [("viewer1", "viewer"), ("op1", "operator"),
                           ("op2", "operator"), ("appr1", "approver"),
                           ("admin1", "admin")]:
        if not db.query(User).filter(User.username == username).first():
            db.add(User(username=username, password_hash=hash_password("Passw0rd!x"), role=role))
    db.commit()
    db.close()
    yield


@pytest.fixture(autouse=True)
def no_celery(monkeypatch):
    """Tests never need a Redis broker."""
    import app.workers.tasks as tasks
    monkeypatch.setattr(tasks.run_security_analysis, "delay", lambda *a, **k: None)
    monkeypatch.setattr(tasks.recompute_asset_risk, "delay", lambda *a, **k: None)
    monkeypatch.setattr(tasks.run_active_backup, "delay", lambda *a, **k: None)


def _token(username: str) -> dict:
    r = client.post("/api/v1/auth/token",
                    data={"username": username, "password": "Passw0rd!x"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- Auth ---

def test_login_wrong_password_rejected():
    r = client.post("/api/v1/auth/token", data={"username": "op1", "password": "wrong"})
    assert r.status_code == 401


def test_assets_require_token():
    assert client.get("/api/v1/assets").status_code == 401


def test_viewer_cannot_create_asset():
    r = client.post("/api/v1/assets", headers=_token("viewer1"), json={
        "hostname": "x", "ip_address": "10.0.0.9",
        "vendor": "cisco_ios", "backup_method": "ACTIVE_SSH"})
    assert r.status_code == 403


def test_operator_asset_crud_and_viewer_read():
    r = client.post("/api/v1/assets", headers=_token("op1"), json={
        "hostname": "CORE-SW-01", "ip_address": "10.1.1.1",
        "vendor": "cisco_ios", "backup_method": "PASSIVE_SFTP"})
    assert r.status_code == 201
    assert r.json()["risk_score"] == 100
    r = client.get("/api/v1/assets", headers=_token("viewer1"))
    assert r.status_code == 200
    assert any(a["hostname"] == "CORE-SW-01" for a in r.json())


def test_credential_secrets_never_exposed():
    r = client.post("/api/v1/credentials", headers=_token("op1"), json={
        "name": "lab", "username": "netadmin", "password": "TopSecret1!"})
    assert r.status_code == 201
    body = r.json()
    assert "TopSecret1!" not in json.dumps(body)
    assert "password_encrypted" not in body


# --- Webhook (Section 5) ---

def _signed(payload: dict) -> tuple[bytes, str]:
    raw = json.dumps(payload).encode()
    sig = hmac.new(os.environ["SFTPGO_WEBHOOK_SECRET"].encode(), raw,
                   hashlib.sha256).hexdigest()
    return raw, sig


def test_webhook_rejects_bad_signature():
    raw, _ = _signed({"action": "upload", "username": "u", "path": "a", "target_path": "a"})
    r = client.post("/api/v1/webhook/sftpgo", content=raw,
                    headers={"x-sftpgo-signature": "deadbeef"})
    assert r.status_code == 401


def test_webhook_rejects_path_traversal():
    raw, sig = _signed({"action": "upload", "username": "u",
                        "path": "../../etc/passwd", "target_path": "dev.conf"})
    r = client.post("/api/v1/webhook/sftpgo", content=raw,
                    headers={"x-sftpgo-signature": sig})
    assert r.status_code == 400


def test_webhook_ignores_non_upload_action():
    raw, sig = _signed({"action": "delete", "username": "u",
                        "path": "x.conf", "target_path": "x.conf"})
    r = client.post("/api/v1/webhook/sftpgo", content=raw,
                    headers={"x-sftpgo-signature": sig})
    assert r.status_code == 200
    assert r.json()["status"] == "ignored_action"


def test_webhook_happy_path_sanitizes_and_commits():
    upload_root = Path(os.environ["SFTPGO_UPLOAD_ROOT"])
    (upload_root / "EDGE-01.conf").write_text(
        "hostname EDGE-01\nenable secret 5 $1$abcd$realhash\n")
    raw, sig = _signed({"action": "upload", "username": "sftpuser",
                        "path": "EDGE-01.conf", "target_path": "EDGE-01.conf"})
    r = client.post("/api/v1/webhook/sftpgo", content=raw,
                    headers={"x-sftpgo-signature": sig})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success" and body["device"] == "EDGE-01"
    committed = Path(os.environ["NABS_GIT_REPO_PATH"]) / "EDGE-01.conf"
    text = committed.read_text()
    assert "$1$abcd$realhash" not in text  # sanitized before commit
    assert "<MASKED_SECRET>" in text


# --- Remediation workflow (Section 8) ---

def _make_advisory(severity: str) -> int:
    db = SessionLocal()
    adv = SecurityAdvisory(rule_id="T-1", title="t", description="d",
                           severity=severity, finding_source="STATIC_RULE_ENGINE")
    db.add(adv)
    db.commit()
    adv_id = adv.id
    db.close()
    return adv_id


def test_approver_cannot_approve_own_request():
    adv_id = _make_advisory("HIGH")
    # approver-role user creates the request themselves
    db = SessionLocal()
    if not db.query(User).filter(User.username == "appr_self").first():
        db.add(User(username="appr_self", password_hash=hash_password("Passw0rd!x"),
                    role="approver"))
        db.commit()
    db.close()
    r = client.post("/api/v1/remediations", headers=_token("appr_self"),
                    json={"advisory_id": adv_id, "generated_commands": "no ip http server"})
    action_id = r.json()["id"]
    r = client.post(f"/api/v1/remediations/{action_id}/transition",
                    params={"new_status": "APPROVED"}, headers=_token("appr_self"))
    assert r.status_code == 403


def test_high_severity_cannot_skip_staged():
    adv_id = _make_advisory("CRITICAL")
    r = client.post("/api/v1/remediations", headers=_token("op1"),
                    json={"advisory_id": adv_id, "generated_commands": "cmd"})
    action_id = r.json()["id"]
    appr = _token("appr1")
    assert client.post(f"/api/v1/remediations/{action_id}/transition",
                       params={"new_status": "APPROVED"}, headers=appr).status_code == 200
    # APPROVED -> APPLIED must be blocked for CRITICAL
    r = client.post(f"/api/v1/remediations/{action_id}/transition",
                    params={"new_status": "APPLIED"}, headers=appr)
    assert r.status_code == 400
    # APPROVED -> STAGED -> APPLIED is the legal path
    assert client.post(f"/api/v1/remediations/{action_id}/transition",
                       params={"new_status": "STAGED"}, headers=appr).status_code == 200
    assert client.post(f"/api/v1/remediations/{action_id}/transition",
                       params={"new_status": "APPLIED"}, headers=appr).status_code == 200


def test_illegal_transition_rejected():
    adv_id = _make_advisory("LOW")
    r = client.post("/api/v1/remediations", headers=_token("op1"),
                    json={"advisory_id": adv_id, "generated_commands": "cmd"})
    action_id = r.json()["id"]
    r = client.post(f"/api/v1/remediations/{action_id}/transition",
                    params={"new_status": "ROLLED_BACK"}, headers=_token("appr1"))
    assert r.status_code == 400


def test_operator_cannot_transition():
    adv_id = _make_advisory("LOW")
    r = client.post("/api/v1/remediations", headers=_token("op1"),
                    json={"advisory_id": adv_id, "generated_commands": "cmd"})
    action_id = r.json()["id"]
    r = client.post(f"/api/v1/remediations/{action_id}/transition",
                    params={"new_status": "APPROVED"}, headers=_token("op2"))
    assert r.status_code == 403
