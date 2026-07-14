"""GUI'den web sunucu TLS sertifika yükleme: doğrulama + uçlar."""
import datetime
import os
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import User

client = TestClient(app)


def _make_cert(days_valid=60, cn="nabs.test"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    not_after = now + datetime.timedelta(days=days_valid)
    # süresi dolmuş senaryoda before, after'dan önce olmalı (geçerli sıralama)
    not_before = min(now - datetime.timedelta(days=1), not_after - datetime.timedelta(days=1))
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    return cert_pem, key_pem


# ---- pure doğrulama ----

def test_valid_pair_accepted():
    from app.services.tls_check import validate_cert_key_pair
    cert, key = _make_cert()
    info = validate_cert_key_pair(cert, key)
    assert info["days_remaining"] > 30 and info["expired"] is False


def test_mismatched_key_rejected():
    from app.services.tls_check import validate_cert_key_pair
    cert, _ = _make_cert()
    _, other_key = _make_cert()
    with pytest.raises(ValueError, match="eşleşmiyor"):
        validate_cert_key_pair(cert, other_key)


def test_expired_cert_rejected():
    from app.services.tls_check import validate_cert_key_pair
    cert, key = _make_cert(days_valid=-5)
    with pytest.raises(ValueError, match="süresi dolmuş"):
        validate_cert_key_pair(cert, key)


def test_garbage_pem_rejected():
    from app.services.tls_check import validate_cert_key_pair
    with pytest.raises(ValueError, match="ayrıştırılamadı"):
        validate_cert_key_pair("not a cert", "not a key")


# ---- uçlar (izole TLS_CERT_DIR) ----

@pytest.fixture(scope="module", autouse=True)
def setup(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    import app.services.tls_check as tc
    tc.TLS_CERT_DIR = str(d)  # izole dizin
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("tls_admin", "admin"), ("tls_op", "operator")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_upload_requires_admin():
    cert, key = _make_cert()
    r = client.post("/api/v1/system/tls-certificate", headers=_token("tls_op"),
                    json={"certificate": cert, "private_key": key})
    assert r.status_code == 403


def test_upload_and_get_roundtrip():
    cert, key = _make_cert(cn="nabs.corp.local")
    r = client.post("/api/v1/system/tls-certificate", headers=_token("tls_admin"),
                    json={"certificate": cert, "private_key": key})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "installed"

    g = client.get("/api/v1/system/tls-certificate", headers=_token("tls_admin")).json()
    assert g["installed"] is True and "nabs.corp.local" in g["subject"]
    # private key sızmamalı
    assert "private" not in str(g).lower() or "PRIVATE KEY" not in str(g)

    # dosya izinleri: key 0600
    import app.services.tls_check as tc
    key_path = os.path.join(tc.TLS_CERT_DIR, tc.KEY_FILE)
    assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"


def test_upload_mismatch_returns_400():
    cert, _ = _make_cert()
    _, other = _make_cert()
    r = client.post("/api/v1/system/tls-certificate", headers=_token("tls_admin"),
                    json={"certificate": cert, "private_key": other})
    assert r.status_code == 400
