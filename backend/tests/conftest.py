"""Test environment: dev mode, in-memory-ish SQLite, temp git repo."""
import base64
import os
import tempfile

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("NABS_MASTER_KEY", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("SFTPGO_WEBHOOK_SECRET", "test-webhook-secret")

_tmp = tempfile.mkdtemp(prefix="nabs-test-")
os.environ.setdefault("NABS_GIT_REPO_PATH", os.path.join(_tmp, "git_repo"))
os.environ.setdefault("SFTPGO_UPLOAD_ROOT", os.path.join(_tmp, "uploads"))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp}/test.db")
os.makedirs(os.environ["SFTPGO_UPLOAD_ROOT"], exist_ok=True)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """Testler tek IP (testserver) paylaştığından login sayacı birikir;
    her testten önce sıfırla ki testler birbirini 429'a düşürmesin."""
    from app.core import ratelimit
    ratelimit._local_buckets.clear()
    yield
