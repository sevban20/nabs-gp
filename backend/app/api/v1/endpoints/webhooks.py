"""Passive Webhook Ingestion — SFTPGo Integration (Spec Section 5, FIXED).

v1.1 fixes enforced here:
1. HMAC signature verification is actually called, over the RAW body.
2. Path-traversal protection: uploaded path must stay inside the
   allowed upload root.
3. The post-backup security scan Celery task is actually queued.

This endpoint relies on HMAC rather than a user JWT (its access model
is declared explicitly per Spec Section 7).
"""
import hashlib
import hmac
import os
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from app.services.git_engine import get_git_engine
from app.services.sanitizer import sanitize_raw_config

router = APIRouter()


def _allowed_upload_root() -> Path:
    return Path(os.getenv("SFTPGO_UPLOAD_ROOT", "/var/nabs/sftpgo_uploads")).resolve()


class SFTPGoUploadPayload(BaseModel):
    action: str
    username: str
    path: str
    target_path: str


def verify_sftpgo_signature(raw_body: bytes, signature_header: str) -> bool:
    """HMAC-SHA256 over the raw, unparsed request body."""
    from app.core.secrets import get_secret
    secret = get_secret("SFTPGO_WEBHOOK_SECRET")
    if not secret:
        raise RuntimeError("SFTPGO_WEBHOOK_SECRET is not configured.")
    computed = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature_header or "")


def resolve_safe_path(candidate: str) -> Path:
    """Rejects any path that would escape the allowed upload root
    (blocks '../' traversal and absolute-path injection)."""
    root = _allowed_upload_root()
    resolved = (root / candidate.lstrip("/")).resolve()
    if resolved != root and root not in resolved.parents:
        raise HTTPException(status_code=400, detail="Path escapes allowed upload root.")
    return resolved


@router.post("/webhook/sftpgo")
async def process_passive_backup(request: Request, x_sftpgo_signature: str = Header(...)):
    raw_body = await request.body()
    if not verify_sftpgo_signature(raw_body, x_sftpgo_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    payload = SFTPGoUploadPayload.model_validate_json(raw_body)
    if payload.action != "upload":
        return {"status": "ignored_action"}

    safe_path = resolve_safe_path(payload.path)
    if not safe_path.exists():
        raise HTTPException(status_code=404, detail="File payload missing on shared volume.")

    raw_config = safe_path.read_text()
    sanitized_config = sanitize_raw_config(raw_config)
    hostname = Path(payload.target_path).stem

    commit_sha = get_git_engine().save_and_commit(
        hostname=hostname, config_content=sanitized_config,
        trigger_source=f"SFTP_PASSIVE_UPLOAD_BY_{payload.username.upper()}",
    )
    if commit_sha:
        from app.workers.tasks import run_security_analysis
        run_security_analysis.delay(hostname, sanitized_config)  # now actually queued

    return {"status": "success", "commit_hash": commit_sha, "device": hostname}
