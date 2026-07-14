"""Credential vault endpoints. Secrets are AES-256-GCM encrypted before
they touch the database; encrypted values are never returned."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.crypto import get_crypto_or_http
from app.core.database import get_db
from app.models.models import Credential
from app.schemas.schemas import CredentialCreate, CredentialOut

router = APIRouter()


@router.get("/credentials", response_model=list[CredentialOut])
def list_credentials(db: Session = Depends(get_db),
                     _user: dict = Depends(require_role("operator"))):
    return db.query(Credential).all()


@router.post("/credentials", response_model=CredentialOut, status_code=201)
def create_credential(payload: CredentialCreate, db: Session = Depends(get_db),
                      _user: dict = Depends(require_role("operator"))):
    crypto = get_crypto_or_http()
    cred = Credential(
        name=payload.name,
        username=payload.username,
        password_encrypted=crypto.encrypt(payload.password),
        secret_encrypted=crypto.encrypt(payload.secret) if payload.secret else None,
        ssh_key_private=crypto.encrypt(payload.ssh_key_private) if payload.ssh_key_private else None,
        passphrase_encrypted=crypto.encrypt(payload.passphrase) if payload.passphrase else None,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


@router.delete("/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: str, db: Session = Depends(get_db),
                      _user: dict = Depends(require_role("admin"))):
    cred = db.get(Credential, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found.")
    db.delete(cred)
    db.commit()
