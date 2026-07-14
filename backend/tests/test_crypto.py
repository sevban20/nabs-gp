"""Spec Section 4.1: fail-closed key handling + AES-256-GCM round trip."""
import base64
import os

import pytest

from app.core.crypto import CryptoManager


def test_encrypt_decrypt_roundtrip():
    cm = CryptoManager()
    for value in ["S3cr3t!", "çok gizli parola", ""]:
        assert cm.decrypt(cm.encrypt(value)) == value


def test_ciphertext_is_nondeterministic():
    cm = CryptoManager()
    assert cm.encrypt("same") != cm.encrypt("same")  # random nonce


def test_fails_closed_in_production_without_key(monkeypatch):
    monkeypatch.delenv("NABS_MASTER_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError, match="NABS_MASTER_KEY"):
        CryptoManager()


def test_ephemeral_key_allowed_in_development(monkeypatch):
    monkeypatch.delenv("NABS_MASTER_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    cm = CryptoManager()
    assert cm.decrypt(cm.encrypt("dev")) == "dev"


def test_rejects_wrong_key_length(monkeypatch):
    monkeypatch.setenv("NABS_MASTER_KEY", base64.b64encode(os.urandom(16)).decode())
    with pytest.raises(RuntimeError, match="32 bytes"):
        CryptoManager()
