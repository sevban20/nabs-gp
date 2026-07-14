"""Cryptographic Management Service (Spec Section 4.1).

Fail-closed key handling: in any non-development environment the service
refuses to start without NABS_MASTER_KEY, because a silently generated
ephemeral key would permanently orphan every previously encrypted
credential on the next restart.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoManager:
    def __init__(self):
        from app.core.secrets import get_secret
        self.secret_key = get_secret("NABS_MASTER_KEY")
        env = os.getenv("APP_ENV", "production")
        if not self.secret_key:
            if env == "development":
                # Ephemeral key for local dev only; does not persist
                # across restarts and must never be used beyond a
                # single dev session.
                self.secret_key = base64.b64encode(os.urandom(32)).decode()
            else:
                raise RuntimeError(
                    f"NABS_MASTER_KEY is not set in '{env}' mode. Refusing "
                    "to start with an ephemeral key: a restart would make "
                    "every previously encrypted credential permanently "
                    "unreadable. Set NABS_MASTER_KEY from your secrets "
                    "manager (Vault / KMS) before starting this service."
                )
        self.key_bytes = base64.b64decode(self.secret_key)
        if len(self.key_bytes) != 32:
            raise RuntimeError("NABS_MASTER_KEY must decode to exactly 32 bytes (256-bit).")
        self.aesgcm = AESGCM(self.key_bytes)

    def encrypt(self, plain_text: str) -> str:
        """Encrypts plaintext with AES-256-GCM, prepending the 96-bit nonce."""
        if not plain_text:
            return ""
        nonce = os.urandom(12)
        encrypted_bytes = self.aesgcm.encrypt(nonce, plain_text.encode(), None)
        return base64.b64encode(nonce + encrypted_bytes).decode("utf-8")

    def decrypt(self, encrypted_base64: str) -> str:
        """Decrypts a base64-encoded block using the embedded nonce."""
        if not encrypted_base64:
            return ""
        payload = base64.b64decode(encrypted_base64.encode("utf-8"))
        nonce, encrypted_bytes = payload[:12], payload[12:]
        return self.aesgcm.decrypt(nonce, encrypted_bytes, None).decode("utf-8")


_crypto: CryptoManager | None = None


def get_crypto() -> CryptoManager:
    """Lazy singleton so importing this module never triggers key validation
    at import time (keeps CLI tools and test collection side-effect free);
    fail-closed behavior still applies at first use."""
    global _crypto
    if _crypto is None:
        _crypto = CryptoManager()
    return _crypto


CRYPTO_CONFIG_HINT = (
    "Şifreleme yapılandırması eksik: NABS_MASTER_KEY ayarlı değil. "
    "Bir anahtar üretip .env dosyasına ekleyin ve servisi yeniden başlatın: "
    'python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"'
)


def get_crypto_or_http():
    """FastAPI uçları için: kripto yapılandırması eksikse anlaşılmaz 500
    yerine net bir 503 döndürür (fail-closed davranışı korunur)."""
    from fastapi import HTTPException
    try:
        return get_crypto()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"{CRYPTO_CONFIG_HINT} (Ayrıntı: {exc})")
