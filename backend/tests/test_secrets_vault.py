"""Opsiyonel Vault secret provider: env fallback, Vault okuma, fail-closed."""
import app.core.secrets as secrets_mod


def _reset_cache():
    secrets_mod._cache = None


def test_env_fallback_when_vault_disabled(monkeypatch):
    _reset_cache()
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.setenv("NABS_MASTER_KEY", "env-key-value")
    assert secrets_mod.vault_enabled() is False
    assert secrets_mod.get_secret("NABS_MASTER_KEY") == "env-key-value"


def test_vault_enabled_detection(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    assert secrets_mod.vault_enabled() is True


def test_reads_from_vault(monkeypatch):
    _reset_cache()
    monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.setattr(secrets_mod, "_load_from_vault",
                        lambda: {"NABS_MASTER_KEY": "vault-key", "JWT_SECRET": "vault-jwt"})
    assert secrets_mod.get_secret("NABS_MASTER_KEY") == "vault-key"
    assert secrets_mod.get_secret("JWT_SECRET") == "vault-jwt"


def test_vault_partial_falls_back_to_env(monkeypatch):
    _reset_cache()
    monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.setenv("SFTPGO_WEBHOOK_SECRET", "env-webhook")
    # Vault yalnızca master key'i tutuyor; webhook env'den gelmeli
    monkeypatch.setattr(secrets_mod, "_load_from_vault", lambda: {"NABS_MASTER_KEY": "vk"})
    assert secrets_mod.get_secret("NABS_MASTER_KEY") == "vk"
    assert secrets_mod.get_secret("SFTPGO_WEBHOOK_SECRET") == "env-webhook"


def test_vault_unreachable_fails_closed(monkeypatch):
    _reset_cache()
    monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")

    def boom():
        raise RuntimeError("connection refused")
    monkeypatch.setattr(secrets_mod, "_load_from_vault", boom)
    # Vault yapılandırılmış ama erişilemez → env'e SESSİZCE düşmez, hata fırlatır
    try:
        secrets_mod.get_secret("NABS_MASTER_KEY")
        assert False, "RuntimeError bekleniyordu"
    except RuntimeError as exc:
        assert "Vault" in str(exc)
    finally:
        _reset_cache()
