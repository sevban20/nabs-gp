"""Bootstrap secret çözümleyici: opsiyonel HashiCorp Vault → ortam değişkeni.

Vault yapılandırılmışsa (VAULT_ADDR + VAULT_TOKEN) secret'lar KV v2'den
okunur; değilse doğrudan ortam değişkenine düşülür. Böylece test ortamı
env-file ile, production Vault ile çalışabilir — kod değişmeden.

Kapsam: yalnızca BOOTSTRAP secret'ları (NABS_MASTER_KEY, JWT_SECRET,
SFTPGO_WEBHOOK_SECRET). Operasyonel ayarlar settings_service'te.

Env:
  VAULT_ADDR=https://vault.corp:8200
  VAULT_TOKEN=...              (ya da VAULT_ROLE_ID/VAULT_SECRET_ID — AppRole)
  VAULT_KV_MOUNT=secret        (varsayılan)
  VAULT_SECRET_PATH=nabs-gp    (KV içindeki path; alanlar secret adlarıdır)
"""
import logging
import os

logger = logging.getLogger("nabs.secrets")

_cache: dict[str, str] | None = None


def vault_enabled() -> bool:
    return bool(os.getenv("VAULT_ADDR") and
               (os.getenv("VAULT_TOKEN") or
                (os.getenv("VAULT_ROLE_ID") and os.getenv("VAULT_SECRET_ID"))))


def _load_from_vault() -> dict[str, str]:
    """Vault KV v2'den secret sözlüğünü çeker. hvac gerektirir."""
    import hvac  # opsiyonel bağımlılık

    client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.getenv("VAULT_TOKEN"))
    if not client.is_authenticated() and os.getenv("VAULT_ROLE_ID"):
        client.auth.approle.login(role_id=os.environ["VAULT_ROLE_ID"],
                                  secret_id=os.environ["VAULT_SECRET_ID"])
    if not client.is_authenticated():
        raise RuntimeError("Vault kimlik doğrulaması başarısız.")
    mount = os.getenv("VAULT_KV_MOUNT", "secret")
    path = os.getenv("VAULT_SECRET_PATH", "nabs-gp")
    resp = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
    return resp["data"]["data"]


def secret_status() -> dict:
    """GUI için: Vault aktif mi, erişilebilir mi ve bootstrap secret'ları
    çözülüyor mu (kaynak: vault/env/eksik). Değerler DÖNDÜRÜLMEZ."""
    names = ["NABS_MASTER_KEY", "JWT_SECRET", "SFTPGO_WEBHOOK_SECRET"]
    result = {"vault_enabled": vault_enabled(), "vault_reachable": None, "secrets": []}
    vault_keys: set[str] = set()
    if vault_enabled():
        try:
            data = _load_from_vault()
            vault_keys = set(data.keys())
            result["vault_reachable"] = True
        except Exception as exc:  # noqa: BLE001
            result["vault_reachable"] = False
            result["error"] = str(exc)[:200]
    for name in names:
        in_vault = name in vault_keys
        in_env = os.getenv(name) not in (None, "")
        source = "vault" if in_vault else ("env" if in_env else "missing")
        result["secrets"].append({"name": name, "is_set": in_vault or in_env, "source": source})
    return result


def get_secret(name: str) -> str | None:
    """Bootstrap secret'ı çözer: Vault (yapılandırılmışsa) → ortam değişkeni.
    Vault yapılandırılıp erişilemezse fail-closed: hata fırlatır (env'e sessizce
    düşmez — yanlış anahtarla açılıp veriyi bozmasın)."""
    global _cache
    if vault_enabled():
        if _cache is None:
            try:
                _cache = _load_from_vault()
                logger.info("Bootstrap secret'ları Vault'tan yüklendi (%d anahtar).",
                            len(_cache))
            except Exception as exc:
                raise RuntimeError(
                    f"Vault yapılandırılmış ama okunamadı: {exc}. "
                    "Fail-closed: env'e sessizce düşülmüyor.") from exc
        if name in _cache:
            return _cache[name]
        # Vault'ta yoksa env'e düşmesine izin ver (kısmi Vault kullanımı)
    return os.getenv(name)
