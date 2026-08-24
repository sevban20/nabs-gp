"""Prod öncesi doğrulama uçları: secret backend (Vault) durumu, platform
TLS sertifika durumu, LDAP bağlantı testi. Hepsi admin yetkisi ister."""
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.auth import require_role

router = APIRouter()


@router.get("/system/secret-status")
def secret_status(_admin: dict = Depends(require_role("admin"))):
    """Vault aktif/erişilebilir mi ve bootstrap secret'ları hangi kaynaktan
    çözülüyor (vault/env/eksik). Değerler döndürülmez."""
    from app.core.secrets import secret_status as _status
    return _status()


@router.get("/system/tls-status")
def tls_status(host: str | None = None, port: int = Query(443, ge=1, le=65535),
               _admin: dict = Depends(require_role("admin"))):
    """Platform (ya da verilen host'un) TLS sertifika durumu. host verilmezse
    NABS_DOMAIN kullanılır."""
    from app.services.tls_check import check_tls_certificate
    target = host or os.getenv("NABS_DOMAIN")
    if not target:
        raise HTTPException(status_code=400,
                            detail="TLS kontrol hedefi yok. host parametresi verin ya da "
                                   "NABS_DOMAIN ayarlayın.")
    return check_tls_certificate(target, port)


class CertUpload(BaseModel):
    certificate: str   # PEM (fullchain önerilir)
    private_key: str   # PEM


@router.get("/system/tls-certificate")
def get_installed_cert(_admin: dict = Depends(require_role("admin"))):
    """GUI'den yüklenmiş web sunucu sertifikasının bilgisi (private key
    asla döndürülmez)."""
    from app.services.tls_check import installed_certificate_info
    return installed_certificate_info()


@router.post("/system/tls-certificate")
def upload_cert(payload: CertUpload, admin: dict = Depends(require_role("admin"))):
    """GUI erişiminde kullanılan web sunucu TLS sertifikasını yükler/günceller.
    Doğrular (anahtar-sertifika eşleşmesi, süre) ve reverse-proxy'nin okuduğu
    dizine yazar; Caddy dosya değişince otomatik yeniler."""
    from app.services.tls_check import install_certificate
    try:
        info = install_certificate(payload.certificate, payload.private_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500,
                            detail=f"Sertifika yazılamadı (dizin izinleri?): {exc}")
    return {"status": "installed", "installed_by": admin["sub"], **info}


class LdapTest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/system/ldap-test")
def ldap_test(payload: LdapTest, _admin: dict = Depends(require_role("admin"))):
    """LDAP yapılandırmasını test eder. Kullanıcı/parola verilirse bind
    denenir; verilmezse yalnızca sunucuya erişim (anonim bind) denenir."""
    from app.core.ldap_auth import ldap_enabled

    if not ldap_enabled():
        return {"ok": False, "reason": "LDAP yapılandırılmamış (Ayarlar → LDAP → LDAP_URL)."}
    try:
        from ldap3 import ALL, Connection, Server
    except ImportError:
        return {"ok": False, "reason": "ldap3 kütüphanesi kurulu değil."}

    from app.core.settings_service import get_setting
    url = get_setting("LDAP_URL")
    try:
        server = Server(url, get_info=ALL, connect_timeout=5)
        if payload.username and payload.password:
            template = get_setting("LDAP_BIND_TEMPLATE", "uid={username}")
            conn = Connection(server, user=template.format(username=payload.username),
                              password=payload.password)
            ok = conn.bind()
            reason = "Bind başarılı." if ok else "Bind başarısız (kullanıcı/parola)."
            conn.unbind()
        else:
            conn = Connection(server)
            ok = conn.bind()  # anonim
            reason = "Sunucuya erişildi (anonim bind)." if ok else \
                "Sunucuya erişildi ama anonim bind kapalı (normal olabilir)."
            ok = True  # erişim sağlandıysa test amacına ulaştı
            conn.unbind()
        return {"ok": ok, "reason": reason, "server": url}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": f"LDAP sunucusuna erişilemedi: {exc}", "server": url}


@router.get("/system/mirror-status")
def mirror_status(_admin: dict = Depends(require_role("admin"))):
    """Config deposunun host dışı aynası (Spec 12.1) yapılandırılmış mı.

    'mirror' remote tanımlı değilse `mirror_git_repository` görevi her
    çalışmada sessizce atlanır; bu durumda config geçmişinin tek kopyası
    kalır. Uç, URL'yi kimlik bilgisi sızdırmayacak biçimde maskeler.
    """
    from app.services.git_engine import get_git_engine

    try:
        repo = get_git_engine().repo
        remote = next((r for r in repo.remotes if r.name == "mirror"), None)
    except Exception as exc:  # depo henüz oluşmamış olabilir
        return {"configured": False, "url": None, "detail": str(exc)}

    if remote is None:
        return {"configured": False, "url": None,
                "detail": "'mirror' remote tanımlı değil — host dışı kopya alınmıyor."}

    url = list(remote.urls)[0]
    if "@" in url:  # https://user:token@host/... -> kimlik bilgisini gizle
        scheme, _, rest = url.partition("://")
        url = f"{scheme}://***@{rest.split('@', 1)[1]}" if rest else "***"
    return {"configured": True, "url": url, "detail": None}
