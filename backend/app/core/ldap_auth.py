"""Faz 5 Sprint 39-40: opsiyonel LDAP kimlik doğrulama.

LDAP_URL tanımlıysa lokal parola doğrulaması başarısız olduğunda LDAP
bind denenir (Faz-1 JWT temeli üzerine katman; onun yerini almaz —
Spec Bölüm 7). SAML SSO ve WebAuthn MFA, IdP entegrasyonu gerektirir ve
kurumsal dağıtımda bu modülün yanına eklenir; TOTP MFA (auth.py) temel
ikinci faktörü sağlar.

Env: LDAP_URL=ldap://dc01:389  LDAP_BIND_TEMPLATE=uid={username},ou=people,dc=corp,dc=local
     LDAP_DEFAULT_ROLE=viewer
"""
import logging
import os

logger = logging.getLogger("nabs.ldap")


def _s(key: str, default: str | None = None):
    from app.core.settings_service import get_setting
    return get_setting(key, default)


def ldap_enabled() -> bool:
    return bool(_s("LDAP_URL"))


def ldap_authenticate(username: str, password: str) -> str | None:
    """Başarılıysa kullanıcıya atanacak rolü döndürür, aksi halde None."""
    if not ldap_enabled() or not password:
        return None
    try:  # pragma: no cover - environment dependent
        from ldap3 import Connection, Server
    except ImportError:
        logger.warning("LDAP_URL tanımlı ama ldap3 kurulu değil.")
        return None
    template = _s("LDAP_BIND_TEMPLATE", "uid={username}")
    server = Server(_s("LDAP_URL"))
    conn = Connection(server, user=template.format(username=username), password=password)
    try:
        if conn.bind():
            return _s("LDAP_DEFAULT_ROLE", "viewer")
        return None
    finally:
        conn.unbind()
