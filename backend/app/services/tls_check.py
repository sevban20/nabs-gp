"""Bir TLS uç noktasının (platform FQDN ya da herhangi bir cihaz) sunduğu
sertifikayı okuyup özet döndürür. Reverse-proxy (Caddy) TLS'i sonlandırdığı
için sertifika, canlı bir TLS bağlantısından okunur.
"""
import os
import socket
import ssl
from datetime import datetime, timezone

# Reverse-proxy'nin (Caddy) okuduğu, GUI'den yüklenen sertifikaların yeri
TLS_CERT_DIR = os.getenv("TLS_CERT_DIR", "/var/nabs/tls")
CERT_FILE = "fullchain.pem"
KEY_FILE = "privkey.pem"


def _cert_info(cert) -> dict:
    """x509 sertifikadan özet çıkarır (parse edilmiş bir sertifika nesnesi)."""
    from cryptography import x509
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") \
        else cert.not_valid_before.replace(tzinfo=timezone.utc)
    days_remaining = (not_after - datetime.now(timezone.utc)).days
    try:
        sans = [n.value for n in
                cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                .value.get_values_for_type(x509.DNSName)]
    except Exception:  # noqa: BLE001
        sans = []
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "expired": days_remaining < 0,
        "expiring_soon": 0 <= days_remaining <= 30,
        "self_signed": cert.subject == cert.issuer,
        "san": sans,
    }


def validate_cert_key_pair(cert_pem: str, key_pem: str) -> dict:
    """Yüklenen sertifika + özel anahtarı doğrular: PEM ayrıştırılabilir mi,
    anahtar sertifikayla eşleşiyor mu, süresi dolmuş mu. Geçerliyse cert özeti
    döner; değilse ValueError."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception as exc:
        raise ValueError(f"Sertifika (PEM) ayrıştırılamadı: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception as exc:
        raise ValueError(f"Özel anahtar (PEM) ayrıştırılamadı: {exc}") from exc

    # Anahtar sertifikayla eşleşiyor mu? (public key karşılaştırması)
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_pub != key_pub:
        raise ValueError("Özel anahtar sertifikayla eşleşmiyor.")

    info = _cert_info(cert)
    if info["expired"]:
        raise ValueError(f"Sertifika süresi dolmuş (bitiş: {info['not_after']}).")
    return info


def install_certificate(cert_pem: str, key_pem: str) -> dict:
    """Sertifika+anahtarı doğrular ve reverse-proxy'nin okuduğu dizine yazar.
    Anahtar 0600, sertifika 0644 izinle. Caddy dosya değişince otomatik yeniler."""
    info = validate_cert_key_pair(cert_pem, key_pem)
    os.makedirs(TLS_CERT_DIR, exist_ok=True)
    cert_path = os.path.join(TLS_CERT_DIR, CERT_FILE)
    key_path = os.path.join(TLS_CERT_DIR, KEY_FILE)
    with open(cert_path, "w") as f:
        f.write(cert_pem if cert_pem.endswith("\n") else cert_pem + "\n")
    os.chmod(cert_path, 0o644)
    # anahtarı önce dar izinle oluştur
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key_pem if key_pem.endswith("\n") else key_pem + "\n")
    os.chmod(key_path, 0o600)
    return info


def installed_certificate_info() -> dict:
    """GUI'den yüklenmiş sertifikanın bilgisi (varsa)."""
    from cryptography import x509
    cert_path = os.path.join(TLS_CERT_DIR, CERT_FILE)
    if not os.path.exists(cert_path):
        return {"installed": False}
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return {"installed": True, "path": cert_path, **_cert_info(cert)}
    except Exception as exc:  # noqa: BLE001
        return {"installed": True, "path": cert_path, "error": f"Okunamadı: {exc}"}


def check_tls_certificate(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """host:port'a TLS bağlanıp sunulan sertifikayı ayrıştırır.
    Doğrulamayı KAPATIR (self-signed/iç sertifikalar da okunabilsin) —
    amaç geçerlilik kanıtı değil, durum görünürlüğü."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)[:200], "host": host, "port": port}

    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        return {"reachable": True, "host": host, "port": port, **_cert_info(cert)}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": True, "host": host, "port": port,
                "error": f"Sertifika ayrıştırılamadı: {exc}"}
