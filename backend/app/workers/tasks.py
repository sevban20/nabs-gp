"""Celery tasks: post-backup security scan (Spec Section 5), risk
recomputation (Section 6), active SSH backups (Scrapli) and Git
mirroring (Section 12.1).

Architectural principle 5 (Spec Section 13): no code path here may push
AI- or rule-generated commands to a live device. All device access is
read-only.
"""
import logging
from datetime import datetime, timezone

from app.workers.celery_app import celery_app

logger = logging.getLogger("nabs.tasks")

# Command matrix per vendor (read-only "show" commands)
BACKUP_COMMAND_MATRIX = {
    "cisco_ios": "show running-config",
    "fortinet": "show full-configuration",
    "fortiswitch": "show",
    "paloalto": "show config running",
    "juniper_junos": "show configuration | display set",
    "huawei_vrp": "display current-configuration",
    "aruba_aoscx": "show running-config",
    "aruba_procurve": "show running-config",
    "mikrotik": "/export",
    # openwrt/linux BACKUP_COMMAND_MATRIX'te değil; ayrı Linux yolundan alınır.
}

# Scrapli sürücü eşlemesi. Çekirdek scrapli yalnızca cisco/juniper/arista
# içerir; huawei/aruba/mikrotik/paloalto için scrapli-community gereklidir.
# NOT: scrapli-community'de güvenilir bir "fortinet" ağ platformu yoktur —
# Fortinet ailesi GENERIC_VENDORS üzerinden GenericDriver ile çekilir.
SCRAPLI_PLATFORM_MAP = {
    "cisco_ios": "cisco_iosxe",
    "juniper_junos": "juniper_junos",
    "huawei_vrp": "huawei_vrp",
    "aruba_aoscx": "aruba_aoscx",
    "paloalto": "paloalto_panos",
    "mikrotik": "mikrotik_routeros",
    "aruba_procurve": "hp_comware",
}

# Linux tabanlı cihazlar: ağ-vendor CLI değil, SSH exec ile yedeklenir.
LINUX_VENDORS = {"openwrt", "linux"}

# scrapli ağ sürücüsü olmayan/klasik enable-config CLI'si gibi davranmayan
# cihazlar: scrapli GenericDriver ile ham komut çalıştırılıp çıktı alınır.
GENERIC_VENDORS = {"fortinet", "fortiswitch"}

# Eski cihazlar için legacy KEX/cipher'lara izin veren ssh config (Dockerfile'da
# /srv/nabs/ssh_config'e kopyalanır). Yoksa Scrapli sistem varsayılanını kullanır.
import os as _os  # noqa: E402
SSH_CONFIG_FILE = _os.getenv("NABS_SSH_CONFIG", "/srv/nabs/ssh_config")


def _scrapli_ssh_kwargs() -> dict:
    """Tüm Scrapli/GenericDriver çağrılarında ortak: legacy-uyumlu ssh config
    ve strict-key kapalı. Config dosyası yoksa sistem varsayılanına düşer."""
    kw = {"auth_strict_key": False, "ssh_config_file": True}
    if _os.path.exists(SSH_CONFIG_FILE):
        kw["ssh_config_file"] = SSH_CONFIG_FILE
    return kw


@celery_app.task(name="app.workers.tasks.run_security_analysis")
def run_security_analysis(hostname: str, sanitized_config: str) -> dict:
    """Automatic post-backup security scan (fixed in v1.1 — actually wired).

    Runs the static rule engine, persists findings to security_advisories
    and queues a risk-score recompute for the asset."""
    from app.core.database import SessionLocal
    from app.models.models import Asset, SecurityAdvisory
    from app.services.static_analyzer import StaticAnalyzer

    findings = StaticAnalyzer.audit_cisco_ios(sanitized_config)

    # Faz 3: YAML politika motoru bulguları da aynı akışa katılır
    import os
    policy_dir = os.getenv("NABS_POLICY_DIR",
                           os.path.join(os.path.dirname(__file__), "..", "..", "policies"))
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.hostname == hostname).first()
        asset_id = asset.id if asset else None
        vendor = asset.vendor if asset else None
        if os.path.isdir(policy_dir):
            from app.services.policy_engine import evaluate_policies, load_policies
            findings += evaluate_policies(sanitized_config, load_policies(policy_dir), vendor)
        for f in findings:
            db.add(SecurityAdvisory(
                asset_id=asset_id,
                rule_id=f["rule_id"], title=f["title"],
                description=f["description"], remediation=f.get("remediation"),
                severity=f["severity"], finding_source="STATIC_RULE_ENGINE",
            ))
        db.commit()
        # Config drift: golden baseline varsa mevcut config'le karşılaştır
        if asset is not None:
            try:
                evaluate_drift(db, asset, sanitized_config)
            except Exception:
                logger.exception("Drift değerlendirmesi başarısız: %s", hostname)
        if asset_id is not None:
            recompute_asset_risk.delay(asset_id)
    finally:
        db.close()

    # Faz 5: CRITICAL/HIGH bulgular yapılandırılmış kanallara bildirilir
    from app.services.notifications import notify_finding
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH"):
            try:
                notify_finding(hostname, f)
            except Exception:
                logger.exception("Bildirim gönderilemedi")

    logger.info("Security analysis for %s: %d finding(s)", hostname, len(findings))
    return {"hostname": hostname, "findings": len(findings)}


@celery_app.task(name="app.workers.tasks.run_discovery_scan")
def run_discovery_scan(cidr: str, snmp_community: str = "public") -> list[dict]:
    """Faz 2: katmanlı CIDR keşif taraması (TCP probe -> SNMP | SSH banner)."""
    from app.services.discovery import scan_network
    return scan_network(cidr, snmp_community)


def _collect_neighbors_over_ssh(host, username, password, enable_secret, vendor):
    """Cihazdan LLDP/CDP komşu çıktısını çeker (read-only). Test için ayrık."""
    from scrapli import Scrapli

    from app.services.topology import NEIGHBOR_COMMANDS

    conn = Scrapli(host=host, auth_username=username, auth_password=password,
                   auth_secondary=enable_secret or "",
                   platform=SCRAPLI_PLATFORM_MAP.get(vendor, "cisco_iosxe"),
                   timeout_socket=30, timeout_ops=60, **_scrapli_ssh_kwargs())
    conn.open()
    try:
        outputs = []
        for cmd in NEIGHBOR_COMMANDS.get(vendor, []):
            try:
                outputs.append(conn.send_command(cmd).result)
            except Exception:  # noqa: BLE001 - komut desteklenmeyebilir
                continue
        return "\n".join(outputs)
    finally:
        conn.close()


# L2 envanter komutları (ARP + MAC tablosu), vendor bazlı
L2_COMMANDS = {
    "cisco_ios": {"arp": "show ip arp", "mac": "show mac address-table"},
    "aruba_aoscx": {"arp": "show arp", "mac": "show mac-address"},
    "huawei_vrp": {"arp": "display arp", "mac": "display mac-address"},
}


def _collect_l2_over_ssh(host, username, password, enable_secret, vendor):
    """Cihazdan ARP ve MAC tablosu çıktısını çeker (read-only). Test için ayrık."""
    from scrapli import Scrapli

    cmds = L2_COMMANDS.get(vendor, L2_COMMANDS["cisco_ios"])
    conn = Scrapli(host=host, auth_username=username, auth_password=password,
                   auth_secondary=enable_secret or "",
                   platform=SCRAPLI_PLATFORM_MAP.get(vendor, "cisco_iosxe"),
                   timeout_socket=30, timeout_ops=60, **_scrapli_ssh_kwargs())
    conn.open()
    try:
        arp = mac = ""
        try:
            arp = conn.send_command(cmds["arp"]).result
        except Exception:  # noqa: BLE001
            pass
        try:
            mac = conn.send_command(cmds["mac"]).result
        except Exception:  # noqa: BLE001
            pass
        return arp, mac
    finally:
        conn.close()


@celery_app.task(name="app.workers.tasks.collect_l2_inventory")
def collect_l2_inventory(asset_id: int) -> dict:
    """Bir switch/router'a bağlanıp ARP + MAC tablosunu toplar, uç cihazları
    (OUI üreticisiyle) discovered_hosts'a upsert eder. Multi-site keşifte her
    yönetilen cihaz kendi segmentindeki uç cihazları raporlar."""
    from datetime import datetime, timezone

    from app.core.crypto import get_crypto
    from app.core.database import SessionLocal
    from app.models.models import Asset, Credential, DiscoveredHost
    from app.services.topology import (
        merge_l2_inventory, parse_arp_table, parse_mac_address_table)

    db = SessionLocal()
    try:
        asset = db.get(Asset, asset_id)
        if not asset or not asset.credential_id:
            return {"status": "SKIPPED", "reason": "asset/credential yok"}
        cred = db.get(Credential, asset.credential_id)
        crypto = get_crypto()
        arp_out, mac_out = _collect_l2_over_ssh(
            host=asset.ip_address, username=cred.username,
            password=crypto.decrypt(cred.password_encrypted),
            enable_secret=crypto.decrypt(cred.secret_encrypted) if cred.secret_encrypted else None,
            vendor=asset.vendor)

        hosts = merge_l2_inventory(parse_arp_table(arp_out),
                                   parse_mac_address_table(mac_out), asset.hostname)
        managed_ips = {ip for (ip,) in db.query(Asset.ip_address).all()}
        upserts = 0
        for h in hosts:
            row = db.query(DiscoveredHost).filter(
                DiscoveredHost.mac == h["mac"],
                DiscoveredHost.seen_on_device == h["seen_on_device"]).first()
            is_onboarded = bool(h.get("ip_address") and h["ip_address"] in managed_ips)
            if row is None:
                db.add(DiscoveredHost(is_onboarded=is_onboarded, **h))
            else:
                row.ip_address = h.get("ip_address") or row.ip_address
                row.oui_vendor = h["oui_vendor"]
                row.seen_on_interface = h.get("seen_on_interface")
                row.vlan = h.get("vlan")
                row.source = h["source"]
                row.is_onboarded = is_onboarded
                row.last_seen = datetime.now(timezone.utc)
            upserts += 1
        db.commit()
        return {"status": "SUCCESS", "hosts": upserts}
    finally:
        db.close()


def ssh_probe(host: str, username: str, password: str, timeout: int = 10) -> dict:
    """Tek host + tek kimlikle SSH bağlantı denemesi (onboarding doğrulama).
    Toplu 'credential spray' YAPMAZ — hesap kilitlenmesini önlemek için tek
    seferlik. Başarılıysa banner'dan vendor tahmini döner."""
    import paramiko

    from app.services.discovery import identify_from_ssh_banner

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password, timeout=timeout,
                       look_for_keys=False, allow_agent=False)
    except paramiko.AuthenticationException:
        return {"success": False, "reason": "Kimlik doğrulama başarısız (kullanıcı/parola)."}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "reason": f"Bağlanılamadı: {exc}"}
    try:
        banner = (client.get_transport().remote_version
                  if client.get_transport() else "") or ""
        vendor = identify_from_ssh_banner(banner).get("vendor", "unknown")
        return {"success": True, "banner": banner, "vendor_guess": vendor}
    finally:
        client.close()


@celery_app.task(name="app.workers.tasks.collect_topology")
def collect_topology(asset_id: int) -> dict:
    """Bir cihaza bağlanıp LLDP/CDP komşularını toplar ve topology_links'i
    o kaynak için tazeler. Ağ haritasının kenarlarını besler."""
    from app.core.crypto import get_crypto
    from app.core.database import SessionLocal
    from app.models.models import Asset, Credential, TopologyLink
    from app.services.topology import parse_cdp_detail, parse_lldp_detail

    db = SessionLocal()
    try:
        asset = db.get(Asset, asset_id)
        if not asset or not asset.credential_id:
            return {"status": "SKIPPED", "reason": "asset/credential yok"}
        cred = db.get(Credential, asset.credential_id)
        crypto = get_crypto()
        output = _collect_neighbors_over_ssh(
            host=asset.ip_address, username=cred.username,
            password=crypto.decrypt(cred.password_encrypted),
            enable_secret=crypto.decrypt(cred.secret_encrypted) if cred.secret_encrypted else None,
            vendor=asset.vendor)

        neighbors = parse_cdp_detail(output) + parse_lldp_detail(output)
        # Bu kaynak için eski link'leri temizle, yenilerini yaz
        db.query(TopologyLink).filter(
            TopologyLink.source_device == asset.hostname).delete()
        for n in neighbors:
            db.add(TopologyLink(
                source_device=asset.hostname, remote_device=n["remote_device"],
                remote_ip=n.get("remote_ip"), local_interface=n.get("local_interface"),
                remote_interface=n.get("remote_interface"), platform=n.get("platform"),
                protocol=n["protocol"]))
        db.commit()
        return {"status": "SUCCESS", "neighbors": len(neighbors)}
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.sync_cves_for_asset")
def sync_cves_for_asset(asset_id: int) -> int:
    """Faz 3 Sprint 21-22: varlığın OS sürümü için NVD CVE eşlemesi."""
    import asyncio

    from app.core.database import SessionLocal
    from app.models.models import Asset, SecurityAdvisory
    from app.services.cve_sync import build_cpe_string, fetch_cves_for_cpe

    db = SessionLocal()
    try:
        asset = db.get(Asset, asset_id)
        if not asset:
            return 0
        cpe = build_cpe_string(asset.vendor, asset.os_version)
        if not cpe:
            return 0
        findings = asyncio.run(fetch_cves_for_cpe(cpe))
        existing = {r.rule_id for r in db.query(SecurityAdvisory)
                    .filter(SecurityAdvisory.asset_id == asset_id,
                            SecurityAdvisory.finding_source == "CVE_MATCH").all()}
        new_count = 0
        for f in findings:
            if f["rule_id"] in existing:
                continue
            db.add(SecurityAdvisory(
                asset_id=asset_id, rule_id=f["rule_id"], title=f["title"],
                description=f["description"], remediation=f.get("remediation"),
                severity=f["severity"], finding_source="CVE_MATCH"))
            new_count += 1
        db.commit()
        if new_count:
            recompute_asset_risk.delay(asset_id)
        return new_count
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.check_asset_reachability")
def check_asset_reachability() -> dict:
    """Up/down izleme: aktif varlıklara TCP probe atar, sonucu asset
    kaydına yazar. Prometheus iş metrikleri (nabs_asset_reachable vb.)
    bu alanlardan beslenir. 5 dakikada bir beat ile çalışır."""
    from app.core.database import SessionLocal
    from app.models.models import Asset
    from app.services.discovery import probe_host

    db = SessionLocal()
    up = down = 0
    try:
        for asset in db.query(Asset).filter(Asset.is_active.is_(True)).all():
            reachable = probe_host(asset.ip_address, timeout=1.5) is not None
            asset.is_reachable = reachable
            asset.last_reachability_check_at = datetime.now(timezone.utc)
            up += reachable
            down += not reachable
        db.commit()
        return {"up": up, "down": down}
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.purge_expired_records")
def purge_expired_records() -> dict:
    """Bölüm 12.3: veri saklama penceresi — süresi dolan backup_history ve
    ÇÖZÜLMÜŞ advisory kayıtlarını temizler. Pencere zone başına
    yapılandırılabilir olacak şekilde env'den okunur (varsayılan 365 gün)."""
    import os
    from datetime import timedelta

    from app.core.database import SessionLocal
    from app.models.models import BackupHistory, SecurityAdvisory

    from app.core.settings_service import get_int
    days = get_int("DATA_RETENTION_DAYS", 365)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db = SessionLocal()
    try:
        purged_backups = (db.query(BackupHistory)
                          .filter(BackupHistory.triggered_at < cutoff)
                          .delete(synchronize_session=False))
        purged_advisories = (db.query(SecurityAdvisory)
                             .filter(SecurityAdvisory.resolved_at.isnot(None),
                                     SecurityAdvisory.resolved_at < cutoff)
                             .delete(synchronize_session=False))
        db.commit()
        return {"backups": purged_backups, "advisories": purged_advisories,
                "retention_days": days}
    finally:
        db.close()


def evaluate_drift(db, asset, current_config: str) -> dict | None:
    """Bir cihazın mevcut config'ini golden baseline'la karşılaştırır ve
    drift advisory'sini yaşam döngüsüyle yönetir (drift olunca aç, düzelince
    kapat). Baseline yoksa None döner. Hem yedek akışı hem zamanlanmış sweep
    bunu çağırır. db.commit() çağrıyı yapan tarafın sorumluluğunda değildir —
    burada commit edilir."""
    from datetime import datetime, timezone

    from app.core.settings_service import get_setting
    from app.models.models import ConfigBaseline, SecurityAdvisory
    from app.services.drift import compute_drift
    from app.services.git_engine import get_git_engine

    baseline = db.query(ConfigBaseline).filter(
        ConfigBaseline.asset_id == asset.id).first()
    if baseline is None:
        return None

    golden = get_git_engine().get_content_at_commit(asset.hostname, baseline.commit_hash)
    result = compute_drift(golden, current_config)

    open_drift = (db.query(SecurityAdvisory).filter(
        SecurityAdvisory.asset_id == asset.id,
        SecurityAdvisory.rule_id == "CONFIG-DRIFT",
        SecurityAdvisory.resolved_at.is_(None)).first())

    if not result["in_sync"]:
        if open_drift is None:
            db.add(SecurityAdvisory(
                asset_id=asset.id, rule_id="CONFIG-DRIFT",
                title="Yapılandırma referanstan (golden) saptı",
                description=(f"Mevcut config golden baz'dan sapıyor: "
                            f"{result['added']} eklenen, {result['removed']} silinen satır. "
                            f"'Drift Göster' ile inceleyin."),
                remediation="Değişiklik onaylıysa yeni golden olarak baz alın; "
                            "değilse cihazı referans config'e geri getirin.",
                severity=get_setting("DRIFT_SEVERITY", "MEDIUM"),
                finding_source="DRIFT_DETECTOR"))
        else:
            open_drift.description = (
                f"Mevcut config golden baz'dan sapıyor: {result['added']} eklenen, "
                f"{result['removed']} silinen satır.")
        asset.has_drift = True
    else:
        if open_drift is not None:
            open_drift.resolved_at = datetime.now(timezone.utc)
        asset.has_drift = False

    asset.last_drift_check_at = datetime.now(timezone.utc)
    db.commit()
    return result


@celery_app.task(name="app.workers.tasks.run_compliance_sweep")
def run_compliance_sweep() -> dict:
    """Zamanlanmış uyumluluk taraması: baseline'ı olan tüm aktif cihazların
    mevcut config'ini golden'la karşılaştırır (yeni yedek beklemeden).
    Drift advisory'leri açar/kapatır ve risk skorunu tazeler."""
    from app.core.database import SessionLocal
    from app.models.models import Asset, ConfigBaseline
    from app.services.git_engine import get_git_engine

    db = SessionLocal()
    checked = drifted = 0
    try:
        baselined_ids = {b.asset_id for b in db.query(ConfigBaseline.asset_id).all()}
        if not baselined_ids:
            return {"checked": 0, "drifted": 0}
        assets = db.query(Asset).filter(
            Asset.id.in_(baselined_ids), Asset.is_active.is_(True)).all()
        for asset in assets:
            current = get_git_engine().get_current_content(asset.hostname)
            if not current:
                continue
            result = evaluate_drift(db, asset, current)
            checked += 1
            if result and not result["in_sync"]:
                drifted += 1
                recompute_asset_risk.delay(asset.id)
        return {"checked": checked, "drifted": drifted}
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.recompute_asset_risk")
def recompute_asset_risk(asset_id: int) -> int:
    """Recompute composite risk score from open, non-silenced advisories."""
    from app.core.database import SessionLocal
    from app.models.models import Asset, SecurityAdvisory
    from app.services.risk_engine import compute_risk_score

    db = SessionLocal()
    try:
        open_rows = (
            db.query(SecurityAdvisory)
            .filter(SecurityAdvisory.asset_id == asset_id,
                    SecurityAdvisory.resolved_at.is_(None))
            .all()
        )
        score = compute_risk_score([
            {"severity": r.severity, "is_silenced": r.is_silenced} for r in open_rows
        ])
        asset = db.get(Asset, asset_id)
        if asset:
            asset.risk_score = score
            db.commit()
        return score
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.run_active_backup", bind=True, max_retries=2)
def run_active_backup(self, asset_id: int, triggered_by: str = "CRON_ENGINE",
                      history_id: int | None = None) -> dict:
    """Active SSH backup via Scrapli: fetch config, sanitize, commit to Git.
    history_id verilirse (endpoint'in oluşturduğu QUEUED kaydı) onu günceller,
    yoksa yeni bir kayıt açar (zamanlanmış yedekler)."""
    from app.core.crypto import get_crypto
    from app.core.database import SessionLocal
    from app.models.models import Asset, BackupHistory, Credential
    from app.services.git_engine import get_git_engine
    from app.services.sanitizer import sanitize_raw_config

    db = SessionLocal()
    history = None
    try:
        asset = db.get(Asset, asset_id)
        if not asset or not asset.is_active:
            return {"status": "SKIPPED", "reason": "asset missing or inactive"}

        history = db.get(BackupHistory, history_id) if history_id else None
        if history is None:
            history = BackupHistory(
                asset_id=asset.id, method_used=asset.backup_method,
                triggered_by=triggered_by)
            db.add(history)
        history.status = "IN_PROGRESS"
        db.commit()

        cred = db.get(Credential, asset.credential_id) if asset.credential_id else None
        if cred is None:
            raise RuntimeError("No credential bound to asset.")

        crypto = get_crypto()
        raw_config = _fetch_config_over_ssh(
            host=asset.ip_address,
            username=cred.username,
            password=crypto.decrypt(cred.password_encrypted),
            enable_secret=crypto.decrypt(cred.secret_encrypted) if cred.secret_encrypted else None,
            vendor=asset.vendor,
        )
        sanitized = sanitize_raw_config(raw_config)
        commit_sha = get_git_engine().save_and_commit(
            hostname=asset.hostname, config_content=sanitized,
            trigger_source=triggered_by,
        )
        history.status = "SUCCESS"
        history.commit_hash = commit_sha or None
        history.config_size_bytes = len(sanitized.encode())
        history.completed_at = datetime.now(timezone.utc)
        asset.last_successful_backup_at = history.completed_at
        db.commit()

        if commit_sha:
            run_security_analysis.delay(asset.hostname, sanitized)
        return {"status": "SUCCESS", "commit": commit_sha}
    except Exception as exc:
        if history is not None:
            history.status = "FAILED"
            history.error_log = str(exc)
            history.completed_at = datetime.now(timezone.utc)
            db.commit()
        raise self.retry(exc=exc, countdown=30)
    finally:
        db.close()


def _fetch_config_over_ssh(host: str, username: str, password: str,
                           enable_secret: str | None, vendor: str) -> str:
    """Read-only config fetch. Yönlendirme:
    - OpenWrt/Linux → SSH exec (uci export)
    - Fortinet ailesi → scrapli GenericDriver (scrapli-community'de 'fortinet'
      ağ platformu yok; network sürücüsü 'Community platform missing…' hatası verir)
    - Diğer ağ-vendor → scrapli network sürücüsü (SCRAPLI_PLATFORM_MAP)
    Test için ayrık tutuldu."""
    if vendor in LINUX_VENDORS:
        return _fetch_linux_config(host, username, password)

    command = BACKUP_COMMAND_MATRIX.get(vendor, "show running-config")

    if vendor in GENERIC_VENDORS:
        return _fetch_generic_config(host, username, password, command)

    from scrapli import Scrapli

    conn = Scrapli(
        host=host, auth_username=username, auth_password=password,
        auth_secondary=enable_secret or "",
        platform=SCRAPLI_PLATFORM_MAP.get(vendor, "cisco_iosxe"),
        timeout_socket=30, timeout_ops=60, **_scrapli_ssh_kwargs(),
    )
    conn.open()
    try:
        return conn.send_command(command).result
    finally:
        conn.close()


def _fetch_generic_config(host: str, username: str, password: str, command: str) -> str:
    """Fortinet ailesi gibi, scrapli ağ platformu olmayan cihazlar için
    GenericDriver ile ham komut çalıştırma. Fortinet'te sayfalama (--More--)
    olmasın diye önce 'config system console / set output standard' denenir;
    desteklenmezse yok sayılır."""
    from scrapli.driver import GenericDriver

    conn = GenericDriver(
        host=host, auth_username=username, auth_password=password,
        timeout_socket=30, timeout_ops=90,
        # Fortinet prompt'u: "hostname #", "hostname (global) #", "> " …
        comms_prompt_pattern=r"(?im)^[\w.\-]+\s*(\([\w.\-]+\))?\s*[#$>]\s*$",
        **_scrapli_ssh_kwargs(),
    )
    conn.open()
    try:
        # sayfalamayı kapat (FortiGate/FortiSwitch); desteklenmezse sessiz geç
        for pre in ("config system console", "set output standard", "end"):
            try:
                conn.send_command(pre)
            except Exception:  # noqa: BLE001
                break
        return conn.send_command(command).result
    finally:
        conn.close()


def _fetch_linux_config(host: str, username: str, password: str) -> str:
    """OpenWrt/Linux yedeği: paramiko exec_command ile 'uci export' çalıştırır
    (tüm yapılandırmayı düz metin verir — diff'e ve sanitizasyona ideal).
    uci yoksa /etc/config/* dosyalarına düşer."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, timeout=30,
                   look_for_keys=False, allow_agent=False)
    try:
        # uci export standart OpenWrt aracı; yoksa ham config dosyaları
        cmd = "uci export 2>/dev/null || (echo '# /etc/config dump'; head -n -0 /etc/config/* 2>/dev/null)"
        _stdin, stdout, _stderr = client.exec_command(cmd, timeout=60)
        output = stdout.read().decode("utf-8", errors="ignore")
        return output.strip()
    finally:
        client.close()


@celery_app.task(name="app.workers.tasks.run_scheduled_backups")
def run_scheduled_backups() -> int:
    """Queue an active backup for every active ACTIVE_SSH asset."""
    from app.core.database import SessionLocal
    from app.models.models import Asset

    db = SessionLocal()
    try:
        assets = db.query(Asset).filter(
            Asset.is_active.is_(True), Asset.backup_method == "ACTIVE_SSH"
        ).all()
        for a in assets:
            run_active_backup.delay(a.id, "CRON_ENGINE")
        return len(assets)
    finally:
        db.close()


@celery_app.task(name="app.workers.tasks.mirror_git_repository")
def mirror_git_repository() -> str:
    """Push the local config repo to an off-host mirror (Spec 12.1).
    Requires a 'mirror' remote to be configured on the repository."""
    from app.services.git_engine import get_git_engine

    engine = get_git_engine()
    remotes = {r.name for r in engine.repo.remotes}
    if "mirror" not in remotes:
        logger.warning("No 'mirror' remote configured; skipping repo mirroring.")
        return "NO_MIRROR_REMOTE"
    engine.repo.remotes.mirror.push(all=True)
    return "PUSHED"
