"""Faz 2: Aktif keşif — TCP erişilebilirlik taraması + SNMP sysDescr'den
vendor/OS tanıma (Sprint 9-10).

ICMP ham soket kök yetkisi gerektirdiğinden erişilebilirlik probu TCP
connect (22/443/8443) ile yapılır. SNMP sorgusu pysnmp kuruluysa çalışır;
kurulu değilse tarama yalnızca erişilebilirlik döndürür.
"""
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

PROBE_PORTS = (22, 443, 8443)

# SSH banner imzaları (port 22 zaten prob ediliyor; bedava vendor ipucu).
# Dropbear gömülü Linux (OpenWrt) için güçlü ama kesin olmayan ipucudur;
# kesin tanı, kimlik bilgisiyle bağlanınca /etc/openwrt_release'ten yapılır.
SSH_BANNER_SIGNATURES: list[tuple[str, str]] = [
    (r"Cisco", "cisco_ios"),
    (r"FortiSSH|Fortinet", "fortinet"),
    (r"PAN-OS|PaloAlto", "paloalto"),
    (r"JUNOS|Juniper|SSH-2.0-OpenSSH.*Junos", "juniper_junos"),
    (r"Huawei", "huawei_vrp"),
    (r"ArubaOS|Aruba", "aruba_aoscx"),
    (r"ROSSSH|RouterOS|MikroTik", "mikrotik"),
    (r"dropbear", "openwrt"),  # gömülü Linux göstergesi (OpenWrt adayı)
]

# sysDescr imzaları -> (vendor, os_version yakalama deseni)
# NOT: daha spesifik olanlar önce gelmeli (ör. FortiSwitch, FortiGate'ten önce).
SYSDESCR_SIGNATURES: list[tuple[str, str, str]] = [
    (r"Cisco IOS[- ]XE", "cisco_ios", r"Version ([\w\.\(\)]+)"),
    (r"Cisco IOS", "cisco_ios", r"Version ([\w\.\(\)]+)"),
    (r"Cisco Adaptive Security Appliance", "cisco_ios", r"Version ([\w\.\(\)]+)"),
    (r"FortiSwitch", "fortiswitch", r"v(\d+\.\d+\.\d+)"),
    (r"FortiGate|FortiOS", "fortinet", r"v(\d+\.\d+\.\d+)"),
    (r"Palo Alto Networks", "paloalto", r"(\d+\.\d+\.\d+)"),
    (r"J[uU][nN][oO][sS]|Juniper", "juniper_junos", r"JUNOS ([\w\.\-]+)"),
    (r"Huawei|\bVRP\b", "huawei_vrp", r"Version ([\w\.]+)"),
    (r"ArubaOS-CX|Aruba.*CX", "aruba_aoscx", r"[Vv]ersion ([\w\.]+)"),
    (r"Aruba|ProCurve|HP.*Switch", "aruba_procurve", r"[Rr]evision ([\w\.]+)"),
    (r"OpenWrt|LEDE", "openwrt", r"(?:OpenWrt|LEDE)[ /]([\w\.\-]+)"),
    (r"MikroTik|RouterOS", "mikrotik", r"RouterOS ([\w\.]+)"),
]


def identify_from_sysdescr(sysdescr: str) -> dict:
    """SNMP sysDescr metninden vendor ve OS sürümü çıkarır (Sprint 9-10:
    automated inventory OS identification)."""
    for vendor_pattern, vendor, version_pattern in SYSDESCR_SIGNATURES:
        if re.search(vendor_pattern, sysdescr):
            m = re.search(version_pattern, sysdescr)
            return {"vendor": vendor, "os_version": m.group(1) if m else None}
    return {"vendor": "unknown", "os_version": None}


def probe_host(ip: str, timeout: float = 1.0) -> dict | None:
    """TCP connect probu: herhangi bir yönetim portu açıksa cihaz canlı sayılır."""
    open_ports = []
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    if not open_ports:
        return None
    return {"ip_address": ip, "open_ports": open_ports}


def grab_ssh_banner(ip: str, timeout: float = 2.0) -> str | None:
    """Port 22'ye bağlanıp sunucunun gönderdiği SSH banner satırını okur.
    Kimlik bilgisi GEREKTİRMEZ; SNMP kapalı cihazlarda bile vendor ipucu verir."""
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode("latin-1", errors="ignore").strip()
            return banner or None
    except OSError:
        return None


def identify_from_ssh_banner(banner: str) -> dict:
    """SSH banner'dan vendor tahmini (ör. 'SSH-2.0-Cisco-1.25')."""
    for pattern, vendor in SSH_BANNER_SIGNATURES:
        if re.search(pattern, banner, re.IGNORECASE):
            return {"vendor": vendor, "os_version": None}
    return {"vendor": "unknown", "os_version": None}


def snmp_sysdescr(ip: str, community: str = "public", timeout: int = 2) -> str | None:
    """SNMPv2c sysDescr.0 sorgusu. pysnmp yoksa None döner (opsiyonel bağımlılık)."""
    try:  # pragma: no cover - environment dependent
        from pysnmp.hlapi import (
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, getCmd,
        )
    except ImportError:
        return None
    iterator = getCmd(
        SnmpEngine(), CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
        ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
    )
    error_indication, error_status, _, var_binds = next(iterator)
    if error_indication or error_status:
        return None
    return str(var_binds[0][1])


def _identify_host(probed: dict, snmp_community: str) -> dict:
    """Katmanlı kimliklendirme: önce SNMP (en zengin), yoksa SSH banner.
    'discovery_source' hangi sinyalin işe yaradığını gösterir."""
    ip = probed["ip_address"]
    sysdescr = snmp_sysdescr(ip, snmp_community)
    if sysdescr:
        identity = identify_from_sysdescr(sysdescr)
        return {**probed, **identity, "sysdescr": sysdescr, "discovery_source": "SNMP"}

    banner = grab_ssh_banner(ip) if 22 in probed["open_ports"] else None
    if banner:
        identity = identify_from_ssh_banner(banner)
        source = "SSH_BANNER" if identity["vendor"] != "unknown" else "TCP_PROBE"
        return {**probed, **identity, "sysdescr": None,
                "ssh_banner": banner, "discovery_source": source}

    return {**probed, "vendor": "unknown", "os_version": None,
            "sysdescr": None, "discovery_source": "TCP_PROBE"}


def scan_network(cidr: str, snmp_community: str = "public",
                 max_workers: int = 64) -> list[dict]:
    """Bir CIDR bloğunu katmanlı tarar: TCP probe -> (SNMP | SSH banner).
    Her sonuç hangi sinyalle tanındığını 'discovery_source' ile bildirir."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts: Iterable[str] = (str(h) for h in network.hosts())
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        live = [p for p in pool.map(probe_host, hosts) if p is not None]
        for identified in pool.map(lambda p: _identify_host(p, snmp_community), live):
            results.append(identified)
    return results
