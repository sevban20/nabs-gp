"""Komşuluk keşfi (LLDP/CDP) ve ARP tablosu parse'ı — ağ topolojisi çıkarımı.

Bir cihaza SSH ile bağlanıp 'show lldp neighbors detail' / 'show cdp
neighbors detail' çıktısını okumak, taramayla asla görülemeyecek komşuları
(SNMP kapalı, ping'e cevapsız) platform ve port bilgisiyle ortaya çıkarır.
Bu, ağ haritasının kenarlarını (link) besleyen ana kaynaktır.

Parser'lar saf metin işler; canlı SSH toplama tasks.py'de mock'lanabilir
biçimde ayrılmıştır (test edilebilirlik).
"""
import re

# Komşuluk komut matrisi (read-only)
NEIGHBOR_COMMANDS = {
    "cisco_ios": ["show cdp neighbors detail", "show lldp neighbors detail"],
    "fortinet": ["get system lldp neighbors"],
    "fortiswitch": ["get switch lldp neighbors-summary"],
    "juniper_junos": ["show lldp neighbors"],
    "paloalto": ["show lldp neighbors all"],
    "huawei_vrp": ["display lldp neighbor brief", "display lldp neighbor"],
    "aruba_aoscx": ["show lldp neighbor-info"],
    "aruba_procurve": ["show lldp info remote-device"],
    "openwrt": ["lldpcli show neighbors"],  # lldpd paketi kuruluysa
    "linux": ["lldpcli show neighbors"],
}
ARP_COMMANDS = {
    "cisco_ios": "show ip arp",
    "juniper_junos": "show arp",
}


def parse_cdp_detail(output: str) -> list[dict]:
    """Cisco 'show cdp neighbors detail' -> komşu listesi.
    Her blok 'Device ID' ile başlar."""
    neighbors = []
    for block in re.split(r"-{4,}", output):
        if "Device ID" not in block:
            continue
        dev = re.search(r"Device ID:\s*([^\s,]+)", block)
        ip = re.search(r"IP(?:v4)? address:\s*([\d.]+)", block)
        local = re.search(r"Interface:\s*([^\s,]+)", block)
        remote = re.search(r"Port ID \(outgoing port\):\s*(.+)", block)
        platform = re.search(r"Platform:\s*([^,]+)", block)
        if dev:
            neighbors.append({
                "remote_device": dev.group(1).split(".")[0],
                "remote_ip": ip.group(1) if ip else None,
                "local_interface": local.group(1) if local else None,
                "remote_interface": remote.group(1).strip() if remote else None,
                "platform": platform.group(1).strip() if platform else None,
                "protocol": "CDP",
            })
    return neighbors


def parse_lldp_detail(output: str) -> list[dict]:
    """Cisco 'show lldp neighbors detail' -> komşu listesi."""
    neighbors = []
    for block in re.split(r"-{4,}|(?=Local Intf:)", output):
        if "System Name" not in block and "Port id" not in block:
            continue
        name = re.search(r"System Name:\s*(.+)", block)
        local = re.search(r"Local Intf:\s*(\S+)", block)
        remote = re.search(r"Port id:\s*(.+)", block)
        ip = re.search(r"(?:Management Addresses:.*?IP:\s*([\d.]+)|IP:\s*([\d.]+))",
                       block, re.DOTALL)
        if name or remote:
            ip_val = None
            if ip:
                ip_val = ip.group(1) or ip.group(2)
            neighbors.append({
                "remote_device": (name.group(1).strip().split(".")[0] if name else "unknown"),
                "remote_ip": ip_val,
                "local_interface": local.group(1) if local else None,
                "remote_interface": remote.group(1).strip() if remote else None,
                "platform": None,
                "protocol": "LLDP",
            })
    return neighbors


def parse_arp_table(output: str) -> list[dict]:
    """Cisco 'show ip arp' -> (ip, mac) listesi. Segmentte canlı ne var
    sorusunun en güvenilir cevabı (cihaz işbirliği gerektirmez)."""
    entries = []
    for line in output.splitlines():
        m = re.search(r"Internet\s+([\d.]+)\s+\S+\s+([0-9a-fA-F.:]{4,})", line)
        if m:
            entries.append({"ip_address": m.group(1), "mac": m.group(2)})
    return entries


def parse_mac_address_table(output: str) -> list[dict]:
    """Cisco 'show mac address-table' -> (vlan, mac, type, interface) listesi.
    L2 switch'lerde hangi MAC hangi portta görülüyor — uç cihazların ağdaki
    fiziksel konumunu verir (topolojide endpoint yerleşimi)."""
    entries = []
    for line in output.splitlines():
        # Vlan  Mac Address  Type  Ports   (ör: "  10  00aa.bbcc.dd01  DYNAMIC  Gi0/5")
        m = re.search(
            r"^\s*(\d+|All|-)\s+([0-9a-fA-F]{2,4}[.:-][0-9a-fA-F.:-]{6,})\s+"
            r"(\w+)\s+(\S+)", line)
        if not m:
            continue
        iface = m.group(4)
        # başlık/özet satırlarını ele
        if iface.lower() in ("ports", "-----"):
            continue
        entries.append({
            "vlan": m.group(1), "mac": m.group(2),
            "type": m.group(3).upper(), "interface": iface,
        })
    return entries


def merge_l2_inventory(arp_entries: list[dict], mac_entries: list[dict],
                       source_device: str) -> list[dict]:
    """ARP (ip↔mac) ve MAC tablosu (mac↔port) verisini birleştirip keşfedilen
    host kayıtları üretir. MAC üreticisi OUI'den atanır. Bir cihaz için tüm
    L2 keşif çıktısını tek listede toplar (uç cihazların konumu dahil)."""
    from app.services.oui import normalize_mac, vendor_from_mac

    # mac -> ip haritası (ARP)
    ip_by_mac: dict[str, str] = {}
    for e in arp_entries:
        nm = normalize_mac(e.get("mac", ""))
        if nm and e.get("ip_address"):
            ip_by_mac[nm] = e["ip_address"]

    hosts: dict[str, dict] = {}

    def upsert(mac_raw, ip, iface, vlan, source):
        nm = normalize_mac(mac_raw)
        if not nm:
            return
        existing = hosts.get(nm)
        entry = {
            "mac": nm, "ip_address": ip, "oui_vendor": vendor_from_mac(nm),
            "seen_on_device": source_device, "seen_on_interface": iface,
            "vlan": vlan, "source": source,
        }
        # MAC_TABLE port bilgisi ARP'a göre daha değerli; onu koru
        if existing is None or (source == "MAC_TABLE" and existing["source"] == "ARP"):
            hosts[nm] = entry
        elif ip and not existing.get("ip_address"):
            existing["ip_address"] = ip

    for e in mac_entries:
        nm = normalize_mac(e.get("mac", ""))
        upsert(e.get("mac"), ip_by_mac.get(nm) if nm else None,
               e.get("interface"), e.get("vlan"), "MAC_TABLE")

    for e in arp_entries:
        nm = normalize_mac(e.get("mac", ""))
        if nm and nm not in hosts:
            upsert(e.get("mac"), e.get("ip_address"), None, None, "ARP")

    return list(hosts.values())


def build_topology_graph(links: list[dict], assets: list[dict],
                         endpoints: list[dict] | None = None) -> dict:
    """Komşuluk link'lerinden ağ haritası grafiği üretir.
    Bilinen (envanterdeki) cihazlar risk skoruyla, keşfedilen ama envanterde
    olmayan komşular 'unmanaged' düğüm olarak işaretlenir.

    endpoints verilirse (L2 keşif: ARP/MAC), her uç cihaz görüldüğü switch'e
    bir 'l2' kenarıyla bağlı yaprak düğüm (type='endpoint') olarak eklenir."""
    known = {a["hostname"]: a for a in assets}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def ensure_node(name: str):
        if name not in nodes:
            asset = known.get(name)
            nodes[name] = {
                "id": name, "type": "device",
                "managed": asset is not None,
                "risk_score": asset["risk_score"] if asset else None,
                "vendor": asset["vendor"] if asset else None,
                "ip_address": asset["ip_address"] if asset else None,
                "is_reachable": asset.get("is_reachable") if asset else None,
            }

    # Envanterdeki her cihaz düğüm olsun (link'i olmasa bile haritada görünsün)
    for a in assets:
        ensure_node(a["hostname"])

    seen_pairs: set[tuple] = set()
    for link in links:
        src, dst = link["source_device"], link["remote_device"]
        ensure_node(src)
        ensure_node(dst)
        pair = tuple(sorted([src, dst]))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        edges.append({
            "source": src, "target": dst, "kind": "neighbor",
            "protocol": link.get("protocol"),
            "local_interface": link.get("local_interface"),
            "remote_interface": link.get("remote_interface"),
        })

    for ep in endpoints or []:
        parent = ep.get("seen_on_device")
        if not parent:
            continue
        ensure_node(parent)
        ep_id = f"ep:{ep['mac']}"
        if ep_id not in nodes:
            nodes[ep_id] = {
                "id": ep_id, "type": "endpoint", "managed": False,
                "mac": ep["mac"], "ip_address": ep.get("ip_address"),
                "oui_vendor": ep.get("oui_vendor"),
                "label": ep.get("ip_address") or f"…{ep['mac'][-6:]}",
            }
        edges.append({
            "source": parent, "target": ep_id, "kind": "l2",
            "local_interface": ep.get("seen_on_interface"),
            "vlan": ep.get("vlan"),
        })

    return {"nodes": list(nodes.values()), "edges": edges}
