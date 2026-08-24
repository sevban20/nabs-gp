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
    # FortiSwitchOS: 'neighbors-detail' komşu başına tam kayıt verir
    # (sistem adı, port, yönetim IP'si). 'summary' yedek olarak denenir.
    "fortinet": ["get system lldp neighbors", "get switch lldp neighbors-detail"],
    "fortiswitch": ["get switch lldp neighbors-detail",
                    "get switch lldp neighbors-summary"],
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


def parse_fortinet_lldp(output: str) -> list[dict]:
    """FortiSwitchOS/FortiOS LLDP çıktısını ayrıştırır.

    Cisco ayrıştırıcıları bu formatı görmez: FortiSwitch 'Local Intf:' değil
    port başlığı, 'Port id:' değil 'Port ID:' yazar. Etiket yazımı sürümden
    sürüme değiştiği için satır bazlı ve toleranslı ilerler; blok sonunda
    en az bir sistem adı ya da uzak port bulunmuşsa komşu üretir.

    Beklenen biçim (yaklaşık):
        Neighbor on port port5:
            Chassis ID        : 00:09:0f:aa:bb:cc
            System Name       : SW-CORE-01
            Port ID           : gi1/0/24
            Management IP     : 10.10.10.1
    """
    neighbors: list[dict] = []
    cur: dict = {}
    local_if: str | None = None

    def flush() -> None:
        nonlocal cur
        if cur.get("remote_device") or cur.get("remote_interface"):
            neighbors.append({
                "remote_device": (cur.get("remote_device") or "unknown").split(".")[0],
                "remote_ip": cur.get("remote_ip"),
                "local_interface": cur.get("local_interface") or local_if,
                "remote_interface": cur.get("remote_interface"),
                "platform": cur.get("platform"),
                "protocol": "LLDP",
            })
        cur = {}

    # "Neighbor on port port5:" / "port5:" / "Interface: port5" → yerel port
    re_local = re.compile(
        r"(?i)^\s*(?:neighbors?\s+(?:on|for)\s+(?:local\s+)?(?:port|interface)\s+|"
        r"(?:local\s+)?(?:port|interface)\s*[:=]\s*)([\w/.\-]+)")
    re_local_bare = re.compile(r"(?i)^\s*([\w/.\-]+)\s*:\s*$")
    re_kv = re.compile(r"(?i)^\s*([A-Za-z][A-Za-z0-9 _/\-]*?)\s*[:=]\s*(.+?)\s*$")

    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        m = re_local.match(line)
        if m:
            flush()
            local_if = m.group(1)
            continue
        m = re_local_bare.match(line)
        if m and not re_kv.match(line):
            flush()
            local_if = m.group(1)
            continue
        if re.match(r"(?i)^\s*neighbor(\s+\d+)?\s*[:.]?\s*$", line):
            flush()
            continue

        m = re_kv.match(line)
        if not m:
            continue
        key = re.sub(r"\s+", " ", m.group(1)).strip().lower()
        val = m.group(2).strip().strip('"')
        if not val or val in ("N/A", "-"):
            continue

        if key.startswith("system name") or key in ("device id", "neighbor name"):
            flush_pending = cur.get("remote_device")
            if flush_pending:      # yeni komşu başlıyor
                flush()
            cur["remote_device"] = val
        elif key.startswith("port id") or key in ("neighbor port", "remote port"):
            cur["remote_interface"] = val
        elif key.startswith("port desc") and not cur.get("remote_interface"):
            cur["remote_interface"] = val
        elif key.startswith("system desc") or key == "platform":
            cur["platform"] = val[:120]
        elif ("management" in key and ("ip" in key or "address" in key)) or key == "mgmt ip":
            ipm = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", val)
            if ipm:
                cur["remote_ip"] = ipm.group(0)
        elif key in ("local port", "local interface", "local intf"):
            cur["local_interface"] = val

    flush()
    return neighbors


def parse_fortinet_arp(output: str) -> list[dict]:
    """FortiOS/FortiSwitchOS 'get system arp' -> (ip, mac).

    Biçim:  Address        Age(min)   Hardware Addr        Interface
            10.0.0.1       0          00:09:0f:aa:bb:cc    internal
    Cisco ayrıştırıcısı satırda 'Internet' kelimesi aradığı için bunu göremez.
    """
    entries = []
    for line in output.splitlines():
        m = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+"
            r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", line)
        if m:
            entries.append({"ip_address": m.group(1), "mac": m.group(2)})
    return entries


def parse_fortiswitch_mac_table(output: str) -> list[dict]:
    """FortiSwitchOS 'diagnose switch mac-address list' -> (vlan, mac, port).

    Biçim (yaklaşık):
        MAC: 00:09:0f:11:22:33   VLAN: 10   Port: port5   Flags: ... [dynamic]
    Alan sırası sürüme göre değişebildiği için etiketler tek tek aranır.
    """
    entries = []
    for line in output.splitlines():
        mac = re.search(r"(?i)\bMAC\s*[:=]\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})", line)
        if not mac:
            continue
        vlan = re.search(r"(?i)\bVLAN\s*[:=]\s*(\d+)", line)
        port = re.search(r"(?i)\b(?:port|interface)\s*[:=]\s*([\w/.\-]+)", line)
        typ = "STATIC" if re.search(r"(?i)static", line) else "DYNAMIC"
        entries.append({
            "vlan": vlan.group(1) if vlan else None,
            "mac": mac.group(1),
            "type": typ,
            "interface": port.group(1) if port else None,
        })
    return entries


def parse_neighbors_any(output: str) -> list[dict]:
    """Vendor formatını bilmeden komşu ayrıştırır: bilinen tüm ayrıştırıcıları
    dener, sonuç veren(ler)i birleştirir. Vendor etiketi yanlış girilmiş
    cihazlarda da çalışır."""
    result: list[dict] = []
    for fn in (parse_cdp_detail, parse_lldp_detail, parse_fortinet_lldp):
        try:
            result.extend(fn(output))
        except Exception:  # noqa: BLE001 - bir ayrıştırıcı diğerini engellemesin
            continue
    seen, uniq = set(), []
    for n in result:
        key = (n.get("remote_device"), n.get("local_interface"), n.get("remote_interface"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(n)
    return uniq


def parse_arp_any(output: str) -> list[dict]:
    """ARP çıktısını Cisco ve Fortinet biçimlerinin ikisine karşı da dener."""
    entries = parse_arp_table(output)
    if not entries:
        entries = parse_fortinet_arp(output)
    return entries


def parse_mac_any(output: str) -> list[dict]:
    """MAC tablosunu Cisco ve FortiSwitch biçimlerinin ikisine karşı da dener."""
    entries = parse_mac_address_table(output)
    if not entries:
        entries = parse_fortiswitch_mac_table(output)
    return entries


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


def normalize_device_name(name: str | None) -> str:
    """Cihaz adını KARŞILAŞTIRMA için normalize eder (görüntülemek için değil).

    Aynı switch, komşularına farklı yazımlarla görünebilir: "SW-C", "sw-c",
    "SW-C.dedas.local", "SW_C". Normalize edilmezse her yazım ayrı bir düğüm
    olur ve tek cihaz haritada birkaç kez görünür.
    """
    if not name:
        return ""
    n = str(name).strip().strip('"').split(".")[0]
    return re.sub(r"[\s_]+", "-", n).strip("-").lower()


def build_topology_graph(links: list[dict], assets: list[dict],
                         endpoints: list[dict] | None = None) -> dict:
    """Komşuluk link'lerinden ağ haritası grafiği üretir.
    Bilinen (envanterdeki) cihazlar risk skoruyla, keşfedilen ama envanterde
    olmayan komşular 'unmanaged' düğüm olarak işaretlenir.

    Düğüm kimliği ad yazımına DUYARSIZDIR: aynı cihaz farklı komşular
    tarafından farklı yazılmış olsa da (büyük/küçük harf, alan adı eki,
    alt çizgi) tek düğümde birleşir. Ad tutmazsa yönetim IP'si üzerinden
    envanterle eşleştirilir.

    endpoints verilirse (L2 keşif: ARP/MAC), her uç cihaz görüldüğü switch'e
    bir 'l2' kenarıyla bağlı yaprak düğüm (type='endpoint') olarak eklenir."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    # --- kimlik indeksleri: normalize ad ve yönetim IP'si ---
    asset_by_norm: dict[str, dict] = {}
    asset_by_ip: dict[str, dict] = {}
    for a in assets:
        asset_by_norm[normalize_device_name(a["hostname"])] = a
        if a.get("ip_address"):
            asset_by_ip[str(a["ip_address"])] = a

    canonical: dict[str, str] = {}   # normalize ad -> haritada kullanılacak id

    def resolve(name: str | None, ip: str | None = None) -> str | None:
        """Bir komşu adını haritadaki tekil kimliğe çevirir."""
        asset = asset_by_ip.get(str(ip)) if ip else None
        if asset is None:
            asset = asset_by_norm.get(normalize_device_name(name))
        if asset is not None:
            return asset["hostname"]

        norm = normalize_device_name(name)
        if not norm or norm == "unknown":
            return None          # adsız komşu — düğüm üretme, sahte kenar olmasın
        if norm not in canonical:
            canonical[norm] = str(name).strip().split(".")[0]
        return canonical[norm]

    def ensure_node(node_id: str, ip: str | None = None):
        if node_id in nodes:
            return
        asset = asset_by_norm.get(normalize_device_name(node_id))
        nodes[node_id] = {
            "id": node_id, "type": "device",
            "managed": asset is not None,
            "risk_score": asset["risk_score"] if asset else None,
            "vendor": asset["vendor"] if asset else None,
            "ip_address": asset["ip_address"] if asset else ip,
            "is_reachable": asset.get("is_reachable") if asset else None,
        }

    # Envanterdeki her cihaz düğüm olsun (link'i olmasa bile haritada görünsün)
    for a in assets:
        ensure_node(a["hostname"])

    seen_pairs: set[tuple] = set()
    for link in links:
        src = resolve(link.get("source_device"))
        dst = resolve(link.get("remote_device"), link.get("remote_ip"))
        if not src or not dst or src == dst:
            continue                       # kendine link ya da adsız komşu
        ensure_node(src)
        ensure_node(dst, link.get("remote_ip"))
        pair = tuple(sorted([src, dst]))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        edges.append({
            "source": src, "target": dst, "kind": "neighbor",
            "protocol": link.get("protocol"),
            "local_interface": link.get("local_interface"),
            "remote_interface": link.get("remote_interface"),
            # Arayüzün komşu detayını gösterebilmesi için taşınır
            "remote_ip": link.get("remote_ip"),
            "platform": link.get("platform"),
        })

    for ep in endpoints or []:
        parent = resolve(ep.get("seen_on_device"))
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
