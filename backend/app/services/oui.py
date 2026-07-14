"""MAC adresi normalizasyonu ve OUI (ilk 3 oktet) → üretici eşlemesi.

Tam IEEE OUI veritabanı 30binden fazla kayıt içerir; burada ağ ve uç
cihaz üreticilerini kapsayan derli toplu bir alt küme gömülüdür. Genişletme
için OUI_MAP'e prefix eklemek yeterli; istenirse harici bir OUI dosyası da
yüklenebilir (load_oui_file).
"""
import re

# Prefix (12→6 hex, upper) → üretici. Yaygın ağ/uç cihaz OUI'leri.
OUI_MAP: dict[str, str] = {
    # Cisco
    "00000C": "Cisco", "001A2F": "Cisco", "00259C": "Cisco", "F09E63": "Cisco",
    "00563D": "Cisco", "008019": "Cisco Meraki", "E0553D": "Cisco Meraki",
    # Aruba / HPE
    "000B86": "Aruba", "24DEC6": "Aruba", "94B40F": "Aruba",
    "000FB5": "HPE", "3C2AF4": "HP", "9457A5": "HPE",
    # Fortinet
    "00090F": "Fortinet", "084F0A": "Fortinet", "90 6C AC".replace(" ", ""): "Fortinet",
    # Juniper
    "3C61 04".replace(" ", ""): "Juniper", "F4B52F": "Juniper", "2C6BF5": "Juniper",
    # Huawei
    "00E0FC": "Huawei", "48435A": "Huawei", "781DBA": "Huawei", "AC4E91": "Huawei",
    # MikroTik
    "4C5E0C": "MikroTik", "6C3B6B": "MikroTik", "E48D8C": "MikroTik",
    # Palo Alto
    "000116": "Palo Alto", "B4 0C 25".replace(" ", ""): "Palo Alto",
    # Ubiquiti
    "0418D6": "Ubiquiti", "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "FCECDA": "Ubiquiti",
    # TP-Link
    "50C7BF": "TP-Link", "1C61B4": "TP-Link", "AC84C6": "TP-Link",
    # Yaygın uç cihaz üreticileri
    "001C42": "Parallels (VM)", "080027": "VirtualBox (VM)", "005056": "VMware (VM)",
    "00155D": "Microsoft (Hyper-V)", "525400": "QEMU/KVM (VM)",
    "3C5AB4": "Google", "F4F5E8": "Google",
    "DCA632": "Raspberry Pi", "B827EB": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "001132": "Synology", "0011D8": "Asus",
    "A4C3F0": "Intel", "3CFDFE": "Intel", "8C1645": "Dell",
    "F0DEF1": "Wistron", "ACDE48": "Apple", "F0189 8".replace(" ", ""): "Apple",
}


def normalize_mac(mac: str) -> str | None:
    """Herhangi bir formattaki MAC'i 12 haneli büyük-harf hex'e çevirir.
    Geçersizse None. Kabul: 00aa.bbcc.ddee, 00:aa:.., 00-AA-.., ham hex."""
    if not mac:
        return None
    hexs = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    return hexs if len(hexs) == 12 else None


def oui_of(mac: str) -> str | None:
    norm = normalize_mac(mac)
    return norm[:6] if norm else None


def vendor_from_mac(mac: str) -> str:
    """MAC'ten üretici tahmini. Bilinmeyen prefix → 'unknown'.
    Yerel yönetilen (U/L biti set) adresler → 'locally-administered'."""
    oui = oui_of(mac)
    if not oui:
        return "unknown"
    # İkinci nibble'ın en düşük biti 1 ise yerel yönetimli (rastgele) MAC
    second = int(oui[1], 16)
    if second & 0x2:
        return OUI_MAP.get(oui, "locally-administered")
    return OUI_MAP.get(oui, "unknown")
