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


# ---------------------------------------------------------------------------
# Harici OUI veritabanı
#
# Yukarıdaki gömülü tablo yalnızca ~50 ağ üreticisini kapsar; gerçek bir ağda
# uç cihazların büyük kısmı bu listede yoktur ve 'unknown' görünür. IEEE kayıt
# defterinde 50 binden fazla tahsis var. Dosya sağlanırsa buradan yüklenir,
# gömülü tablo üzerine yazmaz (elle bakımlı isimler — "Cisco Meraki" gibi —
# korunur, dosya yalnızca eksikleri doldurur).
#
# Kaynak dosya biçimlerinin üçü de desteklenir:
#   IEEE oui.csv   : Registry,Assignment,Organization Name,Organization Address
#   IEEE oui.txt   : "00-09-0F   (hex)  Fortinet, Inc."
#   nmap / manuf   : "00090F Fortinet" ya da "00:09:0F<TAB>Fortinet"
# ---------------------------------------------------------------------------
import logging as _logging  # noqa: E402
import os as _os  # noqa: E402

_logger = _logging.getLogger("nabs.oui")
OUI_FILE_PATH = _os.getenv("NABS_OUI_FILE", "/var/nabs/oui/oui.csv")
_FILE_OUI: dict[str, str] | None = None   # None = henüz denenmedi


def _parse_oui_stream(lines) -> dict[str, str]:
    """Desteklenen üç biçimi de aynı ayrıştırıcıyla okur: satırdan ilk 6 hex
    haneyi ve ardından gelen kurum adını çıkarır."""
    out: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # IEEE CSV: MA-L,00090F,"Fortinet, Inc.",...
        if line.upper().startswith(("MA-L,", "MA-M,", "MA-S,")):
            parts = _csv_split(line)
            if len(parts) >= 3:
                pref = re.sub(r"[^0-9A-Fa-f]", "", parts[1]).upper()[:6]
                name = parts[2].strip().strip('"')
                if len(pref) == 6 and name:
                    out[pref] = name
            continue

        # IEEE TXT: 00-09-0F   (hex)  Fortinet, Inc.
        m = re.match(r"^([0-9A-Fa-f]{2}[-:]){2}[0-9A-Fa-f]{2}\s+\(hex\)\s+(.+)$", line)
        if m:
            pref = re.sub(r"[^0-9A-Fa-f]", "", line.split()[0]).upper()[:6]
            out[pref] = m.group(2).strip()
            continue

        # nmap / manuf: 00090F Fortinet   |   00:09:0F<TAB>Fortinet
        m = re.match(r"^([0-9A-Fa-f]{6}|(?:[0-9A-Fa-f]{2}[:-]){2}[0-9A-Fa-f]{2})\s+(.+)$",
                     line)
        if m:
            pref = re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()[:6]
            name = m.group(2).split("\t")[0].strip()
            if len(pref) == 6 and name:
                out[pref] = name
    return out


def _csv_split(line: str) -> list[str]:
    """Tırnak içindeki virgülleri koruyan basit CSV bölmesi (kurum adlarında
    'Fortinet, Inc.' gibi virgüller var)."""
    import csv  # noqa: PLC0415
    import io  # noqa: PLC0415
    return next(csv.reader(io.StringIO(line)))


def load_oui_file(path: str | None = None) -> int:
    """OUI dosyasını yükler, yüklenen kayıt sayısını döndürür. Dosya yoksa 0."""
    global _FILE_OUI
    target = path or OUI_FILE_PATH
    try:
        opener = open
        if target.endswith(".gz"):
            import gzip  # noqa: PLC0415
            opener = gzip.open
        with opener(target, "rt", encoding="utf-8", errors="ignore") as fh:
            data = _parse_oui_stream(fh)
    except FileNotFoundError:
        _FILE_OUI = {}
        _logger.warning(
            "OUI veritabanı bulunamadı (%s). Gömülü tablo yalnızca %d üretici "
            "içerir; uç cihazların çoğu 'unknown' görünecek. Doldurmak için: "
            "./scripts/fetch_oui.sh", target, len(OUI_MAP))
        return 0
    except Exception as exc:  # noqa: BLE001
        _FILE_OUI = {}
        _logger.error("OUI veritabanı okunamadı (%s): %s", target, exc)
        return 0

    _FILE_OUI = data
    _logger.info("OUI veritabanı yüklendi: %d kayıt (%s)", len(data), target)
    return len(data)


def _lookup(oui: str) -> str | None:
    """Önce elle bakımlı tablo, sonra harici dosya."""
    if oui in OUI_MAP:
        return OUI_MAP[oui]
    if _FILE_OUI is None:
        load_oui_file()
    return (_FILE_OUI or {}).get(oui)


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
    hit = _lookup(oui)
    if hit:
        return hit
    # İkinci nibble'ın en düşük biti 1 ise yerel yönetimli (rastgele) MAC —
    # bu adresler hiçbir üreticiye tahsis edilmez, 'unknown' demek yanıltıcı olur.
    if int(oui[1], 16) & 0x2:
        return "locally-administered"
    return "unknown"
