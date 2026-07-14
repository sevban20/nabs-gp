"""Huawei / Aruba / FortiSwitch / OpenWrt / MikroTik tanıma, komut matrisi
ve genişletilmiş maskeleme testleri."""
from app.services.cve_sync import build_cpe_string
from app.services.discovery import identify_from_ssh_banner, identify_from_sysdescr
from app.services.sanitizer import sanitize_raw_config
from app.workers.tasks import BACKUP_COMMAND_MATRIX, LINUX_VENDORS, SCRAPLI_PLATFORM_MAP


def test_sysdescr_huawei():
    d = identify_from_sysdescr("Huawei Versatile Routing Platform Software VRP (R) "
                               "software, Version 8.180 (S5720 V200R019C10)")
    assert d["vendor"] == "huawei_vrp"


def test_sysdescr_aruba_cx_before_procurve():
    d = identify_from_sysdescr("ArubaOS-CX FL.10.09.0010, 6300M")
    assert d["vendor"] == "aruba_aoscx"


def test_sysdescr_procurve():
    d = identify_from_sysdescr("ProCurve J9086A Switch 2610-24, revision R.11.72")
    assert d["vendor"] == "aruba_procurve"


def test_sysdescr_openwrt():
    d = identify_from_sysdescr("OpenWrt 23.05.2 Linux 5.15.137")
    assert d["vendor"] == "openwrt"


def test_sysdescr_fortiswitch_before_fortigate():
    d = identify_from_sysdescr("FortiSwitch-124F v7.2.4,build0451")
    assert d["vendor"] == "fortiswitch"


def test_sysdescr_mikrotik():
    d = identify_from_sysdescr("MikroTik RouterOS 7.11.2 (stable) CCR2004")
    assert d["vendor"] == "mikrotik"


def test_ssh_banner_dropbear_is_openwrt_candidate():
    assert identify_from_ssh_banner("SSH-2.0-dropbear_2022.83")["vendor"] == "openwrt"
    assert identify_from_ssh_banner("SSH-2.0-Huawei-1.5")["vendor"] == "huawei_vrp"


def test_backup_matrix_and_platforms_cover_new_vendors():
    assert BACKUP_COMMAND_MATRIX["huawei_vrp"] == "display current-configuration"
    assert BACKUP_COMMAND_MATRIX["aruba_aoscx"] == "show running-config"
    assert SCRAPLI_PLATFORM_MAP["huawei_vrp"] == "huawei_vrp"
    # openwrt CLI matrisinde YOK; Linux yolundan alınır
    assert "openwrt" not in BACKUP_COMMAND_MATRIX
    assert "openwrt" in LINUX_VENDORS


def test_fortinet_family_uses_generic_driver_not_scrapli_platform():
    """Regresyon: scrapli-community'de 'fortinet' ağ platformu yok.
    Fortinet ailesi SCRAPLI_PLATFORM_MAP'te OLMAMALI, GENERIC_VENDORS'ta OLMALI."""
    from app.workers.tasks import GENERIC_VENDORS
    assert "fortinet" not in SCRAPLI_PLATFORM_MAP
    assert "fortiswitch" not in SCRAPLI_PLATFORM_MAP
    assert {"fortinet", "fortiswitch"} <= GENERIC_VENDORS


def test_scrapli_ssh_kwargs_defaults(tmp_path, monkeypatch):
    """Ortak Scrapli kwargs: strict-key kapalı; ssh_config dosyası varsa yolu,
    yoksa sistem varsayılanı (True)."""
    import app.workers.tasks as t
    # config dosyası yoksa
    monkeypatch.setattr(t, "SSH_CONFIG_FILE", str(tmp_path / "nope"))
    kw = t._scrapli_ssh_kwargs()
    assert kw["auth_strict_key"] is False and kw["ssh_config_file"] is True
    # config dosyası varsa yolu verir
    cfg = tmp_path / "ssh_config"
    cfg.write_text("Host *\n")
    monkeypatch.setattr(t, "SSH_CONFIG_FILE", str(cfg))
    assert t._scrapli_ssh_kwargs()["ssh_config_file"] == str(cfg)


def test_fetch_routes_fortiswitch_to_generic(monkeypatch):
    """_fetch_config_over_ssh, fortiswitch için GenericDriver yolunu çağırmalı
    (Scrapli network sürücüsünü DEĞİL)."""
    import app.workers.tasks as t

    calls = {}

    def fake_generic(h, u, p, c):
        calls["generic"] = c
        return "config"
    monkeypatch.setattr(t, "_fetch_generic_config", fake_generic)

    def scrapli_boom(*a, **k):
        raise AssertionError("Scrapli network sürücüsü çağrılmamalıydı")
    # scrapli import edilirse patlasın
    monkeypatch.setitem(__import__("sys").modules, "scrapli",
                        type("m", (), {"Scrapli": scrapli_boom}))

    out = t._fetch_config_over_ssh("10.0.0.1", "admin", "pw", None, "fortiswitch")
    assert out == "config"
    assert calls["generic"] == t.BACKUP_COMMAND_MATRIX["fortiswitch"]


def test_cpe_for_new_vendors():
    assert build_cpe_string("huawei_vrp", "8.180").startswith("cpe:2.3:o:huawei:vrp:8.180")
    assert build_cpe_string("openwrt", "23.05.2").startswith("cpe:2.3:o:openwrt:openwrt:23.05.2")


def test_openwrt_uci_secrets_masked():
    cfg = (
        "config wifi-iface 'default'\n"
        "\toption ssid 'HomeNet'\n"
        "\toption encryption 'psk2'\n"
        "\toption key 'SuperSecretWifiPass'\n"
        "config system\n"
        "\toption password 'r00tpass'\n"
    )
    out = sanitize_raw_config(cfg)
    assert "SuperSecretWifiPass" not in out
    assert "r00tpass" not in out
    assert out.count("<MASKED_SECRET>") >= 2
    assert "HomeNet" in out  # gizli olmayan alanlar korunur


def test_huawei_cipher_password_masked():
    out = sanitize_raw_config("local-user admin password irreversible-cipher $1c$AbCdEf123")
    assert "$1c$AbCdEf123" not in out
    assert "<MASKED_SECRET>" in out


def test_mikrotik_psk_masked():
    out = sanitize_raw_config('set wpa2-pre-shared-key="MyWifiKey2024"')
    assert "MyWifiKey2024" not in out
    assert "<MASKED_SECRET>" in out
