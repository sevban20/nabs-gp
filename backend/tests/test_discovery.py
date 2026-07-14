"""Faz 2: sysDescr kimliklendirme ve TCP prob davranışı."""
from app.services.discovery import identify_from_sysdescr, probe_host


def test_identify_cisco_iosxe():
    d = identify_from_sysdescr(
        "Cisco IOS-XE Software, Catalyst L3 Switch, Version 17.6.4, RELEASE")
    assert d["vendor"] == "cisco_ios"
    assert d["os_version"] == "17.6.4,"[:-1] or d["os_version"].startswith("17.6.4")


def test_identify_fortigate():
    d = identify_from_sysdescr("FortiGate-100F v7.0.12,build0523,230425")
    assert d["vendor"] == "fortinet"
    assert d["os_version"] == "7.0.12"


def test_identify_juniper():
    d = identify_from_sysdescr("Juniper Networks, Inc. mx240 , JUNOS 21.4R3.15")
    assert d["vendor"] == "juniper_junos"
    assert d["os_version"] == "21.4R3.15"


def test_identify_paloalto():
    d = identify_from_sysdescr("Palo Alto Networks PA-3220 series firewall 10.2.4")
    assert d["vendor"] == "paloalto"
    assert d["os_version"] == "10.2.4"


def test_identify_unknown():
    d = identify_from_sysdescr("Linux ubuntu 5.15.0 x86_64")
    assert d["vendor"] == "unknown"


def test_probe_dead_host_returns_none():
    # TEST-NET-1 (RFC 5737) yönlendirilemez; probe hızlıca None dönmeli.
    assert probe_host("192.0.2.1", timeout=0.3) is None
