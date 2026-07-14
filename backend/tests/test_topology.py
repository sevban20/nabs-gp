"""LLDP/CDP/ARP parser'ları, SSH banner ve topoloji graph testleri."""
from app.services.discovery import identify_from_ssh_banner
from app.services.topology import (
    build_topology_graph, parse_arp_table, parse_cdp_detail, parse_lldp_detail,
)

CDP_SAMPLE = """\
-------------------------
Device ID: CORE-SW-02.corp.local
Entry address(es):
  IP address: 10.1.1.2
Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/24
Holdtime : 145 sec
-------------------------
Device ID: EDGE-RTR-01.corp.local
Entry address(es):
  IP address: 10.1.1.254
Platform: cisco ISR4451,  Capabilities: Router
Interface: GigabitEthernet0/2,  Port ID (outgoing port): GigabitEthernet0/0/1
"""

LLDP_SAMPLE = """\
------------------------------------------------
Local Intf: Gi0/3
Chassis id: 00aa.bb11.2233
Port id: Gi1/0/5
System Name: ACCESS-SW-07
Management Addresses:
    IP: 10.1.2.7
------------------------------------------------
Local Intf: Gi0/4
Port id: eth2
System Name: SRV-ESX-01
"""

ARP_SAMPLE = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.1.1.1                -   00aa.bbcc.dd01  ARPA   Vlan1
Internet  10.1.1.50              12   00aa.bbcc.dd50  ARPA   Vlan1
"""


def test_parse_cdp_two_neighbors():
    n = parse_cdp_detail(CDP_SAMPLE)
    assert len(n) == 2
    assert n[0]["remote_device"] == "CORE-SW-02"          # domain kırpıldı
    assert n[0]["remote_ip"] == "10.1.1.2"
    assert n[0]["local_interface"] == "GigabitEthernet0/1"
    assert n[0]["remote_interface"] == "GigabitEthernet0/24"
    assert n[0]["protocol"] == "CDP"


def test_parse_lldp_neighbors():
    n = parse_lldp_detail(LLDP_SAMPLE)
    names = {x["remote_device"] for x in n}
    assert "ACCESS-SW-07" in names and "SRV-ESX-01" in names
    acc = next(x for x in n if x["remote_device"] == "ACCESS-SW-07")
    assert acc["remote_ip"] == "10.1.2.7"
    assert acc["protocol"] == "LLDP"


def test_parse_arp_table():
    e = parse_arp_table(ARP_SAMPLE)
    assert {"ip_address": "10.1.1.50", "mac": "00aa.bbcc.dd50"} in e
    assert len(e) == 2


def test_ssh_banner_identification():
    assert identify_from_ssh_banner("SSH-2.0-Cisco-1.25")["vendor"] == "cisco_ios"
    assert identify_from_ssh_banner("SSH-2.0-OpenSSH_7.4 Junos")["vendor"] == "juniper_junos"
    assert identify_from_ssh_banner("SSH-2.0-OpenSSH_8.0")["vendor"] == "unknown"


def test_build_topology_graph_marks_unmanaged():
    assets = [
        {"hostname": "CORE-SW-01", "ip_address": "10.1.1.1", "vendor": "cisco_ios",
         "risk_score": 90, "is_reachable": True},
    ]
    links = [
        {"source_device": "CORE-SW-01", "remote_device": "CORE-SW-02",
         "protocol": "CDP", "local_interface": "Gi0/1", "remote_interface": "Gi0/24"},
    ]
    g = build_topology_graph(links, assets)
    ids = {n["id"]: n for n in g["nodes"]}
    assert ids["CORE-SW-01"]["managed"] is True
    assert ids["CORE-SW-02"]["managed"] is False   # yalnızca komşuluktan bilinir
    assert len(g["edges"]) == 1


def test_topology_graph_dedupes_bidirectional_links():
    assets = []
    links = [
        {"source_device": "A", "remote_device": "B", "protocol": "CDP"},
        {"source_device": "B", "remote_device": "A", "protocol": "CDP"},  # ters yön aynı link
    ]
    g = build_topology_graph(links, assets)
    assert len(g["edges"]) == 1
