"""L2 keşif: OUI/MAC üretici, MAC tablosu parse, ARP+MAC birleştirme ve
keşfedilen host uçları + onboard."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import DiscoveredHost, User
from app.services.oui import normalize_mac, vendor_from_mac
from app.services.topology import merge_l2_inventory, parse_mac_address_table

client = TestClient(app)


# ---- pure ----

def test_normalize_mac_formats():
    assert normalize_mac("00aa.bbcc.ddee") == "00AABBCCDDEE"
    assert normalize_mac("00:AA:BB:CC:DD:EE") == "00AABBCCDDEE"
    assert normalize_mac("00-aa-bb-cc-dd-ee") == "00AABBCCDDEE"
    assert normalize_mac("xyz") is None


def test_vendor_from_mac_known_and_unknown():
    assert vendor_from_mac("00:00:0C:11:22:33") == "Cisco"       # 00000C
    assert vendor_from_mac("00:50:56:aa:bb:cc") == "VMware (VM)"  # 005056
    assert vendor_from_mac("FF:FF:FF:00:00:00") in ("unknown", "locally-administered")


def test_parse_mac_address_table():
    out = (
        "          Mac Address Table\n"
        "-------------------------------------------\n"
        "Vlan    Mac Address       Type        Ports\n"
        "----    -----------       --------    -----\n"
        "  10    00aa.bbcc.dd01    DYNAMIC     Gi0/5\n"
        "  10    0050.56aa.bb01    DYNAMIC     Gi0/6\n"
        "   1    aabb.ccdd.eeff    STATIC      CPU\n"
    )
    rows = parse_mac_address_table(out)
    macs = {r["mac"].replace(".", "").lower() for r in rows}
    assert "00aabbccdd01" in macs
    dyn = [r for r in rows if r["type"] == "DYNAMIC"]
    assert len(dyn) == 2
    assert dyn[0]["interface"] == "Gi0/5" and dyn[0]["vlan"] == "10"


def test_merge_l2_inventory_joins_arp_and_mac():
    arp = [{"ip_address": "10.1.1.50", "mac": "0000.0c11.2201"}]  # gerçek Cisco OUI
    mac = [{"vlan": "10", "mac": "0000.0c11.2201", "type": "DYNAMIC", "interface": "Gi0/5"},
           {"vlan": "10", "mac": "0050.56aa.bb01", "type": "DYNAMIC", "interface": "Gi0/6"}]
    hosts = merge_l2_inventory(arp, mac, "ACCESS-SW-1")
    by_mac = {h["mac"]: h for h in hosts}
    # ARP'lı MAC ip ve port ile
    h1 = by_mac["00000C112201"]
    assert h1["ip_address"] == "10.1.1.50" and h1["seen_on_interface"] == "Gi0/5"
    assert h1["oui_vendor"] == "Cisco" and h1["source"] == "MAC_TABLE"
    # ARP'sız MAC ip'siz ama vendor'lı (VMware)
    h2 = by_mac["005056AABB01"]
    assert h2["ip_address"] is None and h2["oui_vendor"] == "VMware (VM)"


# ---- API + onboard ----

@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for u, r in [("l2_op", "operator"), ("l2_viewer", "viewer")]:
        if not db.query(User).filter(User.username == u).first():
            db.add(User(username=u, password_hash=hash_password("Passw0rd!x"), role=r))
    # keşfedilen host tohumu
    if not db.query(DiscoveredHost).filter(DiscoveredHost.mac == "00AABBCCDD01").first():
        db.add(DiscoveredHost(mac="00AABBCCDD01", ip_address="10.1.1.50", oui_vendor="Cisco",
                              seen_on_device="ACCESS-SW-1", seen_on_interface="Gi0/5",
                              vlan="10", source="MAC_TABLE", is_onboarded=False))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_list_discovered_hosts():
    r = client.get("/api/v1/discovery/hosts", headers=_token("l2_viewer"))
    assert r.status_code == 200
    assert any(h["mac"] == "00AABBCCDD01" for h in r.json())


def test_onboard_discovered_host_creates_asset():
    host_id = [h for h in client.get("/api/v1/discovery/hosts",
               headers=_token("l2_op")).json() if h["mac"] == "00AABBCCDD01"][0]["id"]
    r = client.post(f"/api/v1/discovery/hosts/{host_id}/onboard", headers=_token("l2_op"),
                    json={"hostname": "ACCESS-SW-05", "vendor": "cisco_ios",
                          "backup_method": "ACTIVE_SSH"})
    assert r.status_code == 201
    assert r.json()["ip_address"] == "10.1.1.50"
    # artık unmanaged listede görünmemeli
    remaining = client.get("/api/v1/discovery/hosts", headers=_token("l2_op")).json()
    assert not any(h["mac"] == "00AABBCCDD01" for h in remaining)


def test_ssh_probe_requires_valid_credential():
    r = client.post("/api/v1/discovery/ssh-probe", headers=_token("l2_op"),
                    json={"ip_address": "10.1.1.50", "credential_id": "nonexistent"})
    assert r.status_code == 404
