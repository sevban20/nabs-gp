"""Ağ haritasına L2 uç cihazlarının eklenmesi (endpoint düğümleri)."""
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_password
from app.core.database import Base, SessionLocal, engine
from app.main import app
from app.models.models import Asset, DiscoveredHost, TopologyLink, User
from app.services.topology import build_topology_graph

client = TestClient(app)


def test_build_graph_with_endpoints():
    assets = [{"hostname": "CORE-SW", "ip_address": "10.1.1.1", "vendor": "cisco_ios",
               "risk_score": 90, "is_reachable": True}]
    links = []
    endpoints = [
        {"mac": "00000C112201", "ip_address": "10.1.1.50", "oui_vendor": "Cisco",
         "seen_on_device": "CORE-SW", "seen_on_interface": "Gi0/5", "vlan": "10"},
        {"mac": "005056AABB01", "ip_address": None, "oui_vendor": "VMware (VM)",
         "seen_on_device": "CORE-SW", "seen_on_interface": "Gi0/6", "vlan": "10"},
    ]
    g = build_topology_graph(links, assets, endpoints)
    eps = [n for n in g["nodes"] if n["type"] == "endpoint"]
    assert len(eps) == 2
    # uç cihazlar switch'e l2 kenarıyla bağlı
    l2_edges = [e for e in g["edges"] if e["kind"] == "l2"]
    assert len(l2_edges) == 2
    assert all(e["source"] == "CORE-SW" for e in l2_edges)
    # etiket ip varsa ip, yoksa mac kuyruğu
    labels = {n["label"] for n in eps}
    assert "10.1.1.50" in labels


def test_build_graph_without_endpoints_unchanged():
    g = build_topology_graph([], [{"hostname": "X", "ip_address": "1.1.1.1",
                                   "vendor": "cisco_ios", "risk_score": 100,
                                   "is_reachable": True}])
    assert all(n["type"] == "device" for n in g["nodes"])


@pytest.fixture(scope="module", autouse=True)
def setup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(User).filter(User.username == "tp_viewer").first():
        db.add(User(username="tp_viewer", password_hash=hash_password("Passw0rd!x"),
                    role="viewer"))
    if not db.query(Asset).filter(Asset.hostname == "TP-CORE").first():
        db.add(Asset(hostname="TP-CORE", ip_address="10.2.2.1", vendor="cisco_ios",
                     backup_method="ACTIVE_SSH"))
    db.commit()
    if not db.query(DiscoveredHost).filter(DiscoveredHost.mac == "00000CAB1201").first():
        db.add(DiscoveredHost(mac="00000CAB1201", ip_address="10.2.2.50", oui_vendor="Cisco",
                              seen_on_device="TP-CORE", seen_on_interface="Gi0/1",
                              vlan="1", source="MAC_TABLE", is_onboarded=False))
    db.commit()
    db.close()
    yield


def _token(u):
    r = client.post("/api/v1/auth/token", data={"username": u, "password": "Passw0rd!x"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_graph_endpoint_excludes_endpoints_by_default():
    g = client.get("/api/v1/topology/graph", headers=_token("tp_viewer")).json()
    assert all(n.get("type") != "endpoint" for n in g["nodes"])


def test_graph_endpoint_includes_endpoints_when_requested():
    g = client.get("/api/v1/topology/graph?include_endpoints=true",
                   headers=_token("tp_viewer")).json()
    eps = [n for n in g["nodes"] if n.get("type") == "endpoint"]
    assert any(n.get("mac") == "00000CAB1201" for n in eps)
