"""Faz 2 Sprint 9-10: ağ keşif taraması uçları."""
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import require_role
from app.core.database import get_db

router = APIRouter()


class ScanRequest(BaseModel):
    cidr: str
    snmp_community: str = "public"


@router.post("/discovery/scan", status_code=202)
def start_scan(payload: ScanRequest, _user: dict = Depends(require_role("operator"))):
    try:
        network = ipaddress.ip_network(payload.cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Geçersiz CIDR.")
    if network.num_addresses > 4096:
        raise HTTPException(status_code=400, detail="Tek taramada en fazla /20 desteklenir.")
    from app.workers.tasks import run_discovery_scan
    task = run_discovery_scan.delay(payload.cidr, payload.snmp_community)
    return {"status": "queued", "task_id": str(task)}


@router.get("/discovery/results/{task_id}")
def scan_results(task_id: str, _user: dict = Depends(require_role("viewer"))):
    from app.workers.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)
    if not result.ready():
        return {"state": result.state}
    return {"state": result.state, "hosts": result.result}


@router.post("/topology/collect/{asset_id}", status_code=202)
def collect_topology(asset_id: int, db: Session = Depends(get_db),
                     _user: dict = Depends(require_role("operator"))):
    """Bir cihazdan LLDP/CDP komşularını toplamayı kuyruğa alır."""
    from app.models.models import Asset
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı.")
    if not asset.credential_id:
        raise HTTPException(status_code=400, detail="Cihaza bağlı kimlik bilgisi yok.")
    from app.workers.tasks import collect_topology as task
    t = task.delay(asset_id)
    return {"status": "queued", "task_id": str(t)}


class SshProbeRequest(BaseModel):
    ip_address: str
    credential_id: str


class OnboardRequest(BaseModel):
    hostname: str
    vendor: str = Field(pattern="^(cisco_ios|fortinet|fortiswitch|paloalto|juniper_junos|"
                                "huawei_vrp|aruba_aoscx|aruba_procurve|mikrotik|openwrt|linux)$")
    backup_method: str = Field(default="ACTIVE_SSH",
                               pattern="^(ACTIVE_SSH|ACTIVE_API|PASSIVE_SFTP|PASSIVE_TFTP)$")
    credential_id: str | None = None


@router.post("/assets/{asset_id}/collect-l2", status_code=202)
def collect_l2(asset_id: int, db: Session = Depends(get_db),
               _user: dict = Depends(require_role("operator"))):
    """Bir switch/router'dan ARP + MAC tablosu toplamayı kuyruğa alır."""
    from app.models.models import Asset
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı.")
    if not asset.credential_id:
        raise HTTPException(status_code=400, detail="Cihaza bağlı kimlik bilgisi yok.")
    from app.workers.tasks import collect_l2_inventory
    t = collect_l2_inventory.delay(asset_id)
    return {"status": "queued", "task_id": str(t)}


@router.get("/discovery/hosts")
def discovered_hosts(only_unmanaged: bool = True, q: str | None = None,
                     limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0),
                     db: Session = Depends(get_db),
                     _user: dict = Depends(require_role("viewer"))):
    """L2 keşifle bulunan uç cihazlar. only_unmanaged=True ise yalnızca
    envanterde olmayanlar (onboard adayları)."""
    from sqlalchemy import or_

    from app.models.models import DiscoveredHost
    query = db.query(DiscoveredHost)
    if only_unmanaged:
        query = query.filter(DiscoveredHost.is_onboarded.is_(False))
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(
            DiscoveredHost.mac.ilike(like), DiscoveredHost.ip_address.ilike(like),
            DiscoveredHost.oui_vendor.ilike(like), DiscoveredHost.seen_on_device.ilike(like)))
    rows = (query.order_by(DiscoveredHost.last_seen.desc())
            .offset(offset).limit(limit).all())
    return [{
        "id": h.id, "mac": h.mac, "ip_address": h.ip_address, "oui_vendor": h.oui_vendor,
        "seen_on_device": h.seen_on_device, "seen_on_interface": h.seen_on_interface,
        "vlan": h.vlan, "source": h.source, "is_onboarded": h.is_onboarded,
        "last_seen": h.last_seen.isoformat() if h.last_seen else None,
    } for h in rows]


@router.post("/discovery/ssh-probe")
def ssh_probe_endpoint(payload: SshProbeRequest, db: Session = Depends(get_db),
                       _user: dict = Depends(require_role("operator"))):
    """Seçili kimlik bilgisiyle bir host'a TEK SEFERLİK SSH denemesi
    (onboarding doğrulama). Toplu deneme yapılmaz (hesap kilitlenme riski)."""
    from app.core.crypto import get_crypto_or_http
    from app.models.models import Credential
    from app.workers.tasks import ssh_probe

    cred = db.get(Credential, payload.credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Kimlik bilgisi bulunamadı.")
    crypto = get_crypto_or_http()
    return ssh_probe(payload.ip_address, cred.username,
                     crypto.decrypt(cred.password_encrypted))


@router.post("/discovery/hosts/{host_id}/onboard", status_code=201)
def onboard_host(host_id: int, payload: OnboardRequest, db: Session = Depends(get_db),
                 _user: dict = Depends(require_role("operator"))):
    """Keşfedilen bir uç cihazı yönetilen envantere ekler (asset oluşturur)."""
    from app.models.models import Asset, DiscoveredHost

    host = db.get(DiscoveredHost, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Keşfedilen host bulunamadı.")
    if not host.ip_address:
        raise HTTPException(status_code=400,
                            detail="Bu host'un IP'si yok (yalnızca MAC); onboard için IP gerekli.")
    if db.query(Asset).filter(Asset.ip_address == host.ip_address).first():
        raise HTTPException(status_code=409, detail="Bu IP zaten envanterde.")
    asset = Asset(hostname=payload.hostname, ip_address=host.ip_address,
                  vendor=payload.vendor, backup_method=payload.backup_method,
                  credential_id=payload.credential_id)
    db.add(asset)
    # aynı MAC'in tüm sightings'lerini onboarded işaretle
    for h in db.query(DiscoveredHost).filter(DiscoveredHost.mac == host.mac).all():
        h.is_onboarded = True
    db.commit()
    db.refresh(asset)
    return {"asset_id": asset.id, "hostname": asset.hostname, "ip_address": asset.ip_address}


@router.get("/topology/graph")
def topology_graph(include_endpoints: bool = False,
                   endpoint_limit: int = Query(300, ge=1, le=1000),
                   db: Session = Depends(get_db),
                   _user: dict = Depends(require_role("viewer"))):
    """Ağ haritası: düğümler (cihazlar) + kenarlar (komşuluk link'leri).
    include_endpoints=True ise L2 keşif uç cihazları (ARP/MAC) da switch
    portlarına asılı yaprak düğüm olarak eklenir."""
    from app.models.models import Asset, DiscoveredHost, TopologyLink
    from app.services.topology import build_topology_graph

    links = [{
        "source_device": l.source_device, "remote_device": l.remote_device,
        "protocol": l.protocol, "local_interface": l.local_interface,
        "remote_interface": l.remote_interface,
    } for l in db.query(TopologyLink).all()]
    assets = [{
        "hostname": a.hostname, "ip_address": a.ip_address, "vendor": a.vendor,
        "risk_score": a.risk_score, "is_reachable": a.is_reachable,
    } for a in db.query(Asset).all()]

    endpoints = None
    if include_endpoints:
        rows = (db.query(DiscoveredHost)
                .order_by(DiscoveredHost.ip_address.isnot(None).desc(),
                          DiscoveredHost.last_seen.desc())
                .limit(endpoint_limit).all())
        endpoints = [{
            "mac": h.mac, "ip_address": h.ip_address, "oui_vendor": h.oui_vendor,
            "seen_on_device": h.seen_on_device, "seen_on_interface": h.seen_on_interface,
            "vlan": h.vlan,
        } for h in rows]
    return build_topology_graph(links, assets, endpoints)
