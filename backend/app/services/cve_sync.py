"""Faz 3 Sprint 21-22: NIST NVD CVE beslemesi ve CPE eşleme.

Asset (vendor, model, os_version) üçlüsünden CPE 2.3 dizesi üretir,
NVD API v2'den ilgili CVE'leri çeker ve CVE_MATCH kaynaklı advisory
kayıtları üretir. API anahtarı opsiyoneldir (NVD_API_KEY, oran limiti
için önerilir).
"""
import os
from typing import Dict, List

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# vendor -> (cpe_vendor, cpe_product_prefix)
CPE_VENDOR_MAP = {
    "cisco_ios": ("cisco", "ios"),
    "fortinet": ("fortinet", "fortios"),
    "fortiswitch": ("fortinet", "fortiswitch"),
    "paloalto": ("paloaltonetworks", "pan-os"),
    "juniper_junos": ("juniper", "junos"),
    "huawei_vrp": ("huawei", "vrp"),
    "aruba_aoscx": ("arubanetworks", "arubaos-cx"),
    "mikrotik": ("mikrotik", "routeros"),
    "openwrt": ("openwrt", "openwrt"),
}

CVSS_TO_SEVERITY = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]


def build_cpe_string(vendor: str, os_version: str | None) -> str | None:
    """Asset alanlarından CPE 2.3 dizesi üretir; bilinmeyen vendor -> None."""
    mapped = CPE_VENDOR_MAP.get(vendor)
    if not mapped or not os_version:
        return None
    cpe_vendor, cpe_product = mapped
    version = os_version.strip().lower().replace(" ", "_")
    return f"cpe:2.3:o:{cpe_vendor}:{cpe_product}:{version}:*:*:*:*:*:*:*"


def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "INFO"
    for threshold, label in CVSS_TO_SEVERITY:
        if score >= threshold:
            return label
    return "INFO"


def parse_nvd_response(data: dict) -> List[Dict]:
    """NVD API v2 yanıtını advisory şekline dönüştürür (offline test edilir)."""
    findings: List[Dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "CVE-UNKNOWN")
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )
        score = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        findings.append({
            "rule_id": cve_id,
            "title": f"{cve_id} bilinen zafiyeti bu OS sürümünü etkiliyor",
            "description": description[:2000],
            "severity": cvss_to_severity(score),
            "remediation": "Üreticinin yamalı sürümüne yükseltin; NVD kaydındaki referansları inceleyin.",
        })
    return findings


async def fetch_cves_for_cpe(cpe: str, timeout: float = 30.0) -> List[Dict]:
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(NVD_API_URL, params={"cpeName": cpe}, headers=headers)
        if resp.status_code != 200:
            return []
        return parse_nvd_response(resp.json())
