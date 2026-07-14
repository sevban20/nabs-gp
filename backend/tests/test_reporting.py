"""Faz 3: PDF rapor üretimi."""
from app.services.reporting import generate_risk_report


def test_pdf_generated_with_data():
    pdf = generate_risk_report(
        assets=[{"hostname": "SW1", "ip_address": "10.0.0.1",
                 "vendor": "cisco_ios", "risk_score": 52}],
        advisories=[{"hostname": "SW1", "severity": "HIGH",
                     "title": "Telnet açık", "rule_id": "SEC-PROT-001"}],
    )
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000


def test_pdf_generated_empty():
    pdf = generate_risk_report(assets=[], advisories=[])
    assert pdf.startswith(b"%PDF")
