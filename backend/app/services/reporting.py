"""Faz 3 Sprint 23-24: PDF otomatik raporlama (reportlab).

Varlık envanteri + risk skorları + açık bulguların yönetici özeti.
"""
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#c0392b"), "HIGH": colors.HexColor("#e35d6a"),
    "MEDIUM": colors.HexColor("#e6a23c"), "LOW": colors.HexColor("#8b94a8"),
    "INFO": colors.HexColor("#8b94a8"),
}


def generate_risk_report(assets: list[dict], advisories: list[dict]) -> bytes:
    """assets: [{hostname, ip_address, vendor, risk_score}],
    advisories: [{hostname, severity, title, rule_id}] -> PDF bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = getSampleStyleSheet()
    h1 = styles["Title"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    story = []

    story.append(Paragraph("NABS-GP Güvenlik ve Risk Raporu", h1))
    story.append(Paragraph(
        f"Oluşturulma: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} — "
        f"{len(assets)} varlık, {len(advisories)} açık bulgu", body))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Varlık Risk Skorları", h2))
    asset_rows = [["Hostname", "IP", "Vendor", "Risk Skoru"]]
    for a in sorted(assets, key=lambda x: x["risk_score"]):
        asset_rows.append([a["hostname"], a["ip_address"], a["vendor"], str(a["risk_score"])])
    t = Table(asset_rows, colWidths=[5 * cm, 4 * cm, 4 * cm, 3 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#171e2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Açık Güvenlik Bulguları", h2))
    if advisories:
        adv_rows = [["Cihaz", "Önem", "Kural", "Başlık"]]
        for adv in sorted(advisories, key=lambda x: x["severity"]):
            adv_rows.append([adv["hostname"], adv["severity"], adv["rule_id"], adv["title"][:60]])
        t2 = Table(adv_rows, colWidths=[4 * cm, 2.2 * cm, 3.3 * cm, 6.5 * cm])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#171e2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]
        for i, adv in enumerate(sorted(advisories, key=lambda x: x["severity"]), start=1):
            style.append(("TEXTCOLOR", (1, i), (1, i),
                          SEV_COLORS.get(adv["severity"], colors.black)))
        t2.setStyle(TableStyle(style))
        story.append(t2)
    else:
        story.append(Paragraph("Açık bulgu yok.", body))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Bu rapor NABS-GP tarafından otomatik üretilmiştir. Risk skoru 100 = tam "
        "sıkılaştırılmış, 0 = azami riskli (Spec Bölüm 6).",
        ParagraphStyle("footer", parent=body, fontSize=8, textColor=colors.grey)))

    doc.build(story)
    return buf.getvalue()
