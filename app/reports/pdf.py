from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.scanner.models import ScanResult


SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#b91c1c"),
    "Medium": colors.HexColor("#c2410c"),
    "Low": colors.HexColor("#0369a1"),
    "Info": colors.HexColor("#475569"),
}


def build_pdf_report(result: ScanResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.2 * cm,
        bottomMargin=1.2 * cm,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Web Security Assessment Report", styles["Title"]),
        Paragraph(f"Target: {result.target_url}", styles["Normal"]),
        Paragraph(f"Started: {result.started_at}", styles["Normal"]),
        Paragraph(f"Finished: {result.finished_at}", styles["Normal"]),
        Paragraph(
            f"Profile: {result.metadata.get('profile', 'standard')} | "
            f"Grade: {result.metadata.get('grade', 'A')} | "
            f"Risk score: {result.metadata.get('risk_score', 0)}",
            styles["Normal"],
        ),
        Paragraph(f"URLs scanned: {result.metadata.get('scanned_url_count', 1)}", styles["Normal"]),
        Spacer(1, 12),
    ]

    counts = result.severity_counts()
    summary = [["Severity", "Count"]] + [[key, counts.get(key, 0)] for key in ["Critical", "High", "Medium", "Low", "Info"]]
    summary_table = Table(summary, colWidths=[7 * cm, 3 * cm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.extend([summary_table, Spacer(1, 14)])

    coverage = result.metadata.get("coverage", {})
    if coverage:
        coverage_rows = [["Domain", "Status"]] + [[domain, status] for domain, status in coverage.items()]
        coverage_table = Table(coverage_rows, colWidths=[8 * cm, 4 * cm])
        coverage_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ]
            )
        )
        story.extend([Paragraph("Assessment Coverage", styles["Heading2"]), coverage_table, Spacer(1, 14)])

    if not result.findings:
        story.append(Paragraph("No findings were detected by the enabled modules.", styles["Heading2"]))
    else:
        story.append(Paragraph("Findings", styles["Heading2"]))
        for idx, finding in enumerate(result.findings, start=1):
            story.append(Paragraph(f"{idx}. {finding.title}", styles["Heading3"]))
            story.append(Paragraph(f"{finding.severity} | CVSS {finding.cvss:.1f} | {finding.module}", styles["Normal"]))
            story.append(Paragraph(f"<b>Description:</b> {finding.description}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Evidence:</b> {finding.evidence}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Remediation:</b> {finding.remediation}", styles["BodyText"]))
            story.append(Paragraph(f"<b>URL:</b> {finding.url}", styles["BodyText"]))
            story.append(Spacer(1, 10))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Ethical notice: scan only systems you own or have explicit permission to test.", styles["Italic"]))
    doc.build(story)
    return buffer.getvalue()
