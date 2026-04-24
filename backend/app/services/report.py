"""
UMEagleEye - PDF Report Generation Service (FR-08-02).
Uses ReportLab to generate formatted posture reports.
"""

import io
import logging
from datetime import datetime, timezone
from typing import Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

logger = logging.getLogger(__name__)


class ReportService:
    """PDF report generation and GCS upload."""

    @staticmethod
    def generate_posture_pdf(metrics: Dict[str, Any], posture: Dict[str, Any]) -> bytes:
        """Generate a formatted PDF posture report (FR-08-02).

        Args:
            metrics: Weekly aggregated metrics from PostureService
            posture: Current posture score data

        Returns:
            PDF bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            topMargin=30 * mm, bottomMargin=20 * mm,
            leftMargin=25 * mm, rightMargin=25 * mm,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"],
            fontSize=22, textColor=colors.HexColor("#1b75f5"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "Subtitle", parent=styles["Normal"],
            fontSize=10, textColor=colors.HexColor("#666666"),
            spaceAfter=20,
        )
        heading_style = ParagraphStyle(
            "CustomHeading", parent=styles["Heading2"],
            fontSize=14, textColor=colors.HexColor("#142a57"),
            spaceBefore=16, spaceAfter=8,
        )
        body_style = ParagraphStyle(
            "CustomBody", parent=styles["Normal"],
            fontSize=10, leading=14,
        )
        score_style = ParagraphStyle(
            "ScoreStyle", parent=styles["Normal"],
            fontSize=36, textColor=colors.HexColor("#1b75f5"),
            alignment=1,
        )

        elements = []

        # ── Header ──
        elements.append(Paragraph("UMEagleEye", title_style))
        elements.append(Paragraph("Cyber Asset Attack Surface Management — Security Posture Report", subtitle_style))
        elements.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}",
            ParagraphStyle("DateStyle", parent=styles["Normal"], fontSize=9, textColor=colors.grey)
        ))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1b75f5")))
        elements.append(Spacer(1, 12))

        # ── Posture Score ──
        score = posture.get("overall_score", 0)
        score_color = "#00e676" if score >= 80 else "#ffc400" if score >= 50 else "#ff5252"

        elements.append(Paragraph("Security Posture Score", heading_style))
        elements.append(Paragraph(
            f'<font color="{score_color}" size="48"><b>{score}</b></font><font size="16"> / 100</font>',
            ParagraphStyle("BigScore", parent=styles["Normal"], alignment=1, spaceAfter=12)
        ))

        # Score breakdown table
        breakdown = posture.get("breakdown", {})
        breakdown_data = [
            ["Penalty Category", "Points Deducted"],
            ["Critical Events", str(breakdown.get("critical_penalty", 0))],
            ["High Events", str(breakdown.get("high_penalty", 0))],
            ["Drift Events", str(breakdown.get("drift_penalty", 0))],
            ["SLA Breaches", str(breakdown.get("sla_penalty", 0))],
        ]
        breakdown_table = Table(breakdown_data, colWidths=[3.5 * inch, 2 * inch])
        breakdown_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#142a57")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        elements.append(breakdown_table)
        elements.append(Spacer(1, 16))

        # ── Overview Stats ──
        elements.append(Paragraph("Weekly Overview", heading_style))

        overview_data = [
            ["Metric", "Value"],
            ["Total Assets Discovered", str(metrics.get("total_assets", 0))],
            ["Security Events (7d)", str(metrics.get("drift_events", 0))],
            ["SLA Resolution Rate", f"{metrics.get('sla_resolution_rate', 0)}%"],
            ["Total Advisories (7d)", str(metrics.get("total_advisories", 0))],
            ["Resolved Advisories", str(metrics.get("resolved_advisories", 0))],
        ]
        overview_table = Table(overview_data, colWidths=[3.5 * inch, 2 * inch])
        overview_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#142a57")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        elements.append(overview_table)
        elements.append(Spacer(1, 16))

        # ── Top CVEs ──
        top_cves = metrics.get("top_cves", [])
        if top_cves:
            elements.append(Paragraph("Top Vulnerabilities", heading_style))
            cve_data = [["CVE ID", "CVSS Score", "Affected Package"]]
            for cve in top_cves:
                cve_data.append([
                    str(cve.get("cve_id", "—")),
                    str(cve.get("cvss", "—")),
                    str(cve.get("package", "—")),
                ])
            cve_table = Table(cve_data, colWidths=[2 * inch, 1.5 * inch, 2 * inch])
            cve_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#142a57")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            elements.append(cve_table)
            elements.append(Spacer(1, 16))

        # ── Top Risks ──
        top_risks = posture.get("top_risks", [])
        if top_risks:
            elements.append(Paragraph("Top Risk Items", heading_style))
            for i, risk in enumerate(top_risks[:5], 1):
                elements.append(Paragraph(
                    f"<b>{i}.</b> [{risk['severity'].upper()}] {risk['event_type']} — Risk Score: {risk['risk_score']}",
                    body_style,
                ))
            elements.append(Spacer(1, 16))

        # ── Footer ──
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            "UMEagleEye CAASM • University of Malaya • Confidential",
            ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=1)
        ))

        doc.build(elements)
        return buffer.getvalue()
